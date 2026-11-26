# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2.31",
# ]
# ///
"""Pure-Python backend stress + measurement driver.

No Playwright. No frontend interaction. Spawns the ETW churn driver
(stress_etw.py), exercises hijack/unhijack via HTTP, tails proxyclaw.log,
and reports per-stage backend pipeline latencies.

Setup
    1. start proxyclaw.exe (build/Release) in an admin shell with log_level=debug
       (edit proxyclaw.json or use the Settings UI)
    2. in another shell, run this script (no admin required for the
       script itself; only proxyclaw.exe needs admin)

Usage
    uv run --script tests/stress_backend.py --scenario churn
    uv run --script tests/stress_backend.py --scenario steady --target 500
    uv run --script tests/stress_backend.py --scenario churn --visibility-cycle

Scenarios
    churn   — high event rate, moderate tree (target=200, life 2-5s)
    steady  — low event rate, large tree (target=500, life 30s)

CI smoke (bounded, self-launching; elevated shell)
    python tests/stress_backend.py --exe dist/<pkg>/proxyclaw.exe --ci \
        --duration 45 --summary-json build/stress-summary.json
    Starts proxyclaw.exe with a throwaway config (log_level=debug), runs the
    ETW churn driver at modest size, hijack/unhijack cycling and a few
    threads of concurrent GET load against the API, samples proxyclaw.exe
    working set + handle count once a second, prints a compact summary and
    exits non-zero on any request error, a proxyclaw.exe crash, or a dead
    API at the end. Latency and memory numbers are reported, never gated.

Output
    Per-metric summary: n, min, p50, p95, p99, max (microseconds).
    ETW event rate, tree size range, strand utilization estimate.
    Hijack/unhijack RTT distribution.
    With --visibility-cycle: separate buckets for visible vs hidden.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.wintypes as wintypes
import os
import pathlib
import re
import json
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import api_token  # noqa: F401  (adds the API session token; see tests/api_token.py)
from compare_stress import (  # noqa: E402
    diff_counters,
    diff_latency_hist,
    format_comparison,
    summarize_rss_vs_processes,
)


# ---------------------------------------------------------------- paths/const

REPO_ROOT     = pathlib.Path(__file__).resolve().parents[1]
STRESS_SCRIPT = REPO_ROOT / "tests" / "stress_etw.py"
LOG_PATH      = REPO_ROOT / "build" / "Release" / "proxyclaw.log"  # --exe: next to that exe
EXE           = REPO_ROOT / "build" / "Release" / "proxyclaw.exe"
BASE          = "http://127.0.0.1:18080/api"

# Win32 — minimal, only what we need to drive visibility transitions.
WINDOW_CLASS  = "ProxyClawWebViewClass"
WM_SYSCOMMAND = 0x0112
SC_MINIMIZE   = 0xF020
SC_RESTORE    = 0xF120


# ----------------------------------------------------------------- win32 hwnd

def find_clew_hwnd() -> int | None:
    user32 = ctypes.windll.user32
    EnumWindowsProc = ctypes.WINFUNCTYPE(
        wintypes.BOOL, wintypes.HWND, wintypes.LPARAM,
    )
    found: list[int] = []
    def cb(hwnd, _):
        buf = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, buf, 256)
        if buf.value == WINDOW_CLASS:
            found.append(int(hwnd))
            return False
        return True
    user32.EnumWindows(EnumWindowsProc(cb), 0)
    return found[0] if found else None


def post_wm(hwnd: int, msg: int, wparam: int, lparam: int) -> bool:
    return bool(ctypes.windll.user32.PostMessageW(hwnd, msg, wparam, lparam))


# ------------------------------------------------------------- proxyclaw.log parse

# Quill format: "%(time) [%(log_level_short_code)] %(message)"
# Time format: "%Y-%m-%d %H:%M:%S.%Qus" (microseconds).
# We log at INFO ([I]); accept [D] too in case the macro is changed back.
TRACE_LINE_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+'
    r'\[[IDW]\]\s+'
    r'\[trace\]\s+'
    r'(?P<kind>\w+)'
    r'(?P<rest>.*)$'
)


def parse_ts(s: str) -> float:
    # quill timestamps are local time, naive. Match against time.time().
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").timestamp()


def parse_kv(s: str) -> dict[str, int | str]:
    out: dict[str, int | str] = {}
    for tok in s.strip().split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        try:
            out[k] = int(v)
        except ValueError:
            out[k] = v
    return out


# ------------------------------------------------------- log slice reader
#
# Real-time tailing via Python text-mode + quill backend buffering on Windows
# proved unreliable (lines that are clearly in the file at end-of-test were
# not seen by an open-and-seek-to-EOF FD). Switched to: read the whole file
# at end of phase, filter to events whose timestamp falls inside the phase
# wall-clock window. log is a few MB at most for our test durations, so
# scanning the whole file is fine.

def collect_trace_events(path: pathlib.Path,
                         ts_start: float,
                         ts_end: float) -> list[dict]:
    out: list[dict] = []
    if not path.exists():
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = TRACE_LINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            ts = parse_ts(m.group("ts"))
            if ts < ts_start or ts > ts_end:
                continue
            d: dict = parse_kv(m.group("rest"))
            d["_ts"]   = ts
            d["_kind"] = m.group("kind")
            out.append(d)
    return out


# --------------------------------------------------------------- stat helpers

def stats(values: list[int]) -> str:
    if not values:
        return "n=0"
    s = sorted(values)
    n = len(s)
    def pct(p: float) -> int:
        idx = min(n - 1, max(0, int(round(p * (n - 1)))))
        return s[idx]
    return (f"n={n} min={s[0]} p50={pct(0.50)} p95={pct(0.95)} "
            f"p99={pct(0.99)} max={s[-1]}")


# ----------------------------------------------------------- helper subprocess

def spawn_long_lived_helper(seconds: int = 600) -> subprocess.Popen[bytes]:
    """Stable target for hijack/unhijack measurement. ping for `seconds`."""
    return subprocess.Popen(
        ["cmd.exe", "/c", "ping", "127.0.0.1", "-n", str(seconds)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def wait_tree_ready(timeout: float = 60.0) -> None:
    """Block until /api/stats reports the initial rundown verified
    (tree_ready). Builds without the flag are not waited on."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = requests.get(f"{BASE}/stats", timeout=2).json()
            if s.get("tree_ready", True):
                return
        except Exception:
            pass
        time.sleep(0.25)
    print(f"WARN: process tree not ready after {timeout:.0f}s", file=sys.stderr)


def wait_pid_in_clew(pid: int, timeout: float = 15.0) -> bool:
    # ETW ProcessStart latency is 1-3s+ on a loaded CI runner; the deadline
    # is a ceiling, a healthy box returns in well under a second.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{BASE}/processes/{pid}", timeout=1.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def hijack(pid: int) -> tuple[int, float]:
    # perf_counter: time.monotonic() ticks at 15.6 ms on Windows.
    t0 = time.perf_counter()
    r = requests.post(f"{BASE}/hijack/{pid}",
                      json={"tree": False, "group_id": 0}, timeout=30.0)
    return r.status_code, (time.perf_counter() - t0) * 1e6  # microseconds


def unhijack(pid: int) -> tuple[int, float]:
    t0 = time.perf_counter()
    r = requests.delete(f"{BASE}/hijack/{pid}", data="", timeout=30.0)
    return r.status_code, (time.perf_counter() - t0) * 1e6


HIJACK_ERRORS: list[str] = []


def _safe(fn, pid: int) -> tuple[int | str, float]:
    try:
        return fn(pid)
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}", 0.0


# ------------------------------------------------- CI smoke: load + sampling

# /connections is the UI's single connection poll (v0.14 #3); /tcp and /udp
# stay in the mix because tools and e2e still read them.
LOAD_PATHS = ["/stats", "/connections", "/tcp", "/udp", "/hijack", "/auto-rules",
              "/proxy-groups", "/config"]


BENCH_CONN_EXE = "pc-bench-conn.exe"
BENCH_CONN_SCRIPT = r"""
import socket, subprocess, sys, time

def one_connect(host, port):
    s = socket.create_connection((host, port), timeout=5)
    try:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = s.recv(64)
        return data.startswith(b"HTTP/")
    finally:
        s.close()

if len(sys.argv) > 1 and sys.argv[1] == "--once":
    try:
        sys.exit(0 if one_connect("1.1.1.1", 80) else 2)
    except OSError:
        sys.exit(3)

i = 0
while True:
    try:
        one_connect("1.0.0.1", 80)
    except OSError:
        pass
    i += 1
    if i % 10 == 0:
        try:
            subprocess.run([sys.executable, __file__, "--once"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5)
        except Exception:
            pass
    time.sleep(0.04)
"""


def fetch_stats_snapshot() -> dict | None:
    try:
        r = requests.get(f"{BASE}/stats", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return None


def late_rejected_proxied(stats_obj: dict | None = None) -> int | None:
    """Proxied decisions that lost the race to the SYN watchdog (missed proxies)."""
    try:
        s = stats_obj if stats_obj is not None else fetch_stats_snapshot()
        return int(s["tcp_syn_parking"]["socket"]["late_rejected_proxied"])
    except Exception:  # noqa: BLE001
        return None


class BenchSocks5:
    """Minimal local SOCKS5 stub responding immediately to CONNECT (no internet)."""

    def __init__(self) -> None:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(128)
        self._srv.settimeout(0.5)
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()
        self.handled = 0
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf.extend(chunk)
        return bytes(buf)

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(3.0)
            hdr = self._recv_exact(conn, 2)
            if hdr[0] != 5:
                return
            self._recv_exact(conn, hdr[1])
            conn.sendall(b"\x05\x00")
            req = self._recv_exact(conn, 4)
            atyp = req[3]
            if atyp == 1:
                self._recv_exact(conn, 4 + 2)
            elif atyp == 4:
                self._recv_exact(conn, 16 + 2)
            elif atyp == 3:
                ln = self._recv_exact(conn, 1)[0]
                self._recv_exact(conn, ln + 2)
            else:
                return
            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            with self._lock:
                self.handled += 1
            with contextlib.suppress(OSError):
                conn.recv(256)
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        except Exception:  # noqa: BLE001
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._srv.close()
        self._thread.join(timeout=3)


class ConnectProbe:
    """Drives real outbound proxied TCP CONNECTs (sustained + fresh children)."""

    def __init__(self, work: pathlib.Path) -> None:
        self._work = work
        self._script = work / "bench_conn.py"
        self._script.write_text(BENCH_CONN_SCRIPT, encoding="utf-8")
        py_dir = pathlib.Path(sys.executable).resolve().parent
        self._exe = py_dir / BENCH_CONN_EXE
        shutil.copy2(sys.executable, self._exe)
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        self._proc = subprocess.Popen(
            [str(self._exe), str(self._script)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )

    def stop(self) -> None:
        if self._proc is not None:
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self._proc.pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5,
                )
            with contextlib.suppress(Exception):
                self._proc.wait(timeout=3)
            self._proc = None
        for _ in range(10):
            try:
                self._exe.unlink(missing_ok=True)
                break
            except OSError:
                time.sleep(0.2)


def pct_ms(values_us: list[float], p: float) -> float | None:
    if not values_us:
        return None
    s = sorted(values_us)
    idx = min(len(s) - 1, max(0, int(round(p * (len(s) - 1)))))
    return round(s[idx] / 1000.0, 2)


class HttpLoad:
    """N threads issuing GETs round-robin over LOAD_PATHS until stopped."""

    def __init__(self, workers: int) -> None:
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.lat_us: list[float] = []
        self.errors: list[str] = []
        self.threads = [threading.Thread(target=self._run, args=(i,), daemon=True)
                        for i in range(workers)]

    def start(self) -> None:
        for t in self.threads:
            t.start()

    def finish(self) -> None:
        self.stop.set()
        for t in self.threads:
            t.join(timeout=15)

    def _run(self, i: int) -> None:
        sess = requests.Session()
        sess.trust_env = False
        n = i
        while not self.stop.is_set():
            path = LOAD_PATHS[n % len(LOAD_PATHS)]
            n += 1
            t0 = time.perf_counter()
            try:
                r = sess.get(BASE + path, timeout=10)
                dt = (time.perf_counter() - t0) * 1e6
                with self.lock:
                    if r.status_code == 200:
                        self.lat_us.append(dt)
                    else:
                        self.errors.append(f"GET {path} -> {r.status_code}")
            except Exception as e:  # noqa: BLE001
                with self.lock:
                    self.errors.append(f"GET {path} -> {type(e).__name__}")


class _PMC(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


class ResourceSampler:
    """Once a second: proxyclaw.exe working set, private bytes, handles, process count."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.samples: list[tuple[int, int, int, int | None]] = []  # (ws, private, handles, proc_count)
        self.stop = threading.Event()
        self._lock = threading.Lock()
        self._sess = requests.Session()
        self._sess.trust_env = False
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _query_process_count(self) -> int | None:
        try:
            r = self._sess.get(f"{BASE}/stats", timeout=1.0)
            if r.status_code == 200:
                pc = r.json().get("process_count")
                if pc is not None:
                    return int(pc)
        except Exception:  # noqa: BLE001
            pass
        return None

    def _sample(self) -> tuple[int, int, int, int | None] | None:
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000 | 0x0010, False, self.pid)  # QUERY_LIMITED | VM_READ
        if not h:
            return None
        try:
            pmc = _PMC()
            pmc.cb = ctypes.sizeof(_PMC)
            if not k32.K32GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                return None
            hc = wintypes.DWORD()
            k32.GetProcessHandleCount(h, ctypes.byref(hc))
            pc = self._query_process_count()
            return pmc.WorkingSetSize, pmc.PagefileUsage, hc.value, pc
        finally:
            k32.CloseHandle(h)

    def sample_once(self) -> None:
        s = self._sample()
        if s:
            with self._lock:
                self.samples.append(s)

    def _run(self) -> None:
        while not self.stop.is_set():
            self.sample_once()
            self.stop.wait(1.0)

    def start(self) -> None:
        self.thread.start()

    def finish(self) -> tuple[dict, dict]:
        self.stop.set()
        self.thread.join(timeout=5)
        with self._lock:
            pts = list(self.samples)
        if not pts:
            return {}, {}
        mb = 1024 * 1024
        ws = [x[0] for x in pts]
        pv = [x[1] for x in pts]
        hd = [x[2] for x in pts]
        summary = {"samples": len(pts),
                   "working_set_mb": {"start": round(ws[0] / mb, 1), "end": round(ws[-1] / mb, 1),
                                      "peak": round(max(ws) / mb, 1)},
                   "private_mb": {"start": round(pv[0] / mb, 1), "end": round(pv[-1] / mb, 1),
                                  "peak": round(max(pv) / mb, 1)},
                   "handles": {"start": hd[0], "end": hd[-1], "peak": max(hd)}}
        rss_vs_proc = summarize_rss_vs_processes(pts)
        return summary, rss_vs_proc


def find_proxyclaw_pid() -> int | None:
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq proxyclaw.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = [x.strip('"') for x in line.split('","')]
        if len(parts) > 1 and parts[1].isdigit():
            return int(parts[1])
    return None


def launch_proxyclaw(exe: pathlib.Path, socks_port: int = 1) -> tuple[subprocess.Popen, pathlib.Path]:
    """Start proxyclaw.exe with a throwaway debug config; wait for the API."""
    work = pathlib.Path(tempfile.mkdtemp(prefix="pc_stress_"))
    rule = {
        "id": "bench_conn",
        "name": "bench connect probe",
        "enabled": True,
        "process_name": BENCH_CONN_EXE,
        "cmdline_pattern": "",
        "image_path_pattern": "",
        "hack_tree": True,
        "protocol": "tcp",
        "proxy_group_id": 0,
        "dst_filter": {"include_cidrs": [], "exclude_cidrs": [],
                       "include_ports": [], "exclude_ports": []},
    }
    cfg = {"version": 2,
           "default_proxy": {"type": "socks5", "host": "127.0.0.1", "port": socks_port},
           "proxy_groups": [{"id": 0, "name": "default", "host": "127.0.0.1",
                             "port": socks_port, "type": "socks5"}],
           "next_group_id": 1, "auto_rules": [rule] if socks_port > 1 else [],
           "log_level": "debug", "dns": {"enabled": False}}
    cfg_path = work / "proxyclaw.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    proc = subprocess.Popen([str(exe), "--minimized", "--dev-hooks", "--config", str(cfg_path)],
                            cwd=exe.parent, env=dict(os.environ))
    deadline = time.time() + 30
    while True:
        if proc.poll() is not None:
            raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
        try:
            if requests.get(f"{BASE}/stats", timeout=2).status_code == 200:
                wait_tree_ready()
                return proc, work
        except Exception:
            pass
        if time.time() > deadline:
            proc.kill()
            raise RuntimeError("proxyclaw API did not come up in 30s")
        time.sleep(0.5)


# ----------------------------------------------------------- measurement loop

def run_phase(label: str, secs: float,
              target_pid: int, hijack_interval: float) -> dict:
    """Run a phase: alternate hijack/unhijack at fixed cadence, return
    raw timing data. Trace events are collected from proxyclaw.log AFTER the
    phase ends (post-hoc filter by wall-clock window)."""
    print(f"\n=== phase: {label} ({secs:.1f}s) ===")
    rtts_hijack:   list[float] = []
    rtts_unhijack: list[float] = []
    next_action = time.monotonic()
    is_hijacked = False

    ts_start = time.time()
    end_at = time.monotonic() + secs
    while time.monotonic() < end_at:
        if time.monotonic() >= next_action:
            if not is_hijacked:
                code, rtt_us = _safe(hijack, target_pid)
                if code == 200:
                    rtts_hijack.append(rtt_us)
                    is_hijacked = True
                else:
                    HIJACK_ERRORS.append(f"hijack -> {code}")
            else:
                code, rtt_us = _safe(unhijack, target_pid)
                if code == 200:
                    rtts_unhijack.append(rtt_us)
                    is_hijacked = False
                else:
                    HIJACK_ERRORS.append(f"unhijack -> {code}")
            next_action = time.monotonic() + hijack_interval
        time.sleep(0.05)

    # Restore unhijacked at phase end so the next phase starts clean.
    if is_hijacked:
        unhijack(target_pid)
    ts_end = time.time() + 1.0  # +1s headroom for in-flight log writes

    # Wait for quill to flush trailing writes.
    time.sleep(1.5)

    events = collect_trace_events(LOG_PATH, ts_start, ts_end)
    print(f"    collected {len(events)} trace events from log")

    return {
        "label": label,
        "secs":  secs,
        "events": events,
        "rtts_hijack":   rtts_hijack,
        "rtts_unhijack": rtts_unhijack,
    }


# ----------------------------------------------------------------- reporting

def report(phase: dict) -> None:
    label  = phase["label"]
    secs   = phase["secs"]
    events = phase["events"]

    print(f"\n--- {label}: {secs:.1f}s, {len(events)} trace events ---")

    by_kind: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_kind[e["_kind"]].append(e)

    # ETW arrival rate (off-strand, before any queueing).
    etw_cb = by_kind.get("etw_cb", [])
    starts = sum(1 for e in etw_cb if e.get("id") == "START")
    stops  = sum(1 for e in etw_cb if e.get("id") == "STOP")
    print(f"ETW: {len(etw_cb)} events ({starts} START, {stops} STOP) = "
          f"{len(etw_cb)/max(secs,1e-9):.1f}/sec")

    # Strand: per-event work breakdown (apply + notify) from etw_strand_in.
    etw_strand = by_kind.get("etw_strand_in", [])
    apply_us  = [int(e["apply_us"])  for e in etw_strand if "apply_us"  in e]
    notify_us = [int(e["notify_us"]) for e in etw_strand if "notify_us" in e]
    trees     = [int(e["tree"])      for e in etw_strand if "tree"      in e]
    if etw_strand:
        print(f"strand etw apply_us:  {stats(apply_us)}")
        print(f"strand etw notify_us: {stats(notify_us)}")
        if trees:
            print(f"tree size: min={min(trees)} max={max(trees)} "
                  f"median={sorted(trees)[len(trees)//2]}")

    # Projection (refresh + push), only fires when visible.
    # Three trace kinds depending on build / urgency:
    #   - proj urgency=immediate refresh_us=N push_us=N tree=N   (immediate path)
    #   - proj urgency=batched scheduled tree=N                  (new coalesce: refresh deferred)
    #   - proj urgency=batched refresh_us=N push_us=coalesced... (old coalesce: refresh per-event)
    #   - proj urgency=n/a refresh_us=N push_us=N mode=no-coalesce (PROXYCLAW_NO_COALESCE build)
    #   - proj_timer_flush refresh_us=N push_us=N tree=N         (new coalesce timer fired)
    #   - proj urgency=X skipped=hidden                          (visibility gate)
    proj          = by_kind.get("proj", [])
    proj_flush    = by_kind.get("proj_timer_flush", [])
    proj_skipped  = sum(1 for e in proj if e.get("skipped") == "hidden")
    proj_inline   = [e for e in proj if "refresh_us" in e]      # has refresh inline
    proj_deferred = [e for e in proj if e.get("scheduled") == 1 or
                     "scheduled" in e]                           # new coalesce batched
    refresh_us_inline = [int(e["refresh_us"]) for e in proj_inline]
    push_us_inline    = [int(e["push_us"]) for e in proj_inline
                         if isinstance(e.get("push_us"), int)]
    refresh_us_flush  = [int(e["refresh_us"]) for e in proj_flush]
    push_us_flush     = [int(e["push_us"])    for e in proj_flush]

    print(f"projection: {len(proj)+len(proj_flush)} total "
          f"({len(proj_inline)} inline-refresh, "
          f"{len(proj_deferred)} batched-scheduled, "
          f"{len(proj_flush)} timer-flushes, "
          f"{proj_skipped} skipped-hidden)")
    if proj_inline:
        print(f"  inline refresh_us: {stats(refresh_us_inline)}")
        if push_us_inline:
            print(f"  inline push_us:    {stats(push_us_inline)}")
    if proj_flush:
        print(f"  flush  refresh_us: {stats(refresh_us_flush)}")
        print(f"  flush  push_us:    {stats(push_us_flush)}")

    # Hijack roundtrip from log (svc_post_command total_us) + strand wait.
    svc_post = by_kind.get("svc_post_command", [])
    hijack_total_us = [int(e["total_us"]) for e in svc_post
                       if e.get("op") == "hijack"]
    unhijack_total_us = [int(e["total_us"]) for e in svc_post
                         if e.get("op") == "unhijack"]
    strand_exec = by_kind.get("strand_exec", [])
    hijack_wait_us = [int(e["wait_us"]) for e in strand_exec
                      if e.get("op") == "hijack"]
    unhijack_wait_us = [int(e["wait_us"]) for e in strand_exec
                        if e.get("op") == "unhijack"]
    if hijack_total_us or unhijack_total_us:
        print("hijack/unhijack (server-side, from log):")
        print(f"  hijack   total_us: {stats(hijack_total_us)}")
        print(f"  hijack   wait_us:  {stats(hijack_wait_us)}")
        print(f"  unhijack total_us: {stats(unhijack_total_us)}")
        print(f"  unhijack wait_us:  {stats(unhijack_wait_us)}")

    # Wall-clock RTT measured from the requesting Python process.
    rtts_h = [int(x) for x in phase["rtts_hijack"]]
    rtts_u = [int(x) for x in phase["rtts_unhijack"]]
    if rtts_h or rtts_u:
        print("hijack/unhijack RTT (wall-clock, from python):")
        if rtts_h: print(f"  hijack:   {stats(rtts_h)}")
        if rtts_u: print(f"  unhijack: {stats(rtts_u)}")

    # Strand utilization estimate: sum of strand-side work / phase duration.
    # Includes ETW strand work (apply + notify) AND timer-flush work (in
    # coalesce-with-refresh build, refresh+push runs in timer callback on
    # the strand, so we need to count it explicitly).
    flush_work_us = sum(refresh_us_flush) + sum(push_us_flush)
    strand_work_us = sum(apply_us) + sum(notify_us) + flush_work_us
    util_pct = 100.0 * strand_work_us / (secs * 1e6)
    print(f"strand busy estimate: {strand_work_us/1e3:.1f}ms over {secs:.1f}s "
          f"= {util_pct:.1f}% "
          f"(etw {(sum(apply_us)+sum(notify_us))/1e3:.0f}ms + "
          f"flush {flush_work_us/1e3:.0f}ms)")


# -------------------------------------------------------------------- main

def main() -> int:
    global LOG_PATH
    p = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                description=__doc__.splitlines()[0])
    p.add_argument("--scenario",  choices=["churn", "steady"], default="churn")
    p.add_argument("--target",    type=int,   default=None,
                   help="override scenario default target")
    p.add_argument("--min-life",  type=float, default=None,
                   help="override scenario default min-life (seconds per child)")
    p.add_argument("--max-life",  type=float, default=None,
                   help="override scenario default max-life")
    p.add_argument("--measure-secs", type=float, default=20.0,
                   help="duration of each measurement phase")
    p.add_argument("--hijack-interval", type=float, default=2.0)
    p.add_argument("--warmup-secs", type=float, default=5.0,
                   help="time to wait after stress_etw start before measuring")
    p.add_argument("--visibility-cycle", action="store_true",
                   help="run minimize/restore cycle midway and bucket results")
    p.add_argument("--no-stress", action="store_true",
                   help="skip stress_etw (useful for baseline/idle measurement)")
    p.add_argument("--exe", type=pathlib.Path, default=None,
                   help="launch this proxyclaw.exe (elevated) with a throwaway debug config")
    p.add_argument("--ci", action="store_true",
                   help="bounded smoke: churn target 40, life 1-3s, 4 HTTP workers, "
                        "0.5s hijack cycle; fail on errors/crash, never on numbers")
    p.add_argument("--duration", type=float, default=None,
                   help="--ci: total measured seconds (warmup excluded), capped at 60")
    p.add_argument("--http-workers", type=int, default=None,
                   help="threads of concurrent GET load during measurement (default 0, --ci 4)")
    p.add_argument("--summary-json", type=pathlib.Path, default=None,
                   help="write a machine-readable summary here")
    p.add_argument("--compare", type=pathlib.Path, default=None,
                   help="compare this run's summary against a baseline stress-summary.json")
    p.add_argument("--no-connect-probes", action="store_true",
                   help="--exe: disable the local SOCKS5 TCP CONNECT probe worker")
    args = p.parse_args()

    if args.ci:
        if args.target is None: args.target = 40
        if args.min_life is None: args.min_life = 1.0
        if args.max_life is None: args.max_life = 3.0
        args.warmup_secs = min(args.warmup_secs, 3.0)
        args.hijack_interval = 0.5
        args.measure_secs = min(args.duration or 45.0, 60.0)
        args.visibility_cycle = False
        if args.http_workers is None: args.http_workers = 4
    workers = args.http_workers or 0

    proc = work = socks = None
    if args.exe is not None:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("SKIP: --exe needs an elevated shell (WinDivert)")
            return 2
        exe = args.exe.resolve()
        LOG_PATH = exe.parent / "proxyclaw.log"
        if not args.no_connect_probes:
            socks = BenchSocks5()
        proc, work = launch_proxyclaw(exe, socks.port if socks else 1)
    try:
        return _run(args, workers, proc, work, socks)
    finally:
        if socks is not None:
            socks.close()
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
            shutil.rmtree(work, ignore_errors=True)


def _run(args, workers: int, proc: subprocess.Popen | None,
         work: pathlib.Path | None, socks: BenchSocks5 | None) -> int:
    if not LOG_PATH.exists():
        print(f"ERROR: {LOG_PATH} not found. Start proxyclaw.exe first.", file=sys.stderr)
        return 1
    try:
        requests.get(f"{BASE}/stats", timeout=2).raise_for_status()
    except Exception as e:
        print(f"ERROR: clew not reachable at {BASE} ({e})", file=sys.stderr)
        return 1

    # Scenario defaults — override-able via --target / --min-life / --max-life.
    if args.scenario == "churn":
        target  = args.target if args.target else 200
        min_life, max_life = 2.0, 5.0
    else:  # steady
        target  = args.target if args.target else 500
        min_life, max_life = 25.0, 35.0
    if args.min_life is not None: min_life = args.min_life
    if args.max_life is not None: max_life = args.max_life

    # Spawn a long-lived helper to hijack against. ping covers entire run.
    helper_secs = int(args.warmup_secs + args.measure_secs * 3 + 30)
    helper = spawn_long_lived_helper(helper_secs)
    target_pid = helper.pid
    print(f"==> helper pid={target_pid} (ping -n {helper_secs})")

    if not wait_pid_in_clew(target_pid):
        helper.kill()
        print(f"ERROR: helper pid {target_pid} did not appear in clew tree",
              file=sys.stderr)
        return 1

    pc_pid = proc.pid if proc is not None else find_proxyclaw_pid()
    sampler = ResourceSampler(pc_pid) if pc_pid else None
    if sampler:
        # Capture idle low-process-count RSS before stress_etw spawns churn.
        sampler.sample_once()
        sampler.start()

    stress = None
    if not args.no_stress:
        runner = (["uv", "run", "--script"] if shutil.which("uv") and not args.ci
                  else [sys.executable])
        cmd = [*runner, str(STRESS_SCRIPT),
               "--target", str(target),
               "--min-life", str(min_life),
               "--max-life", str(max_life)]
        print(f"==> launching stress_etw: target={target} life={min_life}-{max_life}s")
        stress = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        print(f"==> warmup {args.warmup_secs}s ...")
        time.sleep(args.warmup_secs)

    stats_before = fetch_stats_snapshot()
    late_before = late_rejected_proxied(stats_before)
    socks_before = socks.handled if socks else 0

    conn_probe: ConnectProbe | None = None
    if socks is not None and work is not None and not args.no_connect_probes:
        try:
            conn_probe = ConnectProbe(work)
            conn_probe.start()
            print(f"==> TCP connect probe running against local SOCKS5 127.0.0.1:{socks.port}")
        except OSError as e:
            print(f"WARN: connect probe disabled ({e})", file=sys.stderr)
            conn_probe = None

    load = HttpLoad(workers) if workers > 0 else None
    if load:
        print(f"==> HTTP load: {workers} workers over {', '.join(LOAD_PATHS)}")
        load.start()

    phases: list[dict] = []
    t_start = time.monotonic()
    try:
        if not args.visibility_cycle:
            phases.append(run_phase("steady", args.measure_secs,
                                    target_pid, args.hijack_interval))
        else:
            hwnd = find_clew_hwnd()
            if hwnd is None:
                print("ERROR: ProxyClawWebViewClass hwnd not found "
                      "(need GUI mode + proxyclaw.exe to be visible at start)",
                      file=sys.stderr)
                return 1
            print(f"==> hwnd=0x{hwnd:x}")
            phases.append(run_phase("visible-pre",
                                    args.measure_secs,
                                    target_pid, args.hijack_interval))
            print("\n==> minimize -> SC_MINIMIZE")
            post_wm(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0)
            time.sleep(0.5)
            phases.append(run_phase("hidden",
                                    args.measure_secs,
                                    target_pid, args.hijack_interval))
            print("\n==> restore -> SC_RESTORE")
            post_wm(hwnd, WM_SYSCOMMAND, SC_RESTORE, 0)
            time.sleep(0.5)
            phases.append(run_phase("visible-post",
                                    args.measure_secs,
                                    target_pid, args.hijack_interval))
    finally:
        if load:
            load.finish()
        if conn_probe is not None:
            conn_probe.stop()
        if stress is not None:
            try:
                stress.send_signal(signal.CTRL_BREAK_EVENT)
                stress.wait(timeout=5)
            except Exception:
                with contextlib.suppress(Exception):
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(stress.pid)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
        with contextlib.suppress(Exception):
            helper.kill()
            helper.wait(timeout=2)
    elapsed = time.monotonic() - t_start
    resources, rss_vs_proc = sampler.finish() if sampler else ({}, {})
    stats_after = fetch_stats_snapshot()
    late_after = late_rejected_proxied(stats_after)
    socks_handled = (socks.handled - socks_before) if socks else None

    perf_before = (stats_before or {}).get("perf") or {}
    perf_after  = (stats_after or {}).get("perf") or {}
    dec_lat  = diff_latency_hist(perf_before.get("decision_latency_us"),
                                 perf_after.get("decision_latency_us"))
    disp_lat = diff_latency_hist(perf_before.get("dispatch_latency_us"),
                                 perf_after.get("dispatch_latency_us"))
    park_lat = diff_latency_hist(perf_before.get("park_latency_us"),
                                 perf_after.get("park_latency_us"))
    missed_keys = [
        "late_rejected_proxied",
        "released_by_watchdog",
        "pool_exhausted",
        "v6_watchdog",
        "udp_park_watchdog",
        "udp_park_full",
    ]
    missed = diff_counters(perf_before.get("missed_proxies"),
                           perf_after.get("missed_proxies"),
                           missed_keys)

    print()
    print("=" * 60)
    print(f"Backend stress report — scenario={args.scenario} target={target}")
    print("=" * 60)
    for phase in phases:
        report(phase)

    # ---- compact summary + pass/fail (errors and crashes only) ----
    crashed = proc is not None and proc.poll() is not None
    alive = False
    with contextlib.suppress(Exception):
        alive = requests.get(f"{BASE}/stats", timeout=5).status_code == 200
    rtts = [x for ph in phases for x in ph["rtts_hijack"] + ph["rtts_unhijack"]]
    lat = load.lat_us if load else []
    load_errors = load.errors if load else []
    err_lines = 0
    if LOG_PATH.exists():
        t_wall0 = time.time() - elapsed - 5
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+\[E\]", line)
                if m and parse_ts(m.group(1)) >= t_wall0:
                    err_lines += 1
    requests_total = len(lat) + len(load_errors) + len(rtts) + len(HIJACK_ERRORS)
    errors_total = len(load_errors) + len(HIJACK_ERRORS)
    summary = {
        "scenario": args.scenario, "ci": bool(args.ci),
        "duration_s": round(elapsed, 1), "churn_target": target,
        "churn_life_s": [min_life, max_life], "http_workers": workers,
        "io_workers": perf_after.get("io_workers"),
        "connect_probes_proxied": socks_handled,
        "requests": requests_total, "errors": errors_total,
        "rps": round(requests_total / elapsed, 1) if elapsed else None,
        "latency_ms": {"p50": pct_ms(lat, 0.50), "p95": pct_ms(lat, 0.95),
                       "p99": pct_ms(lat, 0.99), "max": pct_ms(lat, 1.0), "n": len(lat)},
        "hijack_rtt_ms": {"p50": pct_ms(rtts, 0.50), "p95": pct_ms(rtts, 0.95),
                          "p99": pct_ms(rtts, 0.99), "n": len(rtts)},
        "decision_latency_us": dec_lat,
        "dispatch_latency_us": disp_lat,
        "park_latency_us": park_lat,
        "missed_proxies": missed,
        "rss_vs_processes": rss_vs_proc,
        "trace_events": sum(len(ph["events"]) for ph in phases),
        "log_error_lines": err_lines,
        "proxyclaw": resources,
        "proxyclaw_crashed": crashed, "api_alive_after": alive,
        "error_samples": (load_errors + HIJACK_ERRORS)[:10],
        # Reported, not gated (ROADMAP v0.14/v0.18: compare across runs).
        "late_rejected_proxied": {
            "before": late_before, "after": late_after,
            "delta": (late_after - late_before)
                     if late_before is not None and late_after is not None else None,
        },
    }
    ok = errors_total == 0 and not crashed and alive
    summary["result"] = "pass" if ok else "fail"

    print("\n---- stress smoke summary ----")
    lm, hm = summary["latency_ms"], summary["hijack_rtt_ms"]
    print(f"duration={summary['duration_s']}s requests={requests_total} errors={errors_total} "
          f"rps={summary['rps']} io_workers={summary['io_workers']} "
          f"proxied_probes={socks_handled}")
    print(f"GET latency ms: p50={lm['p50']} p95={lm['p95']} p99={lm['p99']} max={lm['max']}")
    print(f"hijack/unhijack RTT ms: p50={hm['p50']} p95={hm['p95']} p99={hm['p99']} n={hm['n']}")
    if dec_lat:
        print(f"CONNECT->publish us: n={dec_lat['count']} p50={dec_lat['p50_us']} "
              f"p95={dec_lat['p95_us']} p99={dec_lat['p99_us']} mean={dec_lat['mean_us']} "
              f"cum_max={dec_lat['cum_max_us']}")
    if disp_lat:
        print(f"Recv->publish us:    n={disp_lat['count']} p50={disp_lat['p50_us']} "
              f"p95={disp_lat['p95_us']} p99={disp_lat['p99_us']} mean={disp_lat['mean_us']}")
    if park_lat:
        print(f"SYN park wait us:    n={park_lat['count']} p50={park_lat['p50_us']} "
              f"p95={park_lat['p95_us']} p99={park_lat['p99_us']} mean={park_lat['mean_us']}")
    print(f"missed_proxies (delta): {missed}")
    if resources:
        print(f"proxyclaw.exe: working set MB {resources['working_set_mb']}, "
              f"private MB {resources['private_mb']}, handles {resources['handles']}")
    if rss_vs_proc:
        print(f"RSS vs processes: proc={rss_vs_proc['process_count']} "
              f"ws_mb=[{rss_vs_proc['working_set_mb_at_min_proc']} -> "
              f"{rss_vs_proc['working_set_mb_at_max_proc']}] "
              f"ws_kb/proc={rss_vs_proc['ws_kb_per_process']} "
              f"priv_kb/proc={rss_vs_proc['private_kb_per_process']}")
    print(f"log [E] lines in window: {err_lines}  crashed={crashed}  api_alive_after={alive}")
    lr = summary["late_rejected_proxied"]
    print(f"late_rejected_proxied: before={lr['before']} after={lr['after']} delta={lr['delta']}")
    if summary["error_samples"]:
        print(f"error samples: {summary['error_samples']}")
    print(f"RESULT: {summary['result'].upper()}")
    if args.summary_json:
        args.summary_json.parent.mkdir(parents=True, exist_ok=True)
        args.summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if args.compare and args.compare.exists():
        print("\n---- comparison vs baseline ----")
        base_summary = json.loads(args.compare.read_text(encoding="utf-8"))
        print(format_comparison(base_summary, summary, args.compare.stem, "current"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
