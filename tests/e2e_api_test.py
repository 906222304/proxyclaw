"""
ProxyClaw E2E API Test
=====================
Tests the core flow: rule creation → process hijack → traffic interception → proxy routing.

Two modes:

* Attach (local dev): proxyclaw.exe already running elevated on :18080 with
  --dev-hooks and the same PROXYCLAW_API_TOKEN, plus a real SOCKS5 proxy on 127.0.0.1:7890
  whose exit IP differs from the direct one. Routing is judged by exit IP.

      python tests/e2e_api_test.py [-k SUBSTR]

* Launch (CI): --exe starts proxyclaw.exe itself (elevated shell required)
  with a throwaway config whose default group points at a recording SOCKS5
  server run in-process (tests/e2e_rule_policy.py's Socks5Server). Routing is
  judged by whether that server saw the probe's CONNECT, so no external
  proxy or second exit IP is needed.

      python tests/e2e_api_test.py --exe dist/<pkg>/proxyclaw.exe
"""

import ctypes
import json
import os
import pathlib
import queue
import re
import sys

import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import api_token  # noqa: F401  (adds the API session token; see tests/api_token.py)
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator

BASE = "http://127.0.0.1:18080/api"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 7890

# Launch mode (--exe): in-process recording SOCKS5 server; routing verdicts
# come from its CONNECT log instead of the exit IP.
RECORDER = None
RECORDER_URL = "http://1.1.1.1/"
RECORDER_DST = ("1.1.1.1", 80)

# Traffic probe: a private copy of curl.exe under a name only this suite
# matches. The user's own instance usually carries a `curl.exe` rule; the
# control case (rule disabled -> direct) must never touch that one.
# System32 curl is a single static binary (schannel); MSYS/mingw curl needs
# its DLL neighbours and would not start from a copy.
PROBE_NAME = "clew_e2e_curl.exe"
PROBE_DIR  = pathlib.Path(tempfile.gettempdir()) / "clew_e2e"
PROBE_EXE  = PROBE_DIR / PROBE_NAME
SYSTEM_CURL = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"

# Exit-IP oracle targets. Each returns the caller's public IP as plain text
# (or JSON with an "origin"/"ip" field). Override with PROXYCLAW_E2E_IP_URL.
IP_URL_CANDIDATES = [
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://icanhazip.com",
]
PROBE_ARGS = ["-s", "--connect-timeout", "10", "-m", "20", "--noproxy", "*"]

# proxyclaw.log lives next to proxyclaw.exe (since v0.9.0 chdir was reverted in favor
# of explicit exe-dir resolution). Tests scan it for tagged events that
# can't be observed at the HTTP level alone — see T22/T23 below.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
LOG_PATH  = REPO_ROOT / "build" / "Release" / "proxyclaw.log"

# Quill format: "%(time) [%(log_level_short_code)] %(message)"
# Shortened: "2026-05-01 14:15:23.123456 [D] [tree-change] source=batch_hijack"
_LOG_LINE_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+'
    r'\[(?P<lvl>[IDWE])\]\s+'
    r'(?P<msg>.*)$'
)


def _parse_log_ts(s: str) -> float:
    """Quill timestamps are local-time naive; matches time.time() domain."""
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").timestamp()


def collect_log_messages(pattern: re.Pattern,
                         ts_start: float,
                         ts_end: float) -> list[tuple[float, re.Match]]:
    """Scan proxyclaw.log, return [(ts, match), ...] for lines whose timestamp
    is in [ts_start, ts_end] AND whose message body matches `pattern`.

    Real-time tailing on Windows + quill is unreliable (see stress_backend.py
    rationale). We re-read the file at end of the measurement window — the
    log is small enough that scanning the whole thing is fine."""
    out: list[tuple[float, re.Match]] = []
    if not LOG_PATH.exists():
        return out
    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m_outer = _LOG_LINE_RE.match(line.rstrip("\n"))
            if not m_outer:
                continue
            ts = _parse_log_ts(m_outer.group("ts"))
            if ts < ts_start or ts > ts_end:
                continue
            m_inner = pattern.search(m_outer.group("msg"))
            if m_inner:
                out.append((ts, m_inner))
    return out


def wait_log_messages(pattern: re.Pattern, ts_start: float, ts_end: float,
                      done, timeout: float = 5.0) -> list[tuple[float, re.Match]]:
    """collect_log_messages, re-read until done(events) or timeout. Quill
    writes on its backend thread, so a line stamped inside the window can
    reach the file a few hundred ms later on a loaded runner; a single read
    after a fixed sleep raced that flush."""
    deadline = time.monotonic() + timeout
    while True:
        events = collect_log_messages(pattern, ts_start, ts_end)
        if done(events) or time.monotonic() >= deadline:
            return events
        time.sleep(0.1)

passed = 0
failed = 0
errors = []


def test(name):
    """Decorator for test functions."""
    def decorator(fn):
        def wrapper():
            global passed, failed
            try:
                fn()
                passed += 1
                print(f"  [PASS] {name}")
            except AssertionError as e:
                failed += 1
                errors.append(f"{name}: {e}")
                print(f"  [FAIL] {name}: {e}")
            except Exception as e:
                failed += 1
                errors.append(f"{name}: {type(e).__name__}: {e}")
                print(f"  [ERR]  {name}: {e}")
        wrapper.__name__ = name
        return wrapper
    return decorator


# ============================================================
# 1. API Health
# ============================================================

@test("API is reachable")
def test_api_reachable():
    # Engine is always-on (no /api/proxy/status); use /api/stats as a liveness probe.
    r = requests.get(f"{BASE}/stats", timeout=3)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict), f"Unexpected stats payload: {data}"


@test("Process tree is populated")
def test_process_tree():
    # /api/processes was removed when the backend->frontend push channel
    # switched from SSE to WebView2 PostMessage; the snapshot is delivered
    # in the push payload itself. e2e here only needs a backend liveness
    # signal — /api/stats works.
    r = requests.get(f"{BASE}/stats", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert "hijacked_pids" in data, f"unexpected stats payload: {data}"


@test("Stats endpoint returns data")
def test_stats():
    r = requests.get(f"{BASE}/stats", timeout=3)
    assert r.status_code == 200
    data = r.json()
    assert "hijacked_pids" in data
    assert "auto_rules_count" in data
    # v0.13.1: IPv6 is kept out of the decision path and counted instead.
    v6 = data.get("ipv6_unmanaged")
    assert isinstance(v6, dict) and isinstance(v6.get("tcp"), int) \
        and isinstance(v6.get("udp"), int), f"ipv6_unmanaged missing: {data}"


@test("TCP table returns data")
def test_tcp_table():
    r = requests.get(f"{BASE}/tcp", timeout=5)
    assert r.status_code == 200
    conns = r.json()
    assert isinstance(conns, list)


@test("UDP table returns data")
def test_udp_table():
    r = requests.get(f"{BASE}/udp", timeout=5)
    assert r.status_code == 200
    endpoints = r.json()
    assert isinstance(endpoints, list)


@test("Icon API returns PNG for known process")
def test_icon_api():
    r = requests.get(f"{BASE}/icon", params={"name": "svchost.exe"}, timeout=5)
    assert r.status_code == 200, f"Status {r.status_code}"
    assert r.headers.get("Content-Type") == "image/png"
    assert len(r.content) > 50, f"PNG too small: {len(r.content)} bytes"


@test("Icon API returns 204 No Content when there is no icon")
def test_icon_api_no_icon():
    r = requests.get(f"{BASE}/icon", params={"name": "proxyclaw-e2e-no-such-exe.exe"}, timeout=5)
    assert r.status_code == 204, f"Status {r.status_code}"
    assert r.content == b"", f"Expected empty body, got {len(r.content)} bytes"


@test("Icon API rejects a request without name")
def test_icon_api_missing_name():
    r = requests.get(f"{BASE}/icon", timeout=5)
    assert r.status_code == 400, f"Status {r.status_code}"


@test("SSE endpoint connects")
def test_sse():
    r = requests.get(f"{BASE}/events", stream=True, timeout=3)
    assert r.status_code == 200
    assert "text/event-stream" in r.headers.get("Content-Type", "")
    r.close()


# ============================================================
# 2. Auto Rule CRUD
# ============================================================

TEST_RULE_NAME = "E2E_Test_Rule"

@test("Create auto rule")
def test_create_rule():
    # Clean up any leftover test rule
    rules = requests.get(f"{BASE}/auto-rules").json()
    for r in rules:
        if r["name"] == TEST_RULE_NAME:
            requests.delete(f"{BASE}/auto-rules/{r['id']}")

    r = requests.post(f"{BASE}/auto-rules", json={
        "name": TEST_RULE_NAME,
        "enabled": True,
        "process_name": PROBE_NAME,
        "cmdline_pattern": "",
        "image_path_pattern": "",
        "hack_tree": False,
        "protocol": "tcp",
        "proxy_group_id": 0,
        "dst_filter": {
            "include_cidrs": [], "exclude_cidrs": [],
            "include_ports": [], "exclude_ports": [],
        },
        "proxy": {"type": "socks5", "host": PROXY_HOST, "port": PROXY_PORT},
    })
    assert r.status_code == 200 or r.status_code == 201, f"Status {r.status_code}: {r.text}"
    data = r.json()
    assert data.get("success") or data.get("id"), f"Unexpected response: {data}"

    # Verify rule exists
    rules = requests.get(f"{BASE}/auto-rules").json()
    found = [rule for rule in rules if rule["name"] == TEST_RULE_NAME]
    assert found, "Created rule not found in list"


@test("List auto rules includes test rule")
def test_list_rules():
    r = requests.get(f"{BASE}/auto-rules")
    assert r.status_code == 200
    rules = r.json()
    names = [rule["name"] for rule in rules]
    assert TEST_RULE_NAME in names, f"Test rule not found in {names}"


# ============================================================
# 3. Traffic interception — correctness gate on the exit IP
#
# Every probe is a brand-new process that connects immediately (the
# escape case SYN parking exists for). The only assertion that proves a
# connection went through the proxy is the public IP the far end saw:
# counters can stay quiet while a wrong decision is published on time
# (the 14/200 storm misses of 2026-09-07 did exactly that).
# ============================================================

# IPv4 or IPv6: a proxy egress may be v6-preferred while the direct path
# is v4. Only equality of the token matters, never the family.
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})")


def _prepare_probe() -> None:
    PROBE_DIR.mkdir(parents=True, exist_ok=True)
    src = SYSTEM_CURL
    if not src.exists():
        found = shutil.which("curl")
        if not found:
            raise RuntimeError("no curl.exe found (System32 or PATH)")
        print(f"WARN: {SYSTEM_CURL} missing, copying {found} instead "
              "(non-static builds may fail to start)", file=sys.stderr)
        src = pathlib.Path(found)
    shutil.copy2(src, PROBE_EXE)


def _remove_probe() -> None:
    shutil.rmtree(PROBE_DIR, ignore_errors=True)


def _probe_env() -> dict:
    """Child environment with every *_proxy variable removed. A proxy env
    var sends the probe to 127.0.0.1 (loopback, never intercepted) and
    hides the hijack — see lesson: system proxy masks hijack."""
    return {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}


def _spawn_probe(url: str, extra: list[str] | None = None) -> subprocess.Popen:
    return subprocess.Popen(
        [str(PROBE_EXE), *PROBE_ARGS, *(extra or []), url],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=_probe_env(),
    )


def _finish_probe(p: subprocess.Popen) -> tuple[int, str]:
    out, err = p.communicate(timeout=40)
    m = _IP_RE.search(out or "")
    return p.returncode, (m.group(1) if m else (out or err or "").strip()[:80])


def _run_probe(url: str, extra: list[str] | None = None) -> tuple[int, str]:
    return _finish_probe(_spawn_probe(url, extra))


_oracle: dict | None = None


def _resolve_ip_oracle() -> dict:
    """Pick a target and measure both reference IPs once per run.
      proxy_ip  — probe with --proxy socks5://127.0.0.1:7890. Loopback is
                  never intercepted, and socks5:// (not socks5h://) resolves
                  locally so the proxy sees the same destination IP as it
                  does on the hijacked path.
      direct_ip — python requests, trust_env=False (python.exe has no rule).
    Refuses to run when the two are equal: the target would then be routed
    DIRECT by the proxy and every assertion below would be meaningless."""
    global _oracle
    if _oracle is not None:
        return _oracle
    if RECORDER is not None:
        _oracle = {"url": RECORDER_URL, "direct_ip": "direct", "proxy_ip": "proxy"}
        print(f"    oracle: {RECORDER_URL} judged by the recording SOCKS5 server")
        return _oracle
    override = os.environ.get("PROXYCLAW_E2E_IP_URL")
    candidates = [override] if override else IP_URL_CANDIDATES
    tried = []
    direct_session = requests.Session()
    direct_session.trust_env = False     # ignore *_proxy env vars
    for url in candidates:
        try:
            r = direct_session.get(url, timeout=10)
            m = _IP_RE.search(r.text)
            direct_ip = m.group(1) if m else None
        except Exception as e:
            tried.append(f"{url}: direct failed ({type(e).__name__}: {e})")
            continue
        rc, proxy_ip = _run_probe(url, ["--proxy", f"socks5://{PROXY_HOST}:{PROXY_PORT}"])
        if not direct_ip or rc != 0 or not _IP_RE.fullmatch(proxy_ip):
            tried.append(f"{url}: direct={direct_ip} proxy rc={rc} out={proxy_ip!r}")
            continue
        if direct_ip == proxy_ip:
            tried.append(f"{url}: proxy exit == direct ({direct_ip}); "
                         "the proxy routes this target DIRECT")
            continue
        _oracle = {"url": url, "direct_ip": direct_ip, "proxy_ip": proxy_ip}
        print(f"    oracle: {url}  direct={direct_ip}  proxy={proxy_ip}")
        return _oracle
    raise AssertionError("no usable exit-IP target (set PROXYCLAW_E2E_IP_URL): "
                         + "; ".join(tried))


def _parking_stats() -> dict | None:
    """tcp_syn_parking block of /api/stats, or None when parking is off."""
    s = requests.get(f"{BASE}/stats", timeout=5).json()
    return s.get("tcp_syn_parking")


def _reset_routing() -> None:
    if RECORDER is not None:
        RECORDER.take()


def _assert_all_exit(results: list[tuple[int, str]], want_ip: str, label: str) -> None:
    if RECORDER is not None:
        time.sleep(0.3)
        seen = sum(1 for d in RECORDER.take() if d == RECORDER_DST)
        n = len(results)
        bad_rc = [(i, rc) for i, (rc, _) in enumerate(results) if rc != 0]
        want = n if want_ip == "proxy" else 0
        print(f"    {label}: {n - len(bad_rc)}/{n} completed, "
              f"{seen}/{n} seen by SOCKS5 (want {want})")
        assert not bad_rc, f"probes failed: {bad_rc[:10]}"
        assert seen == want, f"{seen}/{n} probes went via the proxy, expected {want}"
        return
    bad = [(i, rc, ip) for i, (rc, ip) in enumerate(results) if ip != want_ip]
    n = len(results)
    print(f"    {label}: {n - len(bad)}/{n} exit={want_ip}")
    assert not bad, (f"{len(bad)}/{n} probes did not exit via {want_ip}: "
                     + ", ".join(f"#{i} rc={rc} got={ip!r}" for i, rc, ip in bad[:10]))


def _assert_parking_delta(before: dict | None, n: int) -> None:
    """Secondary evidence. Requires /api/stats to carry tcp_syn_parking."""
    if before is None:
        print("    (tcp_syn_parking absent: parking disabled, counters skipped)")
        return
    time.sleep(0.5)
    after = _parking_stats()
    assert after is not None, "tcp_syn_parking vanished mid-run"
    ps, pa = before["parking"], after["parking"]
    ss, sa = before["socket"], after["socket"]
    d_proxied  = sa["proxied_decisions"] - ss["proxied_decisions"]
    d_watchdog = pa["released_by_watchdog"] - ps["released_by_watchdog"]
    d_late     = sa["late_rejected"] - ss["late_rejected"]
    print(f"    counters: proxied+{d_proxied} parked+{pa['parked'] - ps['parked']} "
          f"watchdog+{d_watchdog} late+{d_late} pool_in_use={pa['pool_in_use']} "
          f"pool_peak={pa['pool_peak']}")
    assert d_proxied >= n, f"proxied_decisions rose by {d_proxied}, expected >= {n}"
    assert d_watchdog == 0, f"released_by_watchdog rose by {d_watchdog}"
    assert d_late == 0, f"late_rejected rose by {d_late}"
    assert pa["pool_in_use"] == 0, f"pool_in_use={pa['pool_in_use']} after settle"


SEQ_N   = 20
BURST_N = 20
CTRL_N  = 5


@test(f"fresh probe processes, sequential: {SEQ_N}/{SEQ_N} exit via proxy")
def test_probe_sequential():
    o = _resolve_ip_oracle()
    before = _parking_stats()
    _reset_routing()
    results = [_run_probe(o["url"]) for _ in range(SEQ_N)]
    _assert_all_exit(results, o["proxy_ip"], "sequential")
    _assert_parking_delta(before, SEQ_N)


@test(f"fresh probe processes, concurrent burst: {BURST_N}/{BURST_N} exit via proxy")
def test_probe_burst():
    o = _resolve_ip_oracle()
    before = _parking_stats()
    _reset_routing()
    procs = [_spawn_probe(o["url"]) for _ in range(BURST_N)]
    results = [_finish_probe(p) for p in procs]
    _assert_all_exit(results, o["proxy_ip"], "burst")
    _assert_parking_delta(before, BURST_N)


@test(f"control: probe with rule disabled -> {CTRL_N}/{CTRL_N} exit direct")
def test_probe_rule_disabled_goes_direct():
    """Proves the gate can go red and that disabling a rule really stops
    interception. PUT /api/auto-rules/:id is a patch (rule_handlers.cpp)."""
    o = _resolve_ip_oracle()
    rules = requests.get(f"{BASE}/auto-rules").json()
    rule = next((r for r in rules if r["name"] == TEST_RULE_NAME), None)
    assert rule is not None, "test rule missing"
    rid = rule["id"]
    r = requests.put(f"{BASE}/auto-rules/{rid}", json={"enabled": False})
    assert r.status_code == 200, f"disable failed: {r.status_code} {r.text}"
    try:
        time.sleep(0.3)
        _reset_routing()
        results = [_run_probe(o["url"]) for _ in range(CTRL_N)]
        _assert_all_exit(results, o["direct_ip"], "rule disabled")
    finally:
        r = requests.put(f"{BASE}/auto-rules/{rid}", json={"enabled": True})
        assert r.status_code == 200, f"re-enable failed: {r.status_code} {r.text}"


# ============================================================
# 4. Manual Hijack/Unhijack
# ============================================================

@test("Manual hijack and unhijack a PID")
def test_manual_hijack():
    # Use our own PID as a safe target. Since this script was launched after
    # clew's initial NtQuery snapshot, our PID enters the tree only via ETW
    # ProcessStart, which has buffer-flush latency (~hundreds of ms).
    import os
    test_pid = os.getpid()
    assert _wait_pid_in_tree(test_pid), \
        f"PID {test_pid} did not appear in tree within timeout (ETW lag?)"

    # Hijack
    r = requests.post(f"{BASE}/hijack/{test_pid}", json={"tree": False, "group_id": 0})
    assert r.status_code == 200, f"Hijack failed: {r.status_code} {r.text}"

    # Verify
    time.sleep(0.5)
    r = requests.get(f"{BASE}/hijack")
    hijacked = r.json()
    hijacked_pids = [p["pid"] for p in hijacked] if isinstance(hijacked, list) else []
    assert test_pid in hijacked_pids, f"PID {test_pid} not in hijacked list"

    # Unhijack
    r = requests.delete(f"{BASE}/hijack/{test_pid}")
    assert r.status_code == 200, f"Unhijack failed: {r.status_code}"

    # Verify unhijacked
    time.sleep(0.5)
    r = requests.get(f"{BASE}/hijack")
    hijacked = r.json()
    hijacked_pids = [p["pid"] for p in hijacked] if isinstance(hijacked, list) else []
    assert test_pid not in hijacked_pids, f"PID {test_pid} still hijacked"


# ============================================================
# 5. Refactor-specific regressions (T14–T20, added 2026-04-25)
# ============================================================
#
# These cover the four-layer design guarantees that the original 13 tests
# didn't exercise: batch-notify H5 correctness, config_store observer chain,
# proxy group full CRUD including conflict + migrate + test endpoint.

# ---------- SSE / process-tree helpers shared by T14+ ----------

RESERVED_PIDS = frozenset({0, 4})  # System Idle, System


def _is_event_line(line):
    return bool(line) and line.startswith("event:")


def _sse_reader(url, q, stop):
    """Push every `event: <name>` value from an SSE stream into q until stopped."""
    try:
        with requests.get(url, stream=True, timeout=30) as r:
            for line in r.iter_lines(decode_unicode=True):
                if stop.is_set():
                    return
                if _is_event_line(line):
                    q.put(line.removeprefix("event:").strip())
    except Exception:
        pass  # connection torn down on stop — expected


@contextmanager
def _sse_subscription(url, settle=0.3):
    """Yield a queue of SSE event names; reader thread is stopped on exit."""
    q = queue.Queue()
    stop = threading.Event()
    t = threading.Thread(target=_sse_reader, args=(url, q, stop), daemon=True)
    t.start()
    time.sleep(settle)
    try:
        yield q
    finally:
        stop.set()


def _drain(q):
    """Discard everything currently buffered. Non-blocking."""
    try:
        while True:
            q.get_nowait()
    except queue.Empty:
        return


def _count(q, name):
    """Count buffered events equal to `name`. Non-blocking."""
    n = 0
    try:
        while True:
            if q.get_nowait() == name:
                n += 1
    except queue.Empty:
        return n


def _iter_pids(nodes) -> Iterator[int]:
    """Flatten a process tree into a stream of pids."""
    for node in nodes:
        yield node["pid"]
        yield from _iter_pids(node.get("children", []))


def _wait_pid_in_tree(pid, timeout=15.0):
    """Poll the single-PID tree query until pid shows up. Tolerates ETW
    ProcessStart latency for processes spawned after the initial rundown:
    1s FlushTimer floor, observed at 2-3s+ on a busy 4-vCPU CI runner
    (run 42252770650). The deadline is a ceiling, not a wait: a healthy
    box returns in well under a second."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = requests.get(f"{BASE}/processes/{pid}", timeout=5)
        if r.status_code == 200:
            return True
        time.sleep(0.1)
    return False


def _hijack_when_known(pid, timeout=15.0):
    """POST /api/hijack/{pid} until it is accepted. The backend resolves a
    live PID the tree has not seen yet from the OS (resolve_pid_now), so on
    current builds the first call succeeds; polling keeps the precondition
    deterministic against older builds in attach mode."""
    deadline = time.monotonic() + timeout
    while True:
        r = requests.post(f"{BASE}/hijack/{pid}",
                          json={"tree": False, "group_id": 0}, timeout=5)
        if r.status_code == 200 or time.monotonic() >= deadline:
            return r
        time.sleep(0.1)


_TREE_CHANGE_RE = re.compile(r'\[tree-change\] source=(?P<source>\w+)')


@test("Batch hijack fires notify_tree_changed exactly once (H5)")
def test_batch_hijack_single_notify():
    """DESIGN H5: process_tree_manager::batch_hijack applies every add/remove
    on the strand and then fires notify_tree_changed("batch_hijack") exactly
    once for the whole batch — never per-pid. We assert the C++ invariant
    directly by counting `[tree-change] source=batch_hijack` lines in the
    measurement window. Background ETW pushes (source=etw_start / etw_stop /
    reconcile) and per-pid manual hijacks (source=manual_hijack) are
    correctly NOT counted, which is why the previous SSE/Playwright variants
    of this test were flaky on busy machines.

    Requires log_level=debug (set by main()'s setup phase)."""
    # Pre-settle: prior tests spawn curl.exe processes whose ProcessStop
    # events also generate tree-change lines, but those have a different
    # source tag so they don't pollute our count.
    time.sleep(0.5)

    tree = requests.get(f"{BASE}/processes").json() if False else None  # GET removed
    pids_resp = requests.get(f"{BASE}/processes").json() if False else None
    # /api/processes was removed with the PostMessage transition. Walk a
    # known-stable starting point: spawn cmd.exe children we own ourselves
    # so we know the PIDs without going through the tree.
    procs = []
    for _ in range(5):
        p = subprocess.Popen(
            ["cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        procs.append(p)
    test_pids = [p.pid for p in procs]
    try:
        # Wait for ETW to register every spawned pid so the strand has them
        # before we batch-hijack — and so the etw_start tree-change events
        # finish landing before the measurement window opens.
        for pid in test_pids:
            assert _wait_pid_in_tree(pid), (
                f"PID {pid} did not appear in tree (ETW backlog?)"
            )
        time.sleep(0.3)  # let etw_start tree-change lines flush

        ts_start = time.time()

        r = requests.post(f"{BASE}/hijack/batch", json={
            "pids": test_pids, "action": "hijack", "group_id": 0,
        })
        assert r.status_code == 200, f"batch hijack failed: {r.status_code} {r.text}"

        time.sleep(0.4)  # let quill flush + the listener fire
        ts_end = time.time()

        # Truth source: the /api/hijack state. All test pids must appear.
        hijacked_after = {p["pid"] for p in (requests.get(f"{BASE}/hijack").json() or [])}
        expected = set(test_pids)
        assert expected.issubset(hijacked_after), (
            f"batch did not hijack all expected pids: "
            f"missing {sorted(expected - hijacked_after)}"
        )

        # Window is fixed at [ts_start, ts_end]; only the file read is retried
        # until the batch line has been flushed, so extra lines still count.
        events = wait_log_messages(
            _TREE_CHANGE_RE, ts_start, ts_end,
            lambda ev: any(m.group("source") == "batch_hijack" for _, m in ev))
        batch_count = sum(1 for _, m in events if m.group("source") == "batch_hijack")

        # Exactly one batch_hijack tree-change in the window. ETW events
        # (source=etw_start / etw_stop) are filtered by source tag so the
        # test is robust to busy machines; the assertion targets only the
        # H5 invariant. If proxyclaw.log is missing we have bigger problems —
        # don't silently pass.
        assert LOG_PATH.exists(), f"{LOG_PATH} missing — chdir or log routing broken"
        assert batch_count == 1, (
            f"expected exactly 1 [tree-change] source=batch_hijack in window, "
            f"got {batch_count}. All sources seen: "
            f"{[m.group('source') for _, m in events]}"
        )

        # Cleanup
        requests.post(f"{BASE}/hijack/batch", json={
            "pids": test_pids, "action": "unhijack", "group_id": 0,
        })
        time.sleep(0.1)
    finally:
        for p in procs:
            try: p.terminate()
            except Exception: pass


_API_DELETE_RE = re.compile(
    r'\[api\] DELETE (?P<path>\S+) -> (?P<status>\d+) \((?P<us>\d+)us\)'
)


@test("DELETE /api/hijack roundtrip < 60ms (server-side, cpp-httplib regression net)")
def test_delete_under_60ms_serverside():
    """Pre-v0.8.8 cpp-httplib's MSG_PEEK + SO_RCVTIMEO bug made every DELETE
    block for read_timeout (default 5s). The fix shipped a 'body: \"\"' on
    the frontend; this is the regression net.

    We check the SERVER-SIDE elapsed time recorded by route_registry::dispatch
    (`[api] DELETE /api/hijack/N -> 200 (Xus)`), NOT the client-side wall
    clock. Client wall-clock is muddied by Windows TCP loopback Nagle and
    by Python's request stack overhead — the server-side number is what
    actually matters for the bug. Requires log_level=debug (the [api]
    line is INFO, but main()'s setup phase enables debug for T22 anyway)."""
    # Spawn an owned process so we have a stable PID to hijack/unhijack.
    p = subprocess.Popen(
        ["cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    try:
        # Precondition, untimed: the PID must be hijacked before we measure.
        # Only the DELETE round-trip below is under the 60ms cap; ETW
        # ProcessStart latency for the fresh cmd.exe is not (that was the
        # 2026-11-06 flake: 'PID did not appear in tree (ETW backlog?)').
        r = _hijack_when_known(p.pid)
        assert r.status_code == 200, f"hijack failed: {r.status_code} {r.text}"
        # Let the hijack's immediate push and the late ETW START (now an
        # idempotent no-op) drain off the strand so they don't share the
        # measured window.
        time.sleep(0.5)

        ts_start = time.time()
        r = requests.delete(f"{BASE}/hijack/{p.pid}")
        ts_end = time.time()
        assert r.status_code == 200, f"delete failed: {r.status_code} {r.text}"

        target = f"/api/hijack/{p.pid}"
        # Retry the read until quill has flushed the line.
        events = wait_log_messages(
            _API_DELETE_RE, ts_start, ts_end + 0.5,
            lambda ev: any(m.group("path") == target for _, m in ev))
        match = next((m for _, m in events if m.group("path") == target), None)
        assert match is not None, (
            f"no [api] DELETE log line found for {target} in window. "
            f"Events seen: {[(m.group('path'), m.group('us')) for _, m in events]}"
        )

        elapsed_us = int(match.group("us"))
        assert elapsed_us < 60_000, (
            f"DELETE took {elapsed_us}us server-side (cap 60_000us = 60ms). "
            f"Likely regression of cpp-httplib MSG_PEEK + SO_RCVTIMEO bug "
            f"(was: every DELETE blocked for read_timeout = 5s)."
        )
    finally:
        try: p.terminate()
        except Exception: pass


@test("PUT /api/config triggers auto rule reload (observer chain)")
def test_config_put_reloads_rules():
    """config_store.mutate runs observers outside the lock. One of them is
    rule_engine sync: it calls exec.command(apply_auto_rules_from_config).
    We insert a marker rule via PUT /api/config and verify /api/auto-rules
    picks it up — proving config -> config_store -> observer -> rule_engine
    path is live."""
    raw = requests.get(f"{BASE}/config").json()
    original_rules = list(raw.get("auto_rules", []))

    marker_id = "e2e_observer_marker"
    raw["auto_rules"] = original_rules + [{
        "id": marker_id,
        "name": "e2e-marker",
        "enabled": True,
        "process_name": "definitely_not_a_real_tool.exe",
        "cmdline_pattern": "",
        "image_path_pattern": "",
        "hack_tree": False,
        "protocol": "tcp",
        "proxy_group_id": 0,
        "proxy": {"type": "socks5", "host": "127.0.0.1", "port": 7890, "user": "", "password": ""},
        "dst_filter": {"include_cidrs": [], "exclude_cidrs": [],
                        "include_ports": [], "exclude_ports": []},
    }]

    r = requests.put(f"{BASE}/config", json=raw)
    assert r.status_code == 200, f"PUT /config failed: {r.text}"

    time.sleep(0.4)
    rules = requests.get(f"{BASE}/auto-rules").json()
    found = any(rule["id"] == marker_id for rule in rules)

    # Restore original rules before asserting
    raw["auto_rules"] = original_rules
    requests.put(f"{BASE}/config", json=raw)
    time.sleep(0.2)

    assert found, "marker rule not visible via /api/auto-rules; observer chain broken"


@test("PUT /api/config persists log_level change")
def test_config_log_level_roundtrip():
    """Sanity-check PUT /api/config for a scalar field. Pairs with the
    rule-reload test above to cover both list-field and scalar-field mutations."""
    raw = requests.get(f"{BASE}/config").json()
    original_level = raw.get("log_level", "info")

    raw["log_level"] = "debug" if original_level != "debug" else "info"
    r = requests.put(f"{BASE}/config", json=raw)
    assert r.status_code == 200, f"PUT /config failed: {r.text}"

    time.sleep(0.2)
    roundtrip = requests.get(f"{BASE}/config").json()
    new_level = roundtrip.get("log_level")

    # Restore
    raw["log_level"] = original_level
    requests.put(f"{BASE}/config", json=raw)

    assert new_level == raw["log_level"] or new_level != original_level, \
        f"log_level not persisted: wanted {raw['log_level']}, got {new_level}"


E2E_GROUP = "e2e_test_group"


def _purge_e2e_groups():
    groups = requests.get(f"{BASE}/proxy-groups").json()
    for g in groups:
        if g["name"].startswith(E2E_GROUP):
            try:
                requests.delete(f"{BASE}/proxy-groups/{g['id']}")
            except Exception:
                pass


def _purge_e2e_rules(name_prefix):
    rules = requests.get(f"{BASE}/auto-rules").json()
    for rule in rules:
        if rule["name"].startswith(name_prefix):
            try:
                requests.delete(f"{BASE}/auto-rules/{rule['id']}")
            except Exception:
                pass


@test("Proxy group CRUD roundtrip")
def test_group_crud():
    _purge_e2e_groups()

    r = requests.post(f"{BASE}/proxy-groups", json={
        "name": E2E_GROUP,
        "host": "127.0.0.1", "port": 9999, "type": "socks5",
    })
    assert r.status_code == 200, f"create failed: {r.status_code} {r.text}"
    created = r.json()
    gid = created.get("id")
    assert isinstance(gid, int) and gid > 0, f"expected positive gid, got {created}"

    r = requests.put(f"{BASE}/proxy-groups/{gid}", json={"port": 8888})
    assert r.status_code == 200, f"update failed: {r.text}"

    groups = requests.get(f"{BASE}/proxy-groups").json()
    my = next((g for g in groups if g["id"] == gid), None)
    assert my is not None, f"group {gid} missing after update"
    assert my["port"] == 8888, f"port update not applied: {my}"

    r = requests.delete(f"{BASE}/proxy-groups/{gid}")
    assert r.status_code == 200, f"delete failed: {r.text}"
    groups = requests.get(f"{BASE}/proxy-groups").json()
    assert not any(g["id"] == gid for g in groups), "group still listed after delete"


@test("Proxy group delete while in-use returns 409")
def test_group_delete_in_use():
    _purge_e2e_groups()
    _purge_e2e_rules("e2e_conflict_rule")

    r = requests.post(f"{BASE}/proxy-groups", json={
        "name": E2E_GROUP + "_inuse",
        "host": "127.0.0.1", "port": 9998, "type": "socks5",
    })
    assert r.status_code == 200
    gid = r.json()["id"]

    rr = requests.post(f"{BASE}/auto-rules", json={
        "name": "e2e_conflict_rule",
        "enabled": True,
        "process_name": "nonexistent.exe",
        "cmdline_pattern": "", "image_path_pattern": "",
        "hack_tree": False, "protocol": "tcp",
        "proxy_group_id": gid,
        "dst_filter": {"include_cidrs": [], "exclude_cidrs": [],
                        "include_ports": [], "exclude_ports": []},
        "proxy": {"type": "socks5", "host": "127.0.0.1", "port": 7890},
    })
    assert rr.status_code == 200

    r = requests.delete(f"{BASE}/proxy-groups/{gid}")
    assert r.status_code == 409, f"expected 409 conflict, got {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("error") == "group_in_use", f"unexpected error body: {body}"
    assert "details" in body, f"missing conflict details: {body}"

    _purge_e2e_rules("e2e_conflict_rule")
    requests.delete(f"{BASE}/proxy-groups/{gid}")


@test("Proxy group migrate rewrites rule.proxy_group_id and drops source")
def test_group_migrate():
    _purge_e2e_groups()
    _purge_e2e_rules("e2e_migrate_rule")

    src = requests.post(f"{BASE}/proxy-groups", json={
        "name": E2E_GROUP + "_src",
        "host": "127.0.0.1", "port": 9997, "type": "socks5",
    }).json()
    dst = requests.post(f"{BASE}/proxy-groups", json={
        "name": E2E_GROUP + "_dst",
        "host": "127.0.0.1", "port": 9996, "type": "socks5",
    }).json()
    src_id, dst_id = src["id"], dst["id"]

    rr = requests.post(f"{BASE}/auto-rules", json={
        "name": "e2e_migrate_rule",
        "enabled": True,
        "process_name": "nonexistent.exe",
        "cmdline_pattern": "", "image_path_pattern": "",
        "hack_tree": False, "protocol": "tcp",
        "proxy_group_id": src_id,
        "dst_filter": {"include_cidrs": [], "exclude_cidrs": [],
                        "include_ports": [], "exclude_ports": []},
        "proxy": {"type": "socks5", "host": "127.0.0.1", "port": 7890},
    })
    assert rr.status_code == 200

    m = requests.post(f"{BASE}/proxy-groups/{src_id}/migrate",
                      json={"target_group_id": dst_id})
    assert m.status_code == 200, f"migrate failed: {m.text}"

    time.sleep(0.4)
    rules = requests.get(f"{BASE}/auto-rules").json()
    mig = next((x for x in rules if x["name"] == "e2e_migrate_rule"), None)
    assert mig is not None, "rule disappeared after migrate"
    assert mig["proxy_group_id"] == dst_id, \
        f"rule still references source: {mig['proxy_group_id']} (want {dst_id})"

    groups = requests.get(f"{BASE}/proxy-groups").json()
    assert not any(g["id"] == src_id for g in groups), \
        "source group not deleted after migrate"

    _purge_e2e_rules("e2e_migrate_rule")
    requests.delete(f"{BASE}/proxy-groups/{dst_id}")


@test("Proxy group test endpoint returns a valid shape")
def test_group_test_endpoint():
    """The /test handler does a real SOCKS5 handshake + HTTP HEAD. Whether
    the network/proxy responds depends on the environment, so we only
    require a 200 with either latency_ms or error in the body — the aim
    is to catch crashes or missing endpoint, not to assert connectivity."""
    r = requests.post(f"{BASE}/proxy-groups/0/test", timeout=20)
    assert r.status_code == 200, f"unexpected status: {r.status_code} {r.text}"
    body = r.json()
    assert "latency_ms" in body or "error" in body, f"unexpected body: {body}"
    print(f"    group 0 test -> {body}")


@test("Proxy group input validation returns 400 (v0.13.1)")
def test_group_validation():
    _purge_e2e_groups()
    before = requests.get(f"{BASE}/proxy-groups").json()
    bad_bodies = [
        ({"port": 70000}, "port"),
        ({"port": 0}, "port"),
        ({"port": "abc"}, "port"),
        ({"host": ""}, "host"),
        ({"host": "127.0.0.1:1080"}, "host"),
        ({"type": "http"}, "type"),
        ({"user": "alice", "password": "secret"}, "user"),
    ]
    for extra, field in bad_bodies:
        body = {"name": E2E_GROUP + "_bad", "host": "127.0.0.1", "port": 1080, "type": "socks5"}
        body.update(extra)
        r = requests.post(f"{BASE}/proxy-groups", json=body)
        assert r.status_code == 400, f"{extra}: expected 400, got {r.status_code} {r.text}"
        err = r.json()
        assert err.get("details", {}).get("field") == field, f"{extra}: unexpected body {err}"
    after = requests.get(f"{BASE}/proxy-groups").json()
    assert len(after) == len(before), "a rejected create still added a group"

    # Valid create; IPv6 brackets are normalised away.
    r = requests.post(f"{BASE}/proxy-groups", json={
        "name": E2E_GROUP + "_v6", "host": "[::1]", "port": 1080, "type": "socks5"})
    assert r.status_code == 200, f"create failed: {r.status_code} {r.text}"
    gid = r.json()["id"]
    try:
        r = requests.put(f"{BASE}/proxy-groups/{gid}", json={"port": 65536})
        assert r.status_code == 400, f"update port 65536: {r.status_code} {r.text}"
        my = next(g for g in requests.get(f"{BASE}/proxy-groups").json() if g["id"] == gid)
        assert my["host"] == "::1" and my["port"] == 1080, f"unexpected stored group: {my}"

        # The settings editor path validates proxy_groups the same way.
        cfg = requests.get(f"{BASE}/config").json()
        bad = json.loads(json.dumps(cfg))
        for g in bad["proxy_groups"]:
            if g["id"] == gid:
                g["port"] = 70000
        r = requests.put(f"{BASE}/config", json=bad)
        assert r.status_code == 400, f"PUT /config with port 70000: {r.status_code} {r.text}"
        my = next(g for g in requests.get(f"{BASE}/proxy-groups").json() if g["id"] == gid)
        assert my["port"] == 1080, f"config PUT applied anyway: {my}"
    finally:
        requests.delete(f"{BASE}/proxy-groups/{gid}")


@test("Hijack with a non-existent group id returns 400 (v0.13.1)")
def test_hijack_unknown_group():
    test_pid = os.getpid()
    assert _wait_pid_in_tree(test_pid), f"PID {test_pid} not in tree"
    missing = max(g["id"] for g in requests.get(f"{BASE}/proxy-groups").json()) + 1000
    r = requests.post(f"{BASE}/hijack/{test_pid}", json={"group_id": missing})
    assert r.status_code == 400, f"expected 400, got {r.status_code} {r.text}"
    r = requests.post(f"{BASE}/hijack/batch",
                      json={"pids": [test_pid], "action": "hijack", "group_id": missing})
    assert r.status_code == 400, f"batch: expected 400, got {r.status_code} {r.text}"
    hijacked = [p["pid"] for p in requests.get(f"{BASE}/hijack").json()]
    assert test_pid not in hijacked, "process was hijacked into a missing group"


@test("Rule exclusion is runtime-only and survives a config reload (v0.13.1)")
def test_rule_exclusion_runtime():
    import socket as sk
    name = "clew_e2e_excl.exe"
    exe = PROBE_DIR / name
    shutil.copy2(PROBE_EXE, exe)
    _purge_e2e_rules("e2e_excl_rule")
    # A local listener that never answers keeps the process alive; loopback
    # is never intercepted, so the rule's group is irrelevant.
    srv = sk.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    rr = requests.post(f"{BASE}/auto-rules", json={
        "name": "e2e_excl_rule", "enabled": True, "process_name": name,
        "cmdline_pattern": "", "image_path_pattern": "", "hack_tree": False,
        "protocol": "tcp", "proxy_group_id": 0,
        "dst_filter": {"include_cidrs": [], "exclude_cidrs": [],
                       "include_ports": [], "exclude_ports": []},
        "proxy": {"type": "socks5", "host": "127.0.0.1", "port": PROXY_PORT},
    })
    assert rr.status_code == 200, f"rule create failed: {rr.text}"
    proc = subprocess.Popen([str(exe), "-s", "-m", "60", f"http://127.0.0.1:{port}/"],
                            env=_probe_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def rule_entry():
        return next(x for x in requests.get(f"{BASE}/auto-rules").json()
                    if x["name"] == "e2e_excl_rule")

    def pid_state():
        for p in rule_entry().get("matched_pids", []):
            if p["pid"] == proc.pid:
                return "excluded" if p["excluded"] else "matched"
        return None

    def wait_for(state, timeout=15.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if pid_state() == state:
                return True
            time.sleep(0.1)
        return False

    try:
        assert _wait_pid_in_tree(proc.pid), "probe not in tree"
        assert wait_for("matched"), f"rule never matched pid {proc.pid}: {rule_entry()}"
        rid = rule_entry()["id"]
        r = requests.post(f"{BASE}/auto-rules/{rid}/exclude/{proc.pid}")
        assert r.status_code == 200, f"exclude failed: {r.status_code} {r.text}"
        assert pid_state() == "excluded", f"not excluded: {rule_entry()}"

        # Any config mutation reloads the rules; the exclusion must survive
        # and must never be written to the config.
        cfg = requests.get(f"{BASE}/config").json()
        r = requests.put(f"{BASE}/config", json=cfg)
        assert r.status_code == 200, f"config PUT failed: {r.text}"
        time.sleep(0.3)
        assert pid_state() == "excluded", f"exclusion lost on reload: {rule_entry()}"
        raw = json.dumps(requests.get(f"{BASE}/config").json())
        assert "excluded" not in raw, "exclusion leaked into the config"

        r = requests.post(f"{BASE}/auto-rules/{rid}/exclude/4000000000")
        assert r.status_code == 404, f"exclude of a dead PID: {r.status_code} {r.text}"

        proc.kill()
        proc.wait(10)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and rule_entry().get("excluded_count", 0) != 0:
            time.sleep(0.2)
        assert rule_entry().get("excluded_count", 0) == 0, \
            f"exclusion outlived the process: {rule_entry()}"
    finally:
        if proc.poll() is None:
            proc.kill()
        srv.close()
        _purge_e2e_rules("e2e_excl_rule")


# ============================================================
# 6. Cleanup
# ============================================================

@test("Delete test auto rule")
def test_cleanup_rule():
    rules = requests.get(f"{BASE}/auto-rules").json()
    for rule in rules:
        if rule["name"] == TEST_RULE_NAME:
            r = requests.delete(f"{BASE}/auto-rules/{rule['id']}")
            assert r.status_code == 200, f"Delete failed: {r.status_code}"
            return
    # Rule already gone — OK


# ============================================================
# 7. DNS proxy round-trip (kept last — mutates system DNS)
# ============================================================

def _get_system_dns_servers():
    """IPv4 DNS servers of every adapter, via iphlpapi GetAdaptersAddresses.

    In-process and ~1ms. The previous `powershell Get-DnsClientServerAddress`
    cold-starts PowerShell + the CIM/WMI provider, which on a loaded CI runner
    blew through a 10s timeout (run 42248783753). This is also the API
    src/core/system_dns.hpp reads, so test and app see the same view."""
    import ctypes
    from ctypes import wintypes

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]

    class DNS_SERVER(ctypes.Structure):
        pass
    DNS_SERVER._fields_ = [("Length", wintypes.ULONG), ("Reserved", wintypes.DWORD),
                           ("Next", ctypes.POINTER(DNS_SERVER)),
                           ("Address", SOCKET_ADDRESS)]

    class ADAPTER(ctypes.Structure):
        pass
    # Leading fields of IP_ADAPTER_ADDRESSES_LH, up to FirstDnsServerAddress.
    ADAPTER._fields_ = [("Length", wintypes.ULONG), ("IfIndex", wintypes.DWORD),
                        ("Next", ctypes.POINTER(ADAPTER)),
                        ("AdapterName", ctypes.c_char_p),
                        ("FirstUnicastAddress", ctypes.c_void_p),
                        ("FirstAnycastAddress", ctypes.c_void_p),
                        ("FirstMulticastAddress", ctypes.c_void_p),
                        ("FirstDnsServerAddress", ctypes.POINTER(DNS_SERVER))]

    AF_INET = 2
    GAA_FLAG_SKIP_UNICAST, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST = 0x1, 0x2, 0x4
    flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
    fn = ctypes.windll.iphlpapi.GetAdaptersAddresses
    size = wintypes.ULONG(32 * 1024)
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value)
        rc = fn(AF_INET, flags, None, buf, ctypes.byref(size))
        if rc == 111:  # ERROR_BUFFER_OVERFLOW: size now holds the need
            continue
        break
    if rc != 0:
        raise OSError(f"GetAdaptersAddresses failed: {rc}")
    servers = set()
    node = ctypes.cast(buf, ctypes.POINTER(ADAPTER))
    while node:
        dns = node.contents.FirstDnsServerAddress
        while dns:
            sa = dns.contents.Address
            if sa.lpSockaddr and sa.iSockaddrLength >= 8:
                raw = ctypes.string_at(sa.lpSockaddr, 8)
                if int.from_bytes(raw[0:2], "little") == AF_INET:
                    servers.add(".".join(str(b) for b in raw[4:8]))
            dns = dns.contents.Next
        node = node.contents.Next
    return servers


def _wait_system_dns(pred, timeout=15.0):
    """Poll system DNS until pred(servers) holds; return the last reading.
    Replaces fixed sleeps after PUT /api/config: dns_mgr.apply runs on the
    config observer and SetInterfaceDnsSettings takes a variable time."""
    deadline = time.monotonic() + timeout
    while True:
        servers = _get_system_dns_servers()
        if pred(servers) or time.monotonic() >= deadline:
            return servers
        time.sleep(0.2)


def _query_dns(server_ip, hostname='example.com', timeout=5.0):
    """Raw UDP DNS A-query. Return True on response, False on timeout."""
    import socket as sk
    import struct

    txid   = 0x1234
    flags  = 0x0100  # standard query, recursion desired
    header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
    qname  = b''.join(bytes([len(p)]) + p.encode() for p in hostname.split('.')) + b'\x00'
    query  = header + qname + struct.pack('!HH', 1, 1)  # A, IN

    s = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (server_ip, 53))
        data, _ = s.recvfrom(512)
        return len(data) >= 12 and data[:2] == struct.pack('!H', txid)
    except (sk.timeout, OSError):
        return False
    finally:
        s.close()


@test("DNS proxy enable/disable round-trip with system DNS swap")
def test_dns_proxy_roundtrip():
    """Toggle dns.enabled via PUT /api/config and verify the full chain:
      - system DNS gets swapped to 127.0.0.2 on enable
      - forwarder on 127.0.0.2:53 actually answers a real query
        (validates SOCKS5 UDP ASSOCIATE path is alive)
      - system DNS gets restored on disable
    Cleans up unconditionally even on assertion failure."""
    raw          = requests.get(f"{BASE}/config").json()
    original_dns = dict(raw.get("dns") or {})

    initial_servers = _get_system_dns_servers()
    print(f"    system DNS before: {sorted(initial_servers) or '(empty)'}")

    try:
        # --- Enable ---
        enable_cfg = dict(raw, dns=dict(original_dns, enabled=True))
        r = requests.put(f"{BASE}/config", json=enable_cfg)
        assert r.status_code == 200, f"PUT enable failed: {r.status_code} {r.text}"

        servers_after_enable = _wait_system_dns(lambda s: "127.0.0.2" in s)
        assert "127.0.0.2" in servers_after_enable, (
            f"127.0.0.2 not in system DNS after enable: "
            f"{sorted(servers_after_enable)} (was {sorted(initial_servers)})"
        )

        # The forwarder can bind a moment after the system DNS swap; give it a
        # few query attempts instead of a single shot.
        ok = any(_query_dns("127.0.0.2", "example.com", timeout=3.0) for _ in range(3))
        assert ok, "DNS forwarder did not respond on 127.0.0.2:53 (3 x 3s)"

        # --- Disable ---
        disable_cfg = dict(raw, dns=dict(original_dns, enabled=False))
        r = requests.put(f"{BASE}/config", json=disable_cfg)
        assert r.status_code == 200, f"PUT disable failed: {r.status_code} {r.text}"

        servers_after_disable = _wait_system_dns(lambda s: "127.0.0.2" not in s)
        assert "127.0.0.2" not in servers_after_disable, (
            f"127.0.0.2 still in system DNS after disable: "
            f"{sorted(servers_after_disable)}"
        )
        if servers_after_disable != initial_servers:
            print(f"    note: system DNS differs from initial "
                  f"(initial={sorted(initial_servers)}, "
                  f"now={sorted(servers_after_disable)})")
    finally:
        # Belt-and-suspenders: restore original config even on failure
        try:
            requests.put(f"{BASE}/config", json=raw, timeout=5)
            time.sleep(0.5)
        except Exception:
            pass


# ============================================================
# Runner
# ============================================================

def _launch(exe: pathlib.Path) -> tuple[subprocess.Popen, pathlib.Path]:
    """Start proxyclaw.exe with a throwaway config routed at RECORDER."""
    global PROXY_PORT, LOG_PATH
    PROXY_PORT = RECORDER.port
    LOG_PATH = exe.parent / "proxyclaw.log"
    work = pathlib.Path(tempfile.mkdtemp(prefix="pc_e2e_api_"))
    config = {
        "version": 2,
        "default_proxy": {"type": "socks5", "host": "127.0.0.1", "port": PROXY_PORT},
        "proxy_groups": [
            {"id": 0, "name": "default", "host": "127.0.0.1", "port": PROXY_PORT,
             "type": "socks5", "test_url": "http://1.1.1.1/"},
        ],
        "next_group_id": 1,
        "auto_rules": [],
        "log_level": "debug",
        "dns": {"enabled": False},
    }
    cfg_path = work / "proxyclaw.json"
    cfg_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    proc = subprocess.Popen([str(exe), "--minimized", "--dev-hooks", "--config", str(cfg_path)],
                            cwd=exe.parent, env=dict(os.environ))
    deadline = time.time() + 30
    while True:
        if proc.poll() is not None:
            raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
        try:
            if requests.get(f"{BASE}/stats", timeout=2).status_code == 200:
                break
        except Exception:
            pass
        if time.time() > deadline:
            proc.kill()
            raise RuntimeError("proxyclaw API did not come up in 30s")
        time.sleep(0.5)
    _wait_tree_ready(proc)
    time.sleep(2)  # let the WinDivert layers settle
    return proc, work


def _graceful_exit(proc: subprocess.Popen, timeout: float = 30.0) -> bool:
    """Quit through the tray menu's exit command (WM_COMMAND IDM_TRAY_EXIT to
    the host window, exactly what clicking "退出 ProxyClaw" does) and require
    a clean shutdown: exit code 0 within `timeout`, and the log shows the
    WinDivert teardown (WinDivertShutdown -> join -> WinDivertClose, v0.13.1)
    completed. Catches shutdown hangs/crashes that terminate() would hide."""
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    user32.FindWindowW.restype = wintypes.HWND
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    hwnd = user32.FindWindowW("ClewWebViewClass", None)
    if not hwnd:
        print("graceful exit: host window not found")
        return False
    owner = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
    if owner.value != proc.pid:
        print(f"graceful exit: window belongs to pid {owner.value}, not {proc.pid}")
        return False
    offset = LOG_PATH.stat().st_size if LOG_PATH.exists() else 0
    t0 = time.monotonic()
    user32.PostMessageW(hwnd, 0x0111, 40002, 0)  # WM_COMMAND, IDM_TRAY_EXIT
    try:
        code = proc.wait(timeout)
    except subprocess.TimeoutExpired:
        print(f"graceful exit: still running {timeout:.0f}s after exit was requested (shutdown hang)")
        return False
    elapsed = time.monotonic() - t0
    tail = ""
    if LOG_PATH.exists():
        with open(LOG_PATH, "rb") as f:
            f.seek(offset)
            tail = f.read().decode("utf-8", errors="replace")
    markers = ["WinDivert layers stopped", "io_context stopped", "WinDivert layers closed", "Goodbye!"]
    missing = [m for m in markers if m not in tail]
    print(f"graceful exit: code={code} in {elapsed:.1f}s, missing log markers={missing}")
    return code == 0 and not missing


def _wait_tree_ready(proc=None, timeout=60.0):
    """Wait for the backend's initial process rundown to be verified
    (/api/stats tree_ready). Before this, tests that look up pre-existing
    PIDs (our own python.exe) raced the ETW capture_state. Builds without
    the flag are not waited on."""
    deadline = time.monotonic() + timeout
    while True:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
        s = requests.get(f"{BASE}/stats", timeout=5).json()
        if s.get("tree_ready", True):
            print(f"tree ready: {s.get('process_count', '?')} processes")
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"process tree not ready after {timeout:.0f}s: {s}")
        time.sleep(0.25)


def main() -> int:
    global RECORDER
    import argparse
    ap = argparse.ArgumentParser(description="ProxyClaw E2E API test")
    ap.add_argument("-k", dest="name_filter", default=None,
                    help="run only cases whose function name contains SUBSTR")
    ap.add_argument("--exe", type=pathlib.Path, default=None,
                    help="launch this proxyclaw.exe (elevated) with a recording SOCKS5 server")
    args = ap.parse_args()
    name_filter = args.name_filter.lower() if args.name_filter else None

    print("=" * 60)
    print("ProxyClaw E2E API Test")
    print("=" * 60)

    proc = work = None
    if args.exe is not None:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("SKIP: --exe needs an elevated shell (WinDivert)")
            return 2
        from e2e_rule_policy import Socks5Server
        RECORDER = Socks5Server()
        proc, work = _launch(args.exe.resolve())
    rc = 1
    graceful_ok = True
    try:
        rc = _run(name_filter)
    finally:
        if proc is not None:
            try:
                graceful_ok = _graceful_exit(proc)
            except Exception as e:  # noqa: BLE001 - report, then fall back to terminate
                print(f"graceful exit: {e!r}")
                graceful_ok = False
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if (failed or not graceful_ok) and LOG_PATH.exists():
                print("---- proxyclaw.log ([E]/[W] lines, last 60) ----")
                lines = [l for l in LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
                         if " [E] " in l or " [W] " in l]
                print("\n".join(lines[-60:]))
            shutil.rmtree(work, ignore_errors=True)
    if not graceful_ok:
        print("FAIL: graceful shutdown via the tray exit command")
        return 1
    return rc


def _run(name_filter: str | None) -> int:
    # Check connectivity first
    try:
        requests.get(f"{BASE}/stats", timeout=2)
    except Exception as e:
        print(f"\nERROR: Cannot reach ProxyClaw API at {BASE}")
        print(f"  {e}")
        print("\nMake sure proxyclaw.exe is running (admin) on port 18080.")
        return 1

    _wait_tree_ready()
    print(f"\nAPI: {BASE}")
    print(f"Proxy: socks5://{PROXY_HOST}:{PROXY_PORT}")
    print(f"Log:   {LOG_PATH}")
    print()

    # Some tests assert source-tagged invariants (e.g. T22 batch_hijack
    # single notify) by scanning proxyclaw.log. Those debug lines are dropped
    # at quill's compile-cheap path under the default log_level=info, so
    # we flip to debug for the duration of the run and restore on exit.
    cfg = requests.get(f"{BASE}/config").json()
    original_log_level = cfg.get("log_level", "info")
    if original_log_level != "debug":
        cfg["log_level"] = "debug"
        requests.put(f"{BASE}/config", json=cfg)
        time.sleep(0.2)
        print(f"log_level: {original_log_level} -> debug (will restore on exit)")
    else:
        print("log_level: already debug")
    print()

    tests = [
        test_api_reachable,
        test_process_tree,
        test_stats,
        test_tcp_table,
        test_udp_table,
        test_icon_api,
        test_icon_api_no_icon,
        test_icon_api_missing_name,
        # test_sse retired: /api/events removed with the SSE->PostMessage
        # transport switch. Push-channel coverage now lives in Playwright
        # (test_no_event_source / test_push_after_hijack).
        test_create_rule,
        test_list_rules,
        test_probe_sequential,                   # exit-IP gate, fresh processes
        test_probe_burst,
        test_probe_rule_disabled_goes_direct,    # control: the gate can go red
        test_manual_hijack,
        test_batch_hijack_single_notify,         # T22 — log-scan rewrite
        test_delete_under_60ms_serverside,       # T23 — log-scan rewrite
        test_config_put_reloads_rules,
        test_config_log_level_roundtrip,
        test_group_crud,
        test_group_delete_in_use,
        test_group_migrate,
        test_group_test_endpoint,
        test_group_validation,
        test_hijack_unknown_group,
        test_rule_exclusion_runtime,
        # Final cleanup
        test_cleanup_rule,
        # DNS round-trip last — mutates system DNS, has its own cleanup
        test_dns_proxy_roundtrip,
    ]

    if name_filter:
        keep = {test_create_rule, test_cleanup_rule}
        tests = [t for t in tests if t in keep or name_filter in t.__name__.lower()]
        print(f"filter -k {name_filter!r}: {len(tests)} cases\n")

    try:
        _prepare_probe()
        for t in tests:
            t()
    finally:
        _remove_probe()
        # Always restore log_level: in attach mode a leftover debug level
        # would persist into the user's proxyclaw.json via config_store::mutate.
        try:
            cfg2 = requests.get(f"{BASE}/config").json()
            if cfg2.get("log_level") != original_log_level:
                cfg2["log_level"] = original_log_level
                requests.put(f"{BASE}/config", json=cfg2)
        except Exception as e:
            print(f"WARN: failed to restore log_level: {e}", file=sys.stderr)

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    if errors:
        print("\nFailures:")
        for e in errors:
            print(f"  - {e}")
    print(f"{'=' * 60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
