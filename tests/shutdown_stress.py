"""Close-while-busy stress test for proxyclaw.exe (exit crash / hang hunt).

The intermittent exit failures (0xC0000005, or no exit within 20 s) were only
seen at the end of the screenshot test, where the window is closed while
proxied demo connections are alive and the harness kills the demo processes
and drops the SOCKS5 connections at about the same moment. This repeats that
situation N times with more traffic and a random offset between the close
and the teardown:

  start proxyclaw.exe -> wait for /api/stats tree_ready -> churn helpers hold
  proxied TCP connections, open/close new ones and send UDP -> WM_CLOSE to the
  window -> after 0-200 ms kill the helpers and drop the SOCKS5 side -> expect
  exit code 0 within 20 s.

A hang gets a full dump (dump_hung_process); a crash is caught by WER
LocalDumps (configured by the workflow). Logs of failed rounds go to --out.

    python tests/shutdown_stress.py --exe dist/<pkg>/proxyclaw.exe --out build/shutdown-stress
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import pathlib
import random
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from ui_webview2_screenshots import HoldingSocks5, dump_hung_process, wait_tree_ready  # noqa: E402

CHURN_EXE = "pc-stress-net.exe"

CHURN = r"""
import socket, sys, threading, time
held = []
def tcp(host, port):
    try:
        s = socket.create_connection((host, port), timeout=5)
        return s
    except OSError:
        return None
for i in range(16):
    s = tcp("1.1.1.1", 80)
    if s: held.append(s)
print("HELD", len(held), flush=True)
def churn():
    while True:
        s = tcp("1.0.0.1", 80)
        if s:
            try: s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            except OSError: pass
            s.close()
        time.sleep(0.01)
def udp():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try: u.sendto(b"\x00" * 64, ("1.1.1.1", 53))
        except OSError: pass
        time.sleep(0.005)
for f in (churn, churn, udp):
    threading.Thread(target=f, daemon=True).start()
sys.stdin.readline()
"""

user32 = ctypes.WinDLL("user32", use_last_error=True)
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
WM_CLOSE = 0x0010


def main_window(pid: int) -> int | None:
    found: list[int] = []

    def cb(hwnd, _):
        owner = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
            return False
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return found[0] if found else None


def one_round(i: int, exe: pathlib.Path, work: pathlib.Path, churn_exe: pathlib.Path,
              script: pathlib.Path, out: pathlib.Path, rng: random.Random) -> str | None:
    socks = HoldingSocks5()
    token = secrets.token_hex(32)
    proxy = {"type": "socks5", "host": "127.0.0.1", "port": socks.port}
    config = {
        "version": 2,
        "default_proxy": proxy,
        "proxy_groups": [{"id": 0, "name": "default", "host": "127.0.0.1",
                          "port": socks.port, "type": "socks5"}],
        "next_group_id": 1,
        "auto_rules": [{"id": "stress", "name": "stress", "enabled": True,
                        "process_name": CHURN_EXE, "proxy_group_id": 0, "proxy": proxy}],
        "log_level": "info",
        "dns": {"enabled": False},
        "ui": {"window_width": 1024, "window_height": 720, "close_to_tray": False},
    }
    cfg = work / "proxyclaw.json"
    cfg.write_text(json.dumps(config, indent=2), encoding="utf-8")
    env = dict(os.environ, PROXYCLAW_API_TOKEN=token)
    proc = subprocess.Popen([str(exe), "--dev-hooks", "--config", str(cfg)], cwd=exe.parent, env=env)
    helpers: list[subprocess.Popen] = []
    problem = None
    try:
        wait_tree_ready(token, proc)
        deadline = time.time() + 30
        hwnd = None
        while hwnd is None and time.time() < deadline:
            hwnd = main_window(proc.pid)
            if hwnd is None:
                time.sleep(0.2)
        if hwnd is None:
            raise RuntimeError("no visible window")
        for _ in range(2):
            helpers.append(subprocess.Popen([str(churn_exe), str(script)], stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            text=True))
        held = [h.stdout.readline().strip() for h in helpers]
        time.sleep(rng.uniform(1.0, 3.0))
        offset = rng.uniform(0.0, 0.2)
        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        time.sleep(offset)
        for h in helpers:
            h.kill()
        socks.close()
        print(f"round {i}: {held}, teardown {offset * 1000:.0f} ms after WM_CLOSE")
    except Exception as e:  # noqa: BLE001
        problem = f"harness: {e!r}"
        if proc.poll() is None:
            proc.terminate()
    finally:
        for h in helpers:
            if h.poll() is None:
                h.kill()
        socks.close()
    try:
        code = proc.wait(20)
        if code != 0 and problem is None:
            problem = f"exit code {code:#x}" if code >= 0 else f"exit code {code}"
    except subprocess.TimeoutExpired:
        problem = "no exit within 20s after WM_CLOSE"
        dump_hung_process(proc.pid)
        proc.kill()
        proc.wait(10)
    log = exe.parent / "proxyclaw.log"
    if problem and log.exists():
        shutil.copy2(log, out / f"round-{i}-proxyclaw.log")
    trace = exe.parent / "proxyclaw.shutdown.log"
    if problem and trace.exists():
        shutil.copy2(trace, out / f"round-{i}-shutdown.log")
        tail = trace.read_text(encoding="utf-8", errors="replace").splitlines()[-3:]
        print(f"  shutdown trace tail: {tail}", flush=True)
    return problem


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    exe = args.exe.resolve()
    out = args.out.resolve()
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    rng = random.Random(seed)
    print(f"seed {seed}, {args.rounds} rounds")

    work = pathlib.Path(tempfile.mkdtemp(prefix="pc_shutdown_"))
    script = work / "churn.py"
    script.write_text(CHURN, encoding="utf-8")
    # python.exe needs its DLLs next to it.
    churn_exe = pathlib.Path(sys.executable).resolve().parent / CHURN_EXE
    shutil.copy2(sys.executable, churn_exe)
    failures: list[str] = []
    try:
        for i in range(1, args.rounds + 1):
            problem = one_round(i, exe, work, churn_exe, script, out, rng)
            if problem:
                print(f"FAIL round {i}: {problem}")
                failures.append(f"round {i}: {problem}")
    finally:
        churn_exe.unlink(missing_ok=True)
        shutil.rmtree(work, ignore_errors=True)
    if failures:
        print(f"FAIL {len(failures)}/{args.rounds} rounds:\n  " + "\n  ".join(failures))
        return 1
    print(f"PASS {args.rounds} rounds, clean exit every time")
    return 0


if __name__ == "__main__":
    sys.exit(main())
