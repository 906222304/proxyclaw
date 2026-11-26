"""Live hook-mode test: real proxyclaw.exe with interception.mode = "hook".

No WinDivert handle is opened in this mode; proxyclaw_hook64.dll is injected
into proxied processes instead. The probe is a renamed python.exe matched by
a rule (hack_tree on). It waits until ProxyClaw has injected it (the 1 s
sweep of running processes), then checks from the inside:

  - a blocking connect() goes through the SOCKS5 server, and getpeername()
    still reports the original destination;
  - an asyncio connection (Proactor loop = ConnectEx) does the same;
  - a port the rule excludes connects direct;
  - a child it starts (a renamed curl.exe, matched only through the tree)
    is injected before it runs, so its very first connection is proxied.

A curl.exe copy no rule matches must stay direct. /api/stats must report
the hook interception as active.

Usage (elevated):
    python tests/e2e_hook_mode.py --exe build/Release/proxyclaw.exe
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from e2e_rule_policy import SYSTEM_CURL, Socks5Server, api_get  # noqa: E402

# `import asyncio` loads _overlapped, which fetches the ConnectEx pointer at
# import -- before the injection the probe then waits for. The ConnectEx step
# therefore checks that a pointer cached before the DLL arrived is hooked.
PROBE = r"""
import asyncio, ctypes, json, os, socket, subprocess, sys, time, urllib.request

k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype = ctypes.c_void_p
deadline = time.time() + 20
while time.time() < deadline and not k32.GetModuleHandleW("proxyclaw_hook64.dll"):
    time.sleep(0.2)
out = {"injected": bool(k32.GetModuleHandleW("proxyclaw_hook64.dll"))}

def query_api_tcp(local_port, token):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        f"http://127.0.0.1:18080/api/tcp?pid={os.getpid()}",
        headers={"X-ProxyClaw-Token": token},
    )
    with opener.open(req, timeout=5) as resp:
        rows = json.loads(resp.read())
    for r in rows:
        if r.get("local_port") == local_port:
            return {
                "remote_ip": r.get("remote_ip"),
                "remote_port": r.get("remote_port"),
                "proxy_status": r.get("proxy_status"),
                "route_reason": r.get("route_reason"),
                "decision_source": r.get("decision_source"),
                "rule_id": (r.get("decision") or {}).get("rule_id"),
            }
    return None

def http(host, port=80, check_api=False):
    s = socket.create_connection((host, port), timeout=10)
    peer = list(s.getpeername()[:2])
    if check_api and len(sys.argv) > 2:
        try:
            out["api_tcp"] = query_api_tcp(s.getsockname()[1], sys.argv[2])
        except Exception as e:
            out["api_tcp"] = {"error": repr(e)}
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:18080/api/processes/{os.getpid()}",
                headers={"X-ProxyClaw-Token": sys.argv[2]},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                out["api_proc"] = json.loads(resp.read())
        except Exception as e:
            out["api_proc"] = {"error": repr(e)}
    s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
    data = s.recv(16)
    s.close()
    return peer, data.startswith(b"HTTP/")

def step(name, fn):
    try:
        out[name] = fn()
    except Exception as e:
        out[name] = "error: " + repr(e)

step("blocking", lambda: http("1.1.1.1", 80, check_api=True))

async def via_proactor():
    r, w = await asyncio.wait_for(asyncio.open_connection("1.0.0.1", 80), 10)
    peer = list(w.get_extra_info("peername")[:2])
    w.write(b"GET / HTTP/1.0\r\nHost: 1.0.0.1\r\n\r\n")
    await w.drain()
    data = await asyncio.wait_for(r.read(16), 10)
    w.close()
    return peer, data.startswith(b"HTTP/")

step("connectex", lambda: asyncio.run(via_proactor()))

def excluded():
    s = socket.create_connection(("1.1.1.1", 853), timeout=10)
    s.close()
    return True

step("excluded", excluded)

def bound_nic():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.connect(("1.1.1.1", 80))
        nic_ip = u.getsockname()[0]
    finally:
        u.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.bind((nic_ip, 0))
        s.connect(("1.0.0.1", 443))
        return [nic_ip, True]
    finally:
        s.close()

step("bound_nic", bound_nic)

def child():
    r = subprocess.run([sys.argv[1], "-s", "-k", "-o", "NUL", "-w", "%{http_code}", "--noproxy", "*",
                        "--connect-timeout", "10", "-m", "20", "https://1.1.1.1/"],
                       capture_output=True, text=True, timeout=40)
    return [r.returncode, r.stdout]

step("child", child)
if len(sys.argv) > 3 and sys.argv[3]:
    def child32():
        r = subprocess.run([sys.argv[3], "--connect-only"],
                           capture_output=True, text=True, timeout=40)
        return r.returncode
    step("child32", child32)
print(json.dumps(out))
"""

RULE = {
    "id": "e2e_hook",
    "name": "e2e hook",
    "enabled": True,
    "process_name": "pc_hook_app.exe",
    "cmdline_pattern": "",
    "image_path_pattern": "",
    "hack_tree": True,
    "protocol": "tcp",
    "proxy_group_id": 0,
    "dst_filter": {"include_cidrs": [], "exclude_cidrs": [], "include_ports": [],
                   "exclude_ports": ["853"]},
}

RULE32 = {
    "id": "e2e_hook32",
    "name": "e2e hook 32-bit",
    "enabled": True,
    "process_name": "pc_hook32_app.exe",
    "cmdline_pattern": "",
    "image_path_pattern": "",
    "hack_tree": True,
    "protocol": "tcp",
    "proxy_group_id": 0,
    "dst_filter": {"include_cidrs": [], "exclude_cidrs": [], "include_ports": [],
                   "exclude_ports": []},
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True, type=pathlib.Path)
    ap.add_argument("--probe32", type=pathlib.Path, help="optional 32-bit hook32_probe.exe for WOW64 checks")
    ap.add_argument("--keep", action="store_true", help="keep the temp dir")
    args = ap.parse_args()

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("SKIP: needs an elevated shell (process injection)")
        return 2

    exe = args.exe.resolve()
    if not (exe.parent / "proxyclaw_hook64.dll").is_file():
        print(f"FAIL: proxyclaw_hook64.dll missing next to {exe}")
        return 1
    if not (exe.parent / "proxyclaw_hook32.dll").is_file():
        print(f"FAIL: proxyclaw_hook32.dll missing next to {exe}")
        return 1
    work = pathlib.Path(tempfile.mkdtemp(prefix="pc_e2e_hook_"))
    socks = Socks5Server()
    token = secrets.token_hex(32)
    config = {
        "version": 2,
        "default_proxy": {"type": "socks5", "host": "127.0.0.1", "port": socks.port},
        "proxy_groups": [{"id": 0, "name": "default", "host": "127.0.0.1", "port": socks.port,
                          "type": "socks5", "test_url": "http://1.1.1.1/"}],
        "next_group_id": 1,
        "auto_rules": [RULE, RULE32],
        "log_level": "debug",
        "dns": {"enabled": False},
        "interception": {"mode": "hook"},
    }
    cfg_path = work / "proxyclaw.json"
    cfg_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    script = work / "hook_probe.py"
    script.write_text(PROBE, encoding="utf-8")
    py_dir = pathlib.Path(sys.executable).resolve().parent
    app = py_dir / RULE["process_name"]
    shutil.copy2(sys.executable, app)
    child = work / "pc_hook_child.exe"      # matched only through the tree
    shutil.copy2(SYSTEM_CURL, child)
    stranger = work / "pc_hook_none.exe"    # matched by nothing
    shutil.copy2(SYSTEM_CURL, stranger)

    probe32_app = None
    probe32_child = None
    probe32_cross = None
    if args.probe32 and args.probe32.is_file():
        probe32_src = args.probe32.resolve()
        probe32_app = work / RULE32["process_name"]
        probe32_child = work / "pc_hook32_child.exe"
        probe32_cross = work / "pc_hook32_cross.exe"
        shutil.copy2(probe32_src, probe32_app)
        shutil.copy2(probe32_src, probe32_child)
        shutil.copy2(probe32_src, probe32_cross)

    env = dict(os.environ, PROXYCLAW_API_TOKEN=token)
    proc = subprocess.Popen([str(exe), "--minimized", "--dev-hooks", "--config", str(cfg_path)],
                            cwd=exe.parent, env=env)
    failures: list[str] = []
    checks = 0

    def check(name: str, ok: bool, detail: object) -> None:
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
        if not ok:
            failures.append(name)

    try:
        deadline = time.time() + 60
        while True:
            if proc.poll() is not None:
                raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
            try:
                stats = api_get("/stats", token)
                if stats.get("tree_ready", True) and stats.get("interception"):
                    break
            except Exception:
                pass
            if time.time() > deadline:
                raise RuntimeError("proxyclaw API / process tree not ready in 60s")
            time.sleep(0.5)
        time.sleep(1)

        stats0 = api_get("/stats", token)
        inter = stats0.get("interception", {})
        check("stats.interception", inter.get("mode") == "hook" and inter.get("active") is True, inter)
        hook0 = inter.get("hook", {})
        check("stats.hook.wow64_enabled", hook0.get("wow64_enabled") is True, hook0)
        ipv60 = stats0.get("ipv6", {})
        check("stats.ipv6.proxy_available matches hook relay_port_v6",
              ipv60.get("proxy_available") is (hook0.get("relay_port_v6", 0) != 0),
              {"ipv6": ipv60, "relay_port_v6": hook0.get("relay_port_v6")})

        socks.take()
        cmd_args = [str(app), str(script), str(child), token]
        if probe32_cross:
            cmd_args.append(str(probe32_cross))
        res = subprocess.run(cmd_args, capture_output=True, text=True, timeout=120)
        time.sleep(0.5)
        seen = set(socks.take())
        try:
            out = json.loads(res.stdout.strip().splitlines()[-1])
        except Exception:  # noqa: BLE001
            out = {}
            print(f"probe rc={res.returncode} stdout={res.stdout!r} stderr={res.stderr[-800:]!r}")
        check("injected (running process)", out.get("injected") is True, out.get("injected"))
        check("connect proxied, getpeername original",
              out.get("blocking") == [["1.1.1.1", 80], True] and ("1.1.1.1", 80) in seen,
              out.get("blocking"))
        api_row = out.get("api_tcp") or {}
        check("/api/tcp shows original destination and PROXIED",
              api_row.get("remote_ip") == "1.1.1.1" and api_row.get("remote_port") == 80
              and api_row.get("proxy_status") == "PROXIED"
              and api_row.get("decision_source") == "recorded"
              and api_row.get("rule_id") == RULE["id"],
              api_row)
        api_proc = out.get("api_proc") or {}
        check("/api/processes/{pid} reports hook_status=injected",
              api_proc.get("hijacked") is True and api_proc.get("hook_status") == "injected",
              api_proc)
        check("ConnectEx proxied, peername original",
              out.get("connectex") == [["1.0.0.1", 80], True] and ("1.0.0.1", 80) in seen,
              out.get("connectex"))
        check("excluded port direct",
              out.get("excluded") is True and ("1.1.1.1", 853) not in seen, out.get("excluded"))
        bound_out = out.get("bound_nic")
        check("non-loopback bound socket connects direct",
              isinstance(bound_out, list) and len(bound_out) == 2 and bound_out[1] is True
              and not str(bound_out[0]).startswith("127.")
              and ("1.0.0.1", 443) not in seen,
              bound_out)
        child_out = out.get("child")
        check("child injected before its first connect",
              isinstance(child_out, list) and child_out[0] == 0 and ("1.1.1.1", 443) in seen,
              child_out)
        if probe32_cross:
            check("x64 -> 32-bit (WOW64) child injected before its first connect",
                  out.get("child32") == 0 and ("1.0.0.1", 80) in seen,
                  {"child32": out.get("child32"), "seen": sorted(seen)})

        if probe32_app and probe32_child:
            socks.take()
            res32 = subprocess.run([str(probe32_app), "--child", str(probe32_child)],
                                   capture_output=True, text=True, timeout=60)
            time.sleep(0.5)
            seen32 = set(socks.take())
            try:
                out32 = json.loads(res32.stdout.strip().splitlines()[-1])
            except Exception:  # noqa: BLE001
                out32 = {}
                print(f"probe32 rc={res32.returncode} stdout={res32.stdout!r} stderr={res32.stderr[-400:]!r}")
            check("32-bit (WOW64) running process injected & proxied",
                  out32.get("arch") == 32 and out32.get("injected") is True
                  and out32.get("peer") == "1.1.1.1:80" and out32.get("http") is True
                  and ("1.1.1.1", 80) in seen32,
                  {"out32": out32, "seen32": sorted(seen32)})
            check("32-bit -> 32-bit child injected before its first connect",
                  out32.get("child_rc") == 0 and ("1.0.0.1", 80) in seen32,
                  {"out32": out32, "seen32": sorted(seen32)})

        socks.take()
        res = subprocess.run([str(stranger), "-s", "-o", os.devnull, "-w", "%{http_code}",
                              "--noproxy", "*", "--connect-timeout", "10", "-m", "20",
                              "http://1.1.1.1/"], capture_output=True, text=True)
        time.sleep(0.5)
        check("unmatched process direct",
              res.returncode == 0 and ("1.1.1.1", 80) not in set(socks.take()),
              f"rc={res.returncode} http={res.stdout}")

        hook = api_get("/stats", token).get("interception", {}).get("hook", {})
        skip_reasons = hook.get("skip_reasons") or {}
        check("stats: injected, children, and skip_reasons reported",
              hook.get("injected", 0) >= 1 and hook.get("children_injected", 0) >= 1
              and hook.get("proxied", 0) >= 3
              and set(skip_reasons.keys()) == {"wow64", "restricted", "signed_only", "open_failed", "failed"},
              hook)
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log = exe.parent / "proxyclaw.log"
        if failures and log.exists():
            print("---- proxyclaw.log (HOOK / RELAY lines, last 80) ----")
            lines = [l for l in log.read_text(encoding="utf-8", errors="replace").splitlines()
                     if "HOOK" in l or "RELAY" in l or "[E]" in l]
            print("\n".join(lines[-80:]))
        app.unlink(missing_ok=True)
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    print(f"{checks - len(failures)}/{checks} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
