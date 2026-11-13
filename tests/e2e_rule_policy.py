"""Live rule-policy test: real WinDivert, real proxyclaw.exe, real TCP.

Starts proxyclaw.exe (administrator required) with a throwaway config whose
default group points at a SOCKS5 server run by this script. Each case runs a
private copy of System32 curl.exe under a unique name, so exactly one rule
matches it, and checks whether the connection went through the SOCKS5 server
(proxied) or not (direct). Both paths must still complete the request.

UDP cases send DNS queries from one socket to two resolvers (1.1.1.1 and
8.8.8.8) through the SOCKS5 server's UDP ASSOCIATE relay and check each reply
comes back from the resolver it was sent to (per-packet addressing).

Destinations are public anycast addresses (1.1.1.1 / 1.0.0.1 / 8.8.8.8), so
the runner needs outbound internet. No other proxy or service is needed.

Usage (elevated):
    python tests/e2e_rule_policy.py --exe build/Release/proxyclaw.exe
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import secrets
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

API = "http://127.0.0.1:18080/api"
SYSTEM_CURL = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"


class Socks5Server:
    """Minimal SOCKS5 CONNECT relay that records every requested destination."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.seen: list[tuple[str, int]] = []
        self.seen_udp: list[tuple[str, int]] = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def take(self) -> list[tuple[str, int]]:
        with self.lock:
            out, self.seen = self.seen, []
        return out

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _exact(sock: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            part = sock.recv(n - len(data))
            if not part:
                raise EOFError
            data += part
        return data

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(15)
        try:
            ver, nmethods = self._exact(conn, 2)
            self._exact(conn, nmethods)
            conn.sendall(b"\x05\x00")
            ver, cmd, _, atyp = self._exact(conn, 4)
            if atyp == 1:
                host = socket.inet_ntoa(self._exact(conn, 4))
            elif atyp == 3:
                host = self._exact(conn, self._exact(conn, 1)[0]).decode()
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, self._exact(conn, 16))
            else:
                return
            port = struct.unpack("!H", self._exact(conn, 2))[0]
            with self.lock:
                self.seen.append((host, port))
            if cmd == 3:
                self._udp_associate(conn)
                return
            if cmd != 1:
                conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            upstream = socket.create_connection((host, port), timeout=10)
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            self._pump(conn, upstream)
        except Exception:
            pass
        finally:
            conn.close()

    def _udp_associate(self, conn: socket.socket) -> None:
        """RFC 1928 UDP ASSOCIATE: relay datagrams while the TCP control lives.

        `relay` faces proxyclaw on loopback; `out` faces the internet (a
        loopback-bound socket cannot send to a public address)."""
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.bind(("0.0.0.0", 0))
        bnd_port = relay.getsockname()[1]
        conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", bnd_port))
        client = None
        try:
            while True:
                readable, _, _ = select.select([conn, relay, out], [], [], 0.5)
                for sock in readable:
                    try:
                        if sock is conn:
                            if conn.recv(1) == b"":
                                return  # control closed
                        elif sock is relay:
                            data, src = relay.recvfrom(65535)
                            if len(data) < 10 or data[:3] != b"\x00\x00\x00" or data[3] != 1:
                                continue
                            client = src
                            host = socket.inet_ntoa(data[4:8])
                            port = struct.unpack("!H", data[8:10])[0]
                            with self.lock:
                                self.seen_udp.append((host, port))
                            out.sendto(data[10:], (host, port))
                        else:
                            data, src = out.recvfrom(65535)
                            if client is not None:
                                header = b"\x00\x00\x00\x01" + socket.inet_aton(src[0]) + struct.pack("!H", src[1])
                                relay.sendto(header + data, client)
                    except ConnectionResetError:
                        continue  # ICMP unreachable reported on a UDP socket
        except OSError as e:
            print(f"socks5 udp associate ended: {e!r}", file=sys.stderr)
        finally:
            relay.close()
            out.close()

    def take_udp(self) -> list[tuple[str, int]]:
        with self.lock:
            out, self.seen_udp = self.seen_udp, []
        return out

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket) -> None:
        def one_way(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=one_way, args=(b, a), daemon=True)
        t.start()
        one_way(a, b)
        t.join(20)
        b.close()


def rule(name: str, protocol: str = "tcp", **dst) -> dict:
    return {
        "id": f"e2e_{name}",
        "name": f"e2e {name}",
        "enabled": True,
        "process_name": f"pc_e2e_{name}.exe",
        "cmdline_pattern": "",
        "image_path_pattern": "",
        "hack_tree": True,
        "protocol": protocol,
        "proxy_group_id": 0,
        "dst_filter": {
            "include_cidrs": dst.get("include_cidrs", []),
            "exclude_cidrs": dst.get("exclude_cidrs", []),
            "include_ports": dst.get("include_ports", []),
            "exclude_ports": dst.get("exclude_ports", []),
        },
    }


# (rule, [(url, expect_proxied)])
CASES = [
    (rule("control", "both"), [("http://1.1.1.1/", True)]),
    (rule("inc443", include_ports=["443"]), [("https://1.1.1.1/", True), ("http://1.1.1.1/", False)]),
    (rule("exc80", exclude_ports=["80"]), [("http://1.1.1.1/", False), ("https://1.1.1.1/", True)]),
    (rule("inccidr", include_cidrs=["1.0.0.0/24"]), [("http://1.0.0.1/", True), ("http://1.1.1.1/", False)]),
    (rule("exccidr", exclude_cidrs=["1.1.1.0/24"]), [("http://1.1.1.1/", False), ("http://1.0.0.1/", True)]),
    (rule("udponly", "udp"), [("http://1.1.1.1/", False)]),
]


# UDP cases: a copy of python.exe (named so one rule matches it) runs
# UDP_PROBE, which sends DNS queries to two resolvers from ONE socket and
# checks every reply comes back from the resolver it asked, with its id.
# (rule, resolvers, expected resolvers seen at the SOCKS5 UDP relay)
UDP_CASES = [
    (rule("udp2dst", "udp"), ["1.1.1.1", "8.8.8.8"], {"1.1.1.1", "8.8.8.8"}),
    (rule("udpexc", "udp", exclude_cidrs=["8.8.8.0/24"]), ["1.1.1.1", "8.8.8.8"], {"1.1.1.1"}),
    (rule("udpport", "udp", include_ports=["5353"]), ["1.1.1.1"], set()),
]

# Decision record (v0.14 #2): a copy of python.exe named for this rule holds
# one proxied (1.1.1.1:80) and one rule-excluded (1.1.1.1:443) connection
# open while /api/tcp is read; then the rule is deleted and the proxied row
# must keep its recorded verdict instead of being recomputed as direct.
DECISION_RULE = rule("decide", exclude_ports=["443"])
# Rule conflict (v0.14 #4): a later rule for the same process, another group.
# It is shadowed: the first rule in config order decides group and filters,
# and /api rows name both in `conflict`. Deleted first, so the recorded
# decisions then predate the current config_version (stale).
DECISION_SHADOW = dict(rule("decide2"), process_name=DECISION_RULE["process_name"], proxy_group_id=1)

DECISION_PROBE = r"""
import socket, sys
try:
    a = socket.create_connection(("1.1.1.1", 80), timeout=10)
    b = socket.create_connection(("1.1.1.1", 443), timeout=10)
except OSError as e:
    print("ERR", e, flush=True)
    sys.exit(3)
print("OK", a.getsockname()[1], b.getsockname()[1], flush=True)
sys.stdin.readline()
"""

UDP_PROBE = r"""
import random, socket, struct, sys, time
servers = sys.argv[1:]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
# No bind, no wait: the first sendto() binds implicitly and goes out at once,
# before the SOCKET layer has handled the BIND. First-packet parking must hold
# it for the decision; a direct leak shows up as a resolver missing at the
# relay (the direct reply still arrives, so the probe itself would pass).
def query(txid, name):
    q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\0" + struct.pack("!HH", 1, 1)
want = {}
for attempt in range(3):
    for i, srv in enumerate(servers):
        if srv in want.values() and attempt == 0:
            continue
        txid = random.randint(1, 65535)
        want[txid] = srv
        s.sendto(query(txid, "example.com"), (srv, 53))   # back to back, same socket
    got = {}
    deadline = time.time() + 3
    while time.time() < deadline and len(got) < len(servers):
        try:
            data, src = s.recvfrom(4096)
        except socket.timeout:
            continue
        txid = struct.unpack("!H", data[:2])[0]
        if txid not in want:
            continue
        if src[0] != want[txid] or src[1] != 53:
            print(f"WRONG-SOURCE txid={txid} asked={want[txid]} got={src[0]}:{src[1]}")
            sys.exit(3)
        got[src[0]] = txid
    if len(got) == len(servers):
        print("OK " + " ".join(sorted(got)))
        sys.exit(0)
print("TIMEOUT got=" + ",".join(sorted(got)))
sys.exit(4)
"""


# IPv6 block (v0.14 #5). The runner has no IPv6 route, so a documentation
# address (2001:db8:5::/64) is added on the default-route adapter with a
# permanent neighbor for V6_TARGET: a SYN to it really leaves on the wire and
# is never answered. Blocked -> the SYN gate answers with an RST at once
# (connect() is refused); not blocked -> the connect times out.
# (rule, expected TCP result, expect UDP datagrams dropped)
V6_LOCAL = "2001:db8:5::10"
V6_TARGET = "2001:db8:5::1"
V6_CASES = [
    (rule("v6block", "both"), "refused", True),
    (rule("v6exc", "both", exclude_ports=["80", "5353"]), "timeout", False),
]

V6_PROBE = r"""
import socket, sys, time
target = sys.argv[1]
t = time.time()
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(4)
try:
    s.connect((target, 80, 0, 0))
    r = "connected"
except ConnectionRefusedError:
    r = "refused"
except (socket.timeout, TimeoutError):
    r = "timeout"
except OSError as e:
    r = f"oserror:{e.errno}"
dt = time.time() - t
u = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
for _ in range(3):
    u.sendto(b"proxyclaw-e2e", (target, 5353, 0, 0))
    time.sleep(0.05)
print(r, f"{dt:.2f}")
"""


def _ps(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                          capture_output=True, text=True, timeout=60)


def v6_setup() -> str | None:
    """Add V6_LOCAL + a permanent neighbor for V6_TARGET. Returns an error or None."""
    r = _ps(
        "$ErrorActionPreference='Stop';"
        "$i=(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex;"
        f"New-NetIPAddress -InterfaceIndex $i -IPAddress {V6_LOCAL} -PrefixLength 64 -AddressFamily IPv6 | Out-Null;"
        f"New-NetNeighbor -InterfaceIndex $i -IPAddress {V6_TARGET} -LinkLayerAddress 02-00-5e-00-53-01 -State Permanent | Out-Null;"
        "for($n=0;$n -lt 40;$n++){"
        f"$a=Get-NetIPAddress -IPAddress {V6_LOCAL} -ErrorAction SilentlyContinue;"
        "if($a -and $a.AddressState -eq 'Preferred'){break}; Start-Sleep -Milliseconds 250};"
        f"(Get-NetIPAddress -IPAddress {V6_LOCAL}).AddressState")
    if r.returncode != 0 or "Preferred" not in r.stdout:
        return f"rc={r.returncode} out={r.stdout.strip()} err={r.stderr.strip()[-300:]}"
    return None


def v6_teardown() -> None:
    _ps(f"Get-NetNeighbor -IPAddress {V6_TARGET} -ErrorAction SilentlyContinue | Remove-NetNeighbor -Confirm:$false;"
        f"Get-NetIPAddress -IPAddress {V6_LOCAL} -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false")


def run_v6_cases(probes: dict, script: pathlib.Path, token: str, failures: list[str]) -> None:
    err = v6_setup()
    if err:
        for r, _, _ in V6_CASES:
            _check(failures, f"{r['id']} ipv6 setup", False, err)
        return
    try:
        for r, want_tcp, want_udp_drop in V6_CASES:
            before = api_get("/stats", token).get("ipv6_blocked", {})
            res = subprocess.run([str(probes[r["id"]]), str(script), V6_TARGET],
                                 capture_output=True, text=True, timeout=30)
            time.sleep(0.3)
            after = api_get("/stats", token).get("ipv6_blocked", {})
            out = res.stdout.split()
            got_tcp = out[0] if out else "none"
            secs = float(out[1]) if len(out) > 1 else 99.0
            udp_dropped = after.get("udp", 0) - before.get("udp", 0)
            tcp_blocked = after.get("tcp", 0) - before.get("tcp", 0)
            ok = (got_tcp == want_tcp
                  and (secs < 1.5 if want_tcp == "refused" else True)
                  and (udp_dropped >= 3) == want_udp_drop
                  and (tcp_blocked >= 1) == (want_tcp == "refused"))
            _check(failures, f"{r['id']} ipv6", ok,
                   {"tcp": got_tcp, "secs": secs, "tcp_blocked": tcp_blocked,
                    "udp_dropped": udp_dropped, "want": [want_tcp, want_udp_drop],
                    "stderr": res.stderr.strip()[-200:]})
    finally:
        v6_teardown()


def api_get(path: str, token: str) -> object:
    req = urllib.request.Request(API + path, headers={"X-ProxyClaw-Token": token})
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read())


def api_delete(path: str, token: str, timeout: float = 15) -> object:
    req = urllib.request.Request(API + path, method="DELETE",
                                 headers={"X-ProxyClaw-Token": token})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _wait_rows(pid: int, ports: list[int], token: str, timeout: float = 5.0) -> dict[int, dict]:
    """/api/tcp rows of `pid` keyed by local port, once all `ports` are listed."""
    deadline = time.time() + timeout
    rows: dict[int, dict] = {}
    while time.time() < deadline:
        rows = {r["local_port"]: r for r in api_get(f"/tcp?pid={pid}", token)}
        if all(p in rows for p in ports):
            break
        time.sleep(0.25)
    return rows


def _check(failures: list[str], name: str, ok: bool, detail: object) -> None:
    print(f"{'PASS' if ok else 'FAIL'} {name:<34} {json.dumps(detail, ensure_ascii=False)}")
    if not ok:
        failures.append(name)


def run_decision_case(probe: pathlib.Path, script: pathlib.Path, socks: "Socks5Server",
                      token: str, failures: list[str]) -> None:
    rid = DECISION_RULE["id"]
    socks.take()
    p = subprocess.Popen([str(probe), str(script)], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = p.stdout.readline().split()
        if len(line) != 3 or line[0] != "OK":
            _check(failures, "decision probe connects", False,
                   {"stdout": line, "stderr": p.stderr.read()[-300:] if p.poll() is not None else ""})
            return
        port_px, port_dx = int(line[1]), int(line[2])
        time.sleep(0.3)
        _check(failures, "decision probe :80 via proxy", ("1.1.1.1", 80) in socks.take(), {})

        rows = _wait_rows(p.pid, [port_px, port_dx], token)
        px, dx = rows.get(port_px, {}), rows.get(port_dx, {})
        d_px, d_dx = px.get("decision") or {}, dx.get("decision") or {}
        _check(failures, "decision proxied row recorded",
               px.get("decision_source") == "recorded" and d_px.get("verdict") == "proxied"
               and d_px.get("reason") == "none" and d_px.get("rule_id") == rid
               and d_px.get("source") == "rule" and d_px.get("group") == 0
               and d_px.get("pid") == p.pid and px.get("proxy_status") == "PROXIED",
               {k: px.get(k) for k in ("proxy_status", "route_reason", "decision_source", "decision")})
        _check(failures, "decision excluded row recorded",
               dx.get("decision_source") == "recorded" and d_dx.get("verdict") == "direct"
               and d_dx.get("reason") == "rule_exclude_port" and d_dx.get("rule_id") == rid
               and dx.get("proxy_status") == "IGNORED" and dx.get("route_reason") == "rule_exclude_port",
               {k: dx.get(k) for k in ("proxy_status", "route_reason", "decision_source", "decision")})

        # Both rules match the probe; the first decides, the second is shadowed.
        want_conflict = {"manual": False, "winner": rid, "shadowed_rule_ids": [DECISION_SHADOW["id"]]}
        _check(failures, "conflict names winner + shadowed",
               px.get("conflict") == want_conflict and dx.get("conflict") == want_conflict
               and d_px.get("group") == 0,
               {"proxied": px.get("conflict"), "excluded": dx.get("conflict"), "group": d_px.get("group")})

        # Delete the shadowed rule: the conflict goes, the recorded decision
        # stays and is now older than the engine's config_version.
        api_delete(f"/auto-rules/{DECISION_SHADOW['id']}", token)
        listing: dict = {}
        deadline = time.time() + 5
        while time.time() < deadline:
            listing = api_get(f"/connections?pid={p.pid}", token)
            row = next((r for r in listing.get("tcp", []) if r.get("local_port") == port_px), {})
            if row and "conflict" not in row:
                break
            time.sleep(0.25)
        row = next((r for r in listing.get("tcp", []) if r.get("local_port") == port_px), {})
        d_row = row.get("decision") or {}
        _check(failures, "conflict gone, decision stale",
               bool(row) and "conflict" not in row and d_row.get("rule_id") == rid
               and d_row.get("config_version") == d_px.get("config_version")
               and isinstance(listing.get("config_version"), int)
               and listing["config_version"] > d_row.get("config_version", 1 << 62)
               and row.get("hijacked") is True,
               {"row": {k: row.get(k) for k in ("hijacked", "conflict", "decision")},
                "config_version": listing.get("config_version")})

        # Change the rules under the live connections: delete the rule.
        version_before = api_get("/stats", token).get("config_version")
        api_delete(f"/auto-rules/{rid}", token)
        deadline = time.time() + 5
        while time.time() < deadline:
            rows = _wait_rows(p.pid, [port_px, port_dx], token, timeout=1)
            if rows.get(port_px, {}).get("hijacked") is False:
                break
            time.sleep(0.25)
        px = rows.get(port_px, {})
        d_after = px.get("decision") or {}
        version_after = api_get("/stats", token).get("config_version")
        _check(failures, "decision survives rule delete",
               px.get("hijacked") is False and px.get("decision_source") == "recorded"
               and d_after.get("verdict") == "proxied" and px.get("proxy_status") == "PROXIED"
               and d_after.get("rule_id") == rid
               and d_after.get("config_version") == d_px.get("config_version")
               and isinstance(version_after, int) and isinstance(version_before, int)
               and version_after > version_before >= d_after.get("config_version", 1 << 62),
               {"row": {k: px.get(k) for k in ("hijacked", "proxy_status", "decision_source", "decision")},
                "config_version": [version_before, version_after]})
    finally:
        try:
            p.stdin.write("\n")
            p.stdin.flush()
        except OSError:
            pass
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


def api_post(path: str, token: str, timeout: float = 15) -> object:
    req = urllib.request.Request(API + path, data=b"", method="POST",
                                 headers={"X-ProxyClaw-Token": token})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


# (group id, expect ok, expected failed_stage, expected detail prefix)
SPEED_CASES = [
    (0, True, None, "HTTP "),
    (1, True, None, "TLS"),
    (2, False, "connect", None),
]


DECISION_CHECKS = 6   # run_decision_case: via proxy, proxied row, excluded row, conflict, stale, survives delete


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True, type=pathlib.Path)
    ap.add_argument("--keep", action="store_true", help="keep the temp dir")
    args = ap.parse_args()

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("SKIP: needs an elevated shell (WinDivert)")
        return 2

    exe = args.exe.resolve()
    work = pathlib.Path(tempfile.mkdtemp(prefix="pc_e2e_rules_"))
    socks = Socks5Server()
    token = secrets.token_hex(32)

    config = {
        "version": 2,
        "default_proxy": {"type": "socks5", "host": "127.0.0.1", "port": socks.port},
        "proxy_groups": [
            {"id": 0, "name": "default", "host": "127.0.0.1", "port": socks.port,
             "type": "socks5", "test_url": "http://1.1.1.1/"},
            # speed-test cases: domain proxy host + https target, and a dead proxy
            {"id": 1, "name": "bydomain", "host": "localhost", "port": socks.port,
             "type": "socks5", "test_url": "https://1.1.1.1/"},
            {"id": 2, "name": "dead", "host": "127.0.0.1", "port": 1,
             "type": "socks5", "test_url": "http://1.1.1.1/"},
        ],
        "next_group_id": 3,
        "auto_rules": [c[0] for c in CASES] + [c[0] for c in UDP_CASES] + [c[0] for c in V6_CASES]
                      + [DECISION_RULE, DECISION_SHADOW],
        "log_level": "debug",
        "dns": {"enabled": False},
    }
    cfg_path = work / "proxyclaw.json"
    cfg_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    probes = {}
    for r, _ in CASES:
        dst = work / r["process_name"]
        shutil.copy2(SYSTEM_CURL, dst)
        probes[r["id"]] = dst

    # python.exe finds its DLL next to itself, so the renamed copy lives in
    # the interpreter's own directory.
    py_dir = pathlib.Path(sys.executable).resolve().parent
    udp_script = work / "udp_probe.py"
    udp_script.write_text(UDP_PROBE, encoding="utf-8")
    udp_probes = {}
    for r, _, _ in UDP_CASES:
        dst = py_dir / r["process_name"]
        shutil.copy2(sys.executable, dst)
        udp_probes[r["id"]] = dst
    v6_script = work / "v6_probe.py"
    v6_script.write_text(V6_PROBE, encoding="utf-8")
    for r, _, _ in V6_CASES:
        dst = py_dir / r["process_name"]
        shutil.copy2(sys.executable, dst)
        udp_probes[r["id"]] = dst
    decision_script = work / "decision_probe.py"
    decision_script.write_text(DECISION_PROBE, encoding="utf-8")
    decision_probe = py_dir / DECISION_RULE["process_name"]
    shutil.copy2(sys.executable, decision_probe)
    udp_probes[DECISION_RULE["id"]] = decision_probe   # removed with the UDP probes

    env = dict(os.environ, PROXYCLAW_API_TOKEN=token)
    proc = subprocess.Popen([str(exe), "--minimized", "--dev-hooks", "--config", str(cfg_path)],
                            cwd=exe.parent, env=env)
    failures: list[str] = []
    try:
        deadline = time.time() + 60
        while True:
            if proc.poll() is not None:
                raise RuntimeError(f"proxyclaw.exe exited early with {proc.returncode}")
            try:
                rules = api_get("/auto-rules", token)
                # tree_ready: initial process rundown verified (builds
                # without the flag are not waited on).
                if (len(rules) >= len(CASES) + len(UDP_CASES) + len(V6_CASES) + 2
                        and api_get("/stats", token).get("tree_ready", True)):
                    break
            except Exception:
                pass
            if time.time() > deadline:
                raise RuntimeError("proxyclaw API / process tree not ready in 60s")
            time.sleep(0.5)
        time.sleep(2)  # let the WinDivert layers settle

        for r, checks in CASES:
            for url, expect_proxied in checks:
                socks.take()
                cmd = [str(probes[r["id"]]), "-s", "-k", "-o", os.devnull,
                       "-w", "%{http_code}", "--noproxy", "*",
                       "--connect-timeout", "10", "-m", "20", url]
                res = subprocess.run(cmd, capture_output=True, text=True)
                time.sleep(0.3)
                seen = socks.take()
                host = url.split("/")[2]
                port = 443 if url.startswith("https") else 80
                proxied = (host, port) in seen
                ok = res.returncode == 0 and proxied == expect_proxied
                verdict = "PASS" if ok else "FAIL"
                print(f"{verdict} {r['id']:<12} {url:<20} expect={'proxy' if expect_proxied else 'direct'}"
                      f" got={'proxy' if proxied else 'direct'} curl_rc={res.returncode} http={res.stdout}")
                if not ok:
                    failures.append(f"{r['id']} {url}")
        for gid, want_ok, want_stage, want_detail in SPEED_CASES:
            try:
                res = api_post(f"/proxy-groups/{gid}/test", token)
            except Exception as e:  # noqa: BLE001
                res = {"error": repr(e)}
            ok = ("latency_ms" in res) == want_ok
            if want_ok:
                ok = ok and len(res.get("stages", [])) == 5 and str(res.get("detail", "")).startswith(want_detail)
            else:
                ok = ok and res.get("failed_stage") == want_stage
            verdict = "PASS" if ok else "FAIL"
            print(f"{verdict} speedtest g{gid} {json.dumps(res, ensure_ascii=False)}")
            if not ok:
                failures.append(f"speedtest g{gid}")

        for r, servers, expect_relayed in UDP_CASES:
            socks.take_udp()
            res = subprocess.run([str(udp_probes[r["id"]]), str(udp_script), *servers],
                                 capture_output=True, text=True, timeout=30)
            time.sleep(0.3)
            relayed = {host for host, port in socks.take_udp() if port == 53}
            ok = res.returncode == 0 and relayed == expect_relayed
            verdict = "PASS" if ok else "FAIL"
            print(f"{verdict} {r['id']:<12} udp {','.join(servers):<17} expect_relayed={sorted(expect_relayed)}"
                  f" got_relayed={sorted(relayed)} probe_rc={res.returncode} {res.stdout.strip()} {res.stderr.strip()[-200:]}")
            if not ok:
                failures.append(f"{r['id']} udp")

        run_v6_cases(udp_probes, v6_script, token, failures)

        # Last: it deletes its rules.
        decision_failures: list[str] = []
        run_decision_case(decision_probe, decision_script, socks, token, decision_failures)
        failures.extend(decision_failures)
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log = exe.parent / "proxyclaw.log"
        if failures and log.exists():
            print("---- proxyclaw.log (WD-SOCKET / RULE lines, last 80) ----")
            lines = [l for l in log.read_text(encoding="utf-8", errors="replace").splitlines()
                     if "WD-SOCKET" in l or "[RULE]" in l or "[E]" in l or "UDP" in l
                     or "V6" in l or "IPv6" in l]
            print("\n".join(lines[-80:]))
        for path in udp_probes.values():
            path.unlink(missing_ok=True)
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    total = (sum(len(c[1]) for c in CASES) + len(UDP_CASES) + len(V6_CASES) + len(SPEED_CASES)
             + DECISION_CHECKS)
    print(f"{total - len(failures)}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
