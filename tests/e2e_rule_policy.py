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


def api_get(path: str, token: str) -> object:
    req = urllib.request.Request(API + path, headers={"X-ProxyClaw-Token": token})
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read())


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
        "auto_rules": [c[0] for c in CASES] + [c[0] for c in UDP_CASES],
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

    env = dict(os.environ, PROXYCLAW_API_TOKEN=token)
    proc = subprocess.Popen([str(exe), "--minimized", "--config", str(cfg_path)],
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
                if (len(rules) >= len(CASES) + len(UDP_CASES)
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
                     if "WD-SOCKET" in l or "[RULE]" in l or "[E]" in l or "UDP" in l]
            print("\n".join(lines[-80:]))
        for path in udp_probes.values():
            path.unlink(missing_ok=True)
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    total = sum(len(c[1]) for c in CASES) + len(UDP_CASES) + len(SPEED_CASES)
    print(f"{total - len(failures)}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
