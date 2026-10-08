"""Windows DNS forwarder integration tests, using only loopback sockets.

python tests/run_dns_network_tests.py --cxx path/to/zig.exe --asio-include path/to/asio/include
The real production forwarder and SOCKS5 UDP session are compiled. A local fake
SOCKS5/DNS server controls timeouts and packet contents; system DNS is untouched.
"""
import argparse
import contextlib
import os
from pathlib import Path
import queue
import shutil
import socket
import struct
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = socket.inet_aton('203.0.113.53') + struct.pack('!H', 53)

def query(name='example.test', tx=0x1234, edns=None):
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0\0\1\0\1'
    packet = struct.pack('!6H', tx, 0x0100, 1, 0, 0, int(edns is not None)) + question
    if edns is not None: packet += b'\0' + struct.pack('!HHIH', 41, edns, 0, 0)
    return packet

def question_end(packet):
    pos = 12
    while packet[pos]: pos += packet[pos] + 1
    return pos + 5

def domain(packet):
    labels, pos = [], 12
    while packet[pos]:
        n = packet[pos]; pos += 1
        labels.append(packet[pos:pos+n].decode('ascii')); pos += n
    return '.'.join(labels)

def answer(packet, large=False):
    result = bytearray(packet[:question_end(packet)])
    result[2:4] = b'\x81\x80'
    result[6:12] = struct.pack('!3H', 1, 0, 0)
    payload = (bytes([250]) + b'x' * 250) * 6 if large else b'\x01\x02\x03\x04'
    result += b'\xc0\x0c' + struct.pack('!HHIH', 16 if large else 1, 1, 60, len(payload)) + payload
    return bytes(result)

def exact(sock, n):
    result = b''
    while len(result) < n:
        chunk = sock.recv(n - len(result))
        if not chunk: raise EOFError()
        result += chunk
    return result

class Proxy:
    def __init__(self, udp='drop', tcp='ok', bound='ipv4'):
        self.udp_mode, self.tcp_mode, self.bound = udp, tcp, bound
        self.closed = threading.Event()
        self.errors, self.connections, self.threads = [], [], []
        self.udp_queries, self.tcp_queries = [], []
        self.tcp_accepted = 0
        self.accepted = 0
        self.reorder = []
        self.listener = socket.socket(); self.listener.bind(('127.0.0.1', 0)); self.listener.listen(128)
        self.listener.settimeout(.1); self.port = self.listener.getsockname()[1]
        self.relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.relay.bind(('127.0.0.1', 0)); self.relay.settimeout(.1)
        self._spawn(self._accept); self._spawn(self._udp)
    def _spawn(self, fn, *args):
        thread = threading.Thread(target=fn, args=args, daemon=True)
        self.threads.append(thread); thread.start()
    def _accept(self):
        while not self.closed.is_set():
            try: conn, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            index = self.accepted; self.accepted += 1
            if index: self.tcp_accepted += 1
            self.connections.append(conn); conn.settimeout(3)
            self._spawn(self._connection, conn, index)
    def _connection(self, conn, index):
        try:
            assert exact(conn, 3) == b'\x05\x01\x00'
            if index and self.tcp_mode == 'stall_auth': self.closed.wait(5); return
            if index and self.tcp_mode == 'auth_reject': conn.sendall(b'\x05\xff'); return
            conn.sendall(b'\x05\x00')
            head = exact(conn, 4); assert head[0] == 5 and head[2:] == b'\x00\x01'
            destination = exact(conn, 6)
            if head[1] == 3:
                host, port = self.relay.getsockname()
                conn.sendall(b'\x05\x00\x00\x01' + socket.inet_aton(host) + struct.pack('!H', port))
                # Keep UDP ASSOCIATE's control connection alive until stop().
                conn.settimeout(.1)
                while not self.closed.is_set():
                    try:
                        if not conn.recv(1): break
                    except socket.timeout: continue
                return
            assert head[1] == 1 and destination == UPSTREAM
            if self.tcp_mode == 'connect_reject': conn.sendall(b'\x05\x05\x00\x01'); return
            if self.bound == 'ipv6': reply = b'\x05\x00\x00\x04' + b'\0' * 16 + b'\0\x35'
            elif self.bound == 'domain': reply = b'\x05\x00\x00\x03\x09localhost\0\x35'
            else: reply = b'\x05\x00\x00\x01\x7f\0\0\1\0\x35'
            conn.sendall(reply)
            size = struct.unpack('!H', exact(conn, 2))[0]
            packet = exact(conn, size); self.tcp_queries.append(packet)
            if self.tcp_mode == 'stall_dns': self.closed.wait(5); return
            if self.tcp_mode == 'late': time.sleep(.25)
            result = answer(packet, self.tcp_mode == 'large')
            if self.tcp_mode == 'wrong_id': result = bytes([result[0] ^ 1]) + result[1:]
            if self.tcp_mode == 'wrong_question': result = answer(query('wrong.test', struct.unpack('!H', packet[:2])[0]))
            if self.tcp_mode == 'short': conn.sendall(b'\0\x05short'); return
            if self.tcp_mode == 'truncated': result = result[:2] + bytes([result[2] | 2]) + result[3:]
            framed = struct.pack('!H', len(result)) + result
            if self.tcp_mode == 'split':
                for byte in framed: conn.sendall(bytes([byte])); time.sleep(.001)
            else: conn.sendall(framed)
        except (EOFError, ConnectionError, OSError): pass # Expected during cancellation.
        except Exception as e: self.errors.append(repr(e))
        finally: conn.close()
    def _udp_reply(self, raw, peer):
        try: self.relay.sendto(raw, peer)
        except OSError: pass
    def _udp(self):
        while not self.closed.is_set():
            try: raw, peer = self.relay.recvfrom(65535)
            except socket.timeout: continue
            except OSError: break
            try:
                assert raw[:4] == b'\0\0\0\1' and raw[4:10] == UPSTREAM
                packet = raw[10:]; self.udp_queries.append(packet)
                response = b'\0\0\0\1' + UPSTREAM + answer(packet)
                if self.udp_mode == 'drop': continue
                if self.udp_mode == 'nxdomain': response = response[:13] + b'\x83' + response[14:]
                if self.udp_mode == 'truncated': response = response[:12] + bytes([response[12] | 2]) + response[13:]
                if self.udp_mode == 'wrong_source': response = response[:4] + socket.inet_aton('203.0.113.54') + response[8:]
                if self.udp_mode == 'wrong_question':
                    tx = struct.unpack('!H', packet[:2])[0]
                    response = response[:10] + answer(query('wrong.test', tx))
                if self.udp_mode == 'foreign':
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other: other.sendto(response, peer)
                    continue
                if self.udp_mode == 'late':
                    self._spawn(lambda r=response, p=peer: (time.sleep(.16), self._udp_reply(r, p))); continue
                if self.udp_mode == 'reverse':
                    self.reorder.append((response, peer))
                    if len(self.reorder) == 2:
                        for r, p in reversed(self.reorder): self._udp_reply(r, p)
                    continue
                self._udp_reply(response, peer)
            except Exception as e: self.errors.append(repr(e))
    def close(self):
        self.closed.set(); self.listener.close(); self.relay.close()
        for conn in self.connections:
            with contextlib.suppress(OSError): conn.shutdown(socket.SHUT_RDWR)
            conn.close()
        for thread in self.threads: thread.join(timeout=.4)

class Forwarder:
    def __init__(self, exe, proxy, udp_ms=80, tcp_ms=400):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(('127.0.0.1', 0)); self.port = reserve.getsockname()[1]
        self.proxy = proxy
        self.process = subprocess.Popen([str(exe), str(self.port), str(proxy.port), str(udp_ms), str(tcp_ms)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ROOT)
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(self.process.stdout.readline().strip()), daemon=True).start()
        if ready.get(timeout=5) != 'READY':
            self.process.kill(); raise AssertionError('forwarder start failed')
    def client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0)); sock.settimeout(2)
        return sock
    def exchange(self, packet=None):
        packet = packet or query()
        with self.client() as sock:
            start = time.monotonic(); sock.sendto(packet, ('127.0.0.1', self.port))
            response, _ = sock.recvfrom(65535)
            return response, time.monotonic() - start
    def stop(self):
        if self.process.poll() is None:
            out, err = self.process.communicate('stop\n', timeout=3)
            assert self.process.returncode == 0 and 'STOPPED' in out, (out, err)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(('127.0.0.1', self.port)) # Port must be released synchronously.

@contextlib.contextmanager
def running(exe, udp_ms=80, tcp_ms=400, **options):
    proxy = Proxy(**options)
    fwd = None
    try:
        fwd = Forwarder(exe, proxy, udp_ms, tcp_ms); yield fwd, proxy
        assert not proxy.errors, proxy.errors
    finally:
        if fwd:
            try: fwd.stop()
            except Exception:
                fwd.process.kill(); fwd.process.wait(); raise
        proxy.close()

def check_answer(response, packet):
    assert response[:2] == packet[:2] and response[3] & 15 == 0
    assert domain(response) == domain(packet) and response[2] & 0x80 and not response[2] & 2

def tests(exe):
    with running(exe, udp='ok') as (fwd, proxy):
        response, _ = fwd.exchange(); check_answer(response, query())
        time.sleep(.12); assert proxy.tcp_accepted == 0
    print('PASS UDP success cancels fallback timer')
    for bound, mode in [('ipv4', 'split'), ('ipv6', 'ok'), ('domain', 'ok')]:
        with running(exe, bound=bound, tcp=mode) as (fwd, proxy):
            response, elapsed = fwd.exchange(); check_answer(response, query())
            assert elapsed >= .06 and len(proxy.tcp_queries) == 1
        print(f'PASS UDP timeout -> TCP ({bound} SOCKS5 reply, {mode} DNS framing)')
    with running(exe, udp='truncated', udp_ms=1000) as (fwd, proxy):
        response, elapsed = fwd.exchange(); check_answer(response, query())
        assert elapsed < .3 and len(proxy.tcp_queries) == 1
    print('PASS truncated UDP response -> immediate TCP fallback')
    with running(exe, udp='nxdomain') as (fwd, proxy):
        response, _ = fwd.exchange()
        assert response[3] & 15 == 3
        time.sleep(.12); assert proxy.tcp_accepted == 0
    print('PASS UDP NXDOMAIN preserved without a TCP retry')
    for udp_mode in ['wrong_source', 'wrong_question', 'foreign']:
        with running(exe, udp=udp_mode) as (fwd, proxy):
            response, _ = fwd.exchange(); check_answer(response, query()); assert len(proxy.tcp_queries) == 1
        print(f'PASS invalid UDP response ignored ({udp_mode})')
    for mode in ['auth_reject', 'connect_reject', 'short', 'wrong_id', 'wrong_question', 'truncated', 'stall_auth', 'stall_dns']:
        with running(exe, tcp=mode) as (fwd, _):
            response, elapsed = fwd.exchange()
            assert response[:2] == query()[:2] and response[3] & 15 == 2 and elapsed < 1.5
            if mode.startswith('stall_'): assert elapsed >= .35
        print(f'PASS TCP failure returns bounded SERVFAIL ({mode})')
    with running(exe, udp='late', tcp='late') as (fwd, proxy):
        with fwd.client() as sock:
            sock.sendto(query(), ('127.0.0.1', fwd.port)); response, _ = sock.recvfrom(65535); check_answer(response, query())
            assert proxy.tcp_accepted == 1
            sock.settimeout(.4)
            try: sock.recvfrom(65535); raise AssertionError('duplicate response')
            except socket.timeout: pass
    print('PASS late UDP wins once and cancels in-flight TCP')
    with running(exe, udp='reverse') as (fwd, proxy):
        with fwd.client() as first, fwd.client() as second:
            a, b = query('first.test', 42), query('second.test', 42)
            first.sendto(a, ('127.0.0.1', fwd.port)); second.sendto(b, ('127.0.0.1', fwd.port))
            check_answer(first.recvfrom(65535)[0], a); check_answer(second.recvfrom(65535)[0], b)
            assert proxy.udp_queries[0][:2] != proxy.udp_queries[1][:2]
    print('PASS colliding client IDs routed correctly with reordered replies')
    for limit in [1232, 4096]:
        with running(exe, tcp='large') as (fwd, _):
            packet = query(edns=limit); response, _ = fwd.exchange(packet)
            if limit == 1232: assert response[2] & 2 and len(response) <= limit
            else: check_answer(response, packet); assert len(response) > 1232
    print('PASS TCP reply respects client EDNS UDP size')
    with running(exe, tcp='stall_auth') as (fwd, proxy):
        with fwd.client() as sock:
            sock.sendto(query(), ('127.0.0.1', fwd.port))
            until = time.monotonic() + 1
            while not proxy.tcp_accepted and time.monotonic() < until: time.sleep(.01)
            assert proxy.tcp_accepted
            start = time.monotonic(); fwd.stop(); assert time.monotonic() - start < 1
    print('PASS stop cancels active fallback and immediately releases listener')
    with running(exe, tcp='stall_dns') as (fwd, proxy):
        with fwd.client() as sock:
            for tx in range(70): sock.sendto(query(tx=tx), ('127.0.0.1', fwd.port))
            ids = set()
            for _ in range(70):
                response, _ = sock.recvfrom(65535)
                assert response[3] & 15 == 2; ids.add(struct.unpack('!H', response[:2])[0])
            assert len(ids) == 70 and proxy.tcp_accepted <= 64
    print('PASS bounded concurrent TCP fallback connections')

def compile_host(compiler, asio_include):
    build = ROOT / 'build' / 'dns-network-tests'; build.mkdir(parents=True, exist_ok=True)
    exe = build / 'dns_forwarder_harness.exe'
    cxx = shutil.which(compiler) or str(Path(compiler).resolve())
    command = [cxx]
    if Path(cxx).stem == 'zig': command.append('c++')
    if Path(cxx).stem in ('cl', 'clang-cl'):
        command += ['/EHsc', '/std:c++latest', '/W4', '/WX', '/utf-8', '/DNOMINMAX', '/D_WIN32_WINNT=0x0a00',
                    '/I' + str(ROOT / 'tests/network_fakes'), '/I' + str(ROOT / 'src'), '/I' + str(asio_include),
                    str(ROOT / 'tests/dns_forwarder_harness.cpp'), '/Fe:' + str(exe), '/Fo:' + str(build / 'host.obj'),
                    '/link', 'ws2_32.lib', 'mswsock.lib']
    else:
        # Zig's MinGW target does not define _MT/_REENTRANT, so Asio needs
        # explicit thread support to select its real Win32 timer/resolver code.
        command += ['-std=c++23', '-Wall', '-Wextra', '-Werror', '-DNOMINMAX', '-D_WIN32_WINNT=0x0a00', '-DASIO_HAS_THREADS=1',
                    '-I' + str(ROOT / 'tests/network_fakes'), '-I' + str(ROOT / 'src'), '-isystem', str(asio_include),
                    str(ROOT / 'tests/dns_forwarder_harness.cpp'), '-lws2_32', '-lmswsock', '-o', str(exe)]
    env = os.environ.copy(); env['ZIG_GLOBAL_CACHE_DIR'] = str(build / 'zig-global-cache'); env['ZIG_LOCAL_CACHE_DIR'] = str(build / 'zig-local-cache')
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    return exe

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx', default=os.environ.get('CXX', 'cl'))
    parser.add_argument('--asio-include', type=Path)
    parser.add_argument('--exe', type=Path, help='Reuse an already compiled test host')
    args = parser.parse_args()
    if os.name != 'nt': parser.error('these tests exercise the Windows production network implementation')
    if not args.exe and not args.asio_include: parser.error('--asio-include is required when compiling')
    tests(args.exe.resolve() if args.exe else compile_host(args.cxx, args.asio_include.resolve()))

if __name__ == '__main__': main()
