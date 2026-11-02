"""Actual TCP/UDP regression tests on loopback, with no driver or system changes.

--baseline compiles the pre-fix headers to demonstrate the old defects.
"""
import argparse
import contextlib
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def exact(sock, n):
    result = b''
    while len(result) < n:
        part = sock.recv(n - len(result))
        if not part:
            raise EOFError()
        result += part
    return result


class Proxy:
    def __init__(self, behavior='halfclose', bound='ipv4'):
        self.behavior, self.bound = behavior, bound
        self.closed = threading.Event()
        self.errors, self.connections, self.threads = [], [], []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(128)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        family = socket.AF_INET6 if bound == 'ipv6' else socket.AF_INET
        self.relay = socket.socket(family, socket.SOCK_DGRAM)
        self.relay.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0))
        self.relay.settimeout(.1)
        self.spawn(self.accept)
        self.spawn(self.echo_udp)

    def spawn(self, function, *args):
        thread = threading.Thread(target=function, args=args, daemon=True)
        self.threads.append(thread)
        thread.start()

    def accept(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.settimeout(3)
            self.connections.append(connection)
            self.spawn(self.handle, connection)

    def reply(self, port):
        if self.bound == 'ipv6':
            return b'\x05\0\0\x04' + socket.inet_pton(socket.AF_INET6, '::1') + struct.pack('!H', port)
        if self.bound == 'domain':
            return b'\x05\0\0\x03\x09localhost' + struct.pack('!H', port)
        address = '0.0.0.0' if self.bound == 'wildcard' else '127.0.0.1'
        return b'\x05\0\0\x01' + socket.inet_aton(address) + struct.pack('!H', port)

    def handle(self, connection):
        try:
            assert exact(connection, 3) == b'\x05\x01\0'
            if self.behavior == 'stall_auth':
                self.closed.wait(5)
                return
            if self.behavior == 'auth_reject':
                connection.sendall(b'\x05\xff')
                self.closed.wait(2)
                return
            connection.sendall(b'\x05\0')
            head = exact(connection, 4)
            assert head[0] == 5 and head[2:] == b'\0\x01'
            exact(connection, 6)
            if self.behavior == 'stall_connect':
                self.closed.wait(5)
                return
            if self.behavior == 'connect_reject':
                connection.sendall(b'\x05\x05\0\x01')  # deliberately no address tail
                self.closed.wait(2)
                return
            reply = self.reply(self.relay.getsockname()[1] if head[1] == 3 else 443)
            if self.behavior == 'bad_rsv':
                reply = reply[:2] + b'\x01' + reply[3:]
            if self.behavior == 'bad_atyp':
                reply = reply[:3] + b'\x09' + reply[4:]
            if self.behavior == 'split_reply':
                for byte in reply:
                    connection.sendall(bytes([byte]))
                    time.sleep(.001)
            else:
                connection.sendall(reply)
            if head[1] == 3:
                while connection.recv(64):
                    pass
                return
            assert head[1] == 1
            if self.behavior == 'reset':
                time.sleep(.03)
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('hh', 1, 0))
                return
            if self.behavior == 'idle':
                time.sleep(.35)  # longer than setup deadline; healthy idle TCP stays alive
            while connection.recv(64):
                pass  # response is sent only AFTER application's FIN
            time.sleep(.03)
            connection.sendall(b'complete-response')
            connection.shutdown(socket.SHUT_WR)
        except (EOFError, ConnectionError, OSError):
            pass  # cancellation and malformed/rejected handshakes intentionally close
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            connection.close()

    def echo_udp(self):
        while not self.closed.is_set():
            try:
                data, peer = self.relay.recvfrom(65535)
                self.relay.sendto(data, peer)
            except socket.timeout:
                continue
            except OSError:
                return

    def drop_control(self):
        connection = self.connections[0]
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()

    def stop(self):
        self.closed.set()
        self.listener.close()
        self.relay.close()
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for thread in self.threads:
            thread.join(1)
        assert not self.errors, self.errors


class Host:
    def __init__(self, exe, mode, port):
        self.lines = queue.Queue()
        self.process = subprocess.Popen([str(exe), mode, str(port)], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def collect():
            for line in self.process.stdout:
                self.lines.put(line.strip())
        self.reader = threading.Thread(target=collect, daemon=True)
        self.reader.start()

    def line(self, timeout=2):
        try:
            return self.lines.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError('host did not complete operation within deadline')

    def done(self):
        assert self.line() == 'DONE'
        assert self.process.wait(timeout=2) == 0, self.process.stderr.read()

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=2)
        self.reader.join(1)
        self.process.stdout.close()
        self.process.stderr.close()


@contextlib.contextmanager
def running(exe, mode='tcp', **kwargs):
    proxy = Proxy(**kwargs)
    host = Host(exe, mode, proxy.port)
    try:
        yield host, proxy
    finally:
        host.stop()
        proxy.stop()


def tcp_case(exe, behavior='halfclose', bound='ipv4'):
    with running(exe, behavior=behavior, bound=bound) as (host, _):
        ready = host.line().split()
        assert ready[0] == 'READY'
        start = time.monotonic()
        with socket.create_connection(('127.0.0.1', int(ready[1])), timeout=2) as client:
            client.sendall(b'request')
            client.shutdown(socket.SHUT_WR)
            data = b''
            try:
                while part := client.recv(1024):
                    data += part
            except ConnectionError:
                pass
        host.done()
        elapsed = time.monotonic() - start
        if behavior in ('halfclose', 'idle', 'split_reply'):
            assert data == b'complete-response', ('response lost/corrupted', data)
        else:
            assert data == b'', data
        if behavior.startswith('stall_'):
            assert .1 <= elapsed < 1, elapsed
        if behavior in ('auth_reject', 'connect_reject', 'bad_rsv', 'bad_atyp'):
            assert elapsed < .14, ('failure waited for timeout', elapsed)


def control_case(exe, mode='udp_control'):
    with running(exe, mode=mode) as (host, proxy):
        assert host.line().startswith('READY ')
        proxy.drop_control()
        host.done()


def compile_host(args):
    build = ROOT / 'build/proxy-health-tests'
    build.mkdir(parents=True, exist_ok=True)
    command = [str(args.cxx.resolve()), 'c++', '-std=c++23', '-Wall', '-Wextra', '-Werror',
               '-DNOMINMAX', '-D_WIN32_WINNT=0x0a00', '-DASIO_HAS_THREADS=1']
    if args.baseline:
        baseline = build / 'baseline'
        for name in ('proxy/relay.hpp', 'proxy/socks5_async.hpp', 'udp/socks5_udp_manager.hpp', 'udp/socks5_udp_session.hpp'):
            target = baseline / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(subprocess.check_output(['git', 'show', args.baseline_ref + ':src/' + name], cwd=ROOT))
        command += ['-DPROXYCLAW_BASELINE', '-I' + str(baseline)]
    exe = build / ('proxy_health_baseline.exe' if args.baseline else 'proxy_health_harness.exe')
    command += ['-I' + str(ROOT / 'tests/network_fakes'), '-I' + str(ROOT / 'src'),
                '-isystem', str(args.asio_include.resolve()), str(ROOT / 'tests/proxy_health_harness.cpp'),
                '-lws2_32', '-lmswsock', '-o', str(exe)]
    env = os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR'] = str(ROOT / 'build/dns-network-tests/zig-global-cache')
    env['ZIG_LOCAL_CACHE_DIR'] = str(ROOT / 'build/dns-network-tests/zig-local-cache')
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    return exe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx', type=Path, default=ROOT / 'build/test-toolchain/ziglang/zig.exe')
    parser.add_argument('--asio-include', type=Path, default=ROOT / 'build/network-test-deps/asio-asio-1-30-2/asio/include')
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--baseline-ref', default='5b93eb0bdc5dc3d857f0ddfe5529938138d4944f')
    parser.add_argument('--exe', type=Path)
    args = parser.parse_args()
    exe = args.exe.resolve() if args.exe else compile_host(args)
    if args.baseline:
        reproduced = 0
        for name, case in [('TCP half-close truncates response', lambda: tcp_case(exe)),
                           ('IPv6 reply leaves corrupt bytes', lambda: tcp_case(exe, bound='ipv6')),
                           ('UDP control loss leaves receive suspended', lambda: control_case(exe))]:
            try:
                case()
            except AssertionError as error:
                print('REPRODUCED', name, ':', error, flush=True)
                reproduced += 1
            else:
                raise AssertionError('baseline defect did not reproduce: ' + name)
        assert reproduced == 3
        return
    for behavior, bound in [('halfclose', 'ipv4'), ('halfclose', 'ipv6'), ('halfclose', 'domain'),
                            ('split_reply', 'ipv6'), ('idle', 'ipv4'), ('reset', 'ipv4'),
                            ('stall_auth', 'ipv4'), ('stall_connect', 'ipv4'),
                            ('auth_reject', 'ipv4'), ('connect_reject', 'ipv4'),
                            ('bad_rsv', 'ipv4'), ('bad_atyp', 'ipv4')]:
        tcp_case(exe, behavior, bound)
        print('PASS TCP', behavior, bound, flush=True)
    control_case(exe)
    print('PASS UDP control loss releases pending receive', flush=True)
    control_case(exe, 'udp_recreate')
    print('PASS UDP dead session is replaced and replies are received', flush=True)
    for behavior in ('stall_auth', 'stall_connect', 'connect_reject'):
        with running(exe, mode='udp_stall', behavior=behavior) as (host, _):
            assert host.line() == 'TICK'
            host.done()
        print('PASS UDP bounded setup without blocking IO/status', behavior, flush=True)
    with running(exe, mode='udp_stop', behavior='stall_auth') as (host, _):
        assert host.line() == 'TICK'
        host.done()
    print('PASS stop cancels pending UDP handshake', flush=True)
    for bound in ('ipv4', 'ipv6', 'wildcard', 'domain'):
        with running(exe, mode='udp_cleanup', bound=bound) as (host, _):
            host.done()
        print('PASS 96 UDP creations/cleanups/recreations, no retained ownership', bound, flush=True)
    subprocess.run([str(exe), 'keepalive', '0'], check=True, timeout=2)
    print('PASS Windows TCP keepalive is enabled', flush=True)


if __name__ == '__main__':
    main()
