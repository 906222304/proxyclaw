"""Administrator-only, bounded-port integration test; no proxy/DNS changes.

Uses production packet rewriting and SOCKS relay, with concurrent closes and
real TLS certificate verification. The loopback health proxy is a test fixture.
"""
import argparse
import concurrent.futures
import ctypes
import json
from pathlib import Path
import socket
import ssl
import subprocess
import time
from run_proxy_health_tests import Proxy


def run_case(exe, output, name, base, count, proxy_port, destination, operation):
    marker = output / name
    ready = Path(str(marker) + '.ready')
    if ready.exists():
        raise RuntimeError(f'Use a fresh output directory: {ready}')
    process = subprocess.Popen([str(exe), str(base), str(count), str(proxy_port),
                                destination, str(marker)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 8
        while not ready.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f'{name}: host failed to become ready')
            time.sleep(.05)
        def client(n):
            try:
                with socket.socket() as sock:
                    sock.settimeout(15)
                    sock.bind(('', base + n))
                    sock.connect((destination, 443))
                    return {'port': base + n, 'ok': operation(sock)}
            except OSError as error:
                return {'port': base + n, 'ok': False, 'error': str(error)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(client, range(count)))
        stdout = process.communicate(timeout=15)[0].decode(errors='replace')
        (output / (name + '-clients.json')).write_text(json.dumps(results, indent=2), encoding='utf-8')
        if process.returncode or not all(row['ok'] for row in results):
            raise RuntimeError(f'{name}: {results}, exit={process.returncode}, {stdout}')
        metrics = Path(str(marker) + '.result').read_text().split()
        assert metrics == [str(count), '0', '0'], metrics
        print(f'PASS {name}: {count} connections; no relay exceptions/send errors', flush=True)
        return {'name': name, 'connections': count, 'metrics': metrics}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def halfclose(sock):
    sock.sendall(b'request-body-' * 100)
    sock.shutdown(socket.SHUT_WR)
    response = bytearray()
    while True:
        part = sock.recv(8192)
        if not part:
            return response == b'complete-response'
        response.extend(part)


def reset(sock):
    sock.sendall(b'reset-test')
    try:
        return sock.recv(8192) == b''
    except ConnectionResetError:
        return True


def https(sock):
    with ssl.create_default_context().wrap_socket(sock, server_hostname='www.gstatic.com') as tls:
        tls.sendall(b'GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n')
        response = bytearray()
        # A 204 response ends at its headers; do not require TCP EOF from a
        # server/proxy that keeps the transport open after this bodyless reply.
        while b'\r\n\r\n' not in response:
            part = tls.recv(8192)
            if not part:
                break
            response.extend(part)
        return response.startswith(b'HTTP/1.1 204')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--https-only', action='store_true')
    args = parser.parse_args()
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel.CreateMutexW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    # Respect the application's own single-instance guard throughout the test.
    # This also prevents an accidental GUI launch between two test phases.
    gate = kernel.CreateMutexW(None, False, 'Global\\Clew_SingleInstance')
    if not gate or ctypes.get_last_error() == 183:
        if gate:
            kernel.CloseHandle(gate)
        raise RuntimeError('Exit every ProxyClaw instance before running this test')
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for name, base, count, behavior, operation in ([] if args.https_only else [
        ('concurrent-halfclose', 57100, 128, 'halfclose', halfclose),
        ('concurrent-reset', 57300, 32, 'reset', reset),
    ]):
        proxy = Proxy(behavior)
        try:
            results.append(run_case(args.exe, args.output, name, base, count,
                                    proxy.port, '203.0.113.1', operation))
        finally:
            proxy.stop()
    destination = socket.gethostbyname('www.gstatic.com')
    results.append(run_case(args.exe, args.output, 'real-https', 57400, 4,
                            7890, destination, https))
    (args.output / 'summary.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    kernel.CloseHandle(gate)


if __name__ == '__main__':
    main()
