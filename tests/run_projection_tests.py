"""Compile real process_projection with fake tree data; no ETW/proxy/DNS."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx', type=Path, default=ROOT/'build/test-toolchain/ziglang/zig.exe')
    parser.add_argument('--asio-include', type=Path,
                        default=ROOT/'build/network-test-deps/asio-asio-1-30-2/asio/include')
    args = parser.parse_args()
    build = ROOT/'build/projection-tests'; build.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR'] = str(ROOT/'build/dns-network-tests/zig-global-cache')
    env['ZIG_LOCAL_CACHE_DIR'] = str(ROOT/'build/dns-network-tests/zig-local-cache')
    exe = build/'test_projection_visibility.exe'
    subprocess.run([str(args.cxx.resolve()), 'c++', '-std=c++23', '-DASIO_HAS_THREADS=1',
                    '-DPROXYCLAW_PROJECTION_COALESCE',
                    '-I'+str(ROOT/'tests/projection_fakes'), '-I'+str(ROOT/'tests/network_fakes'),
                    '-I'+str(ROOT/'src'), '-I'+str(args.asio_include.resolve()),
                    str(ROOT/'tests/test_projection_visibility.cpp'),
                    str(ROOT/'src/projection/process_projection.cpp'),
                    '-lws2_32', '-lmswsock', '-o', str(exe)], cwd=ROOT, env=env, check=True)
    subprocess.run([str(exe)], timeout=15, check=True)
if __name__ == '__main__': main()
