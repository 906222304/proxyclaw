"""Compile the real fixed-path log service; only writes inside ignored test dir."""
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
build = root / 'build/log-tail-tests'
build.mkdir(parents=True, exist_ok=True)
exe = build / 'log_tail_test.exe'
env = os.environ.copy()
env['ZIG_GLOBAL_CACHE_DIR'] = str(root / 'build/dns-network-tests/zig-global-cache')
env['ZIG_LOCAL_CACHE_DIR'] = str(root / 'build/dns-network-tests/zig-local-cache')
command = [str(root / 'build/test-toolchain/ziglang/zig.exe'), 'c++', '-std=c++23',
           '-Wall', '-Wextra', '-Werror', '-DNOMINMAX', '-I' + str(root / 'src'),
           '-isystem', str(root / 'build/test-deps'),
           str(root / 'tests/log_tail_test.cpp'), str(root / 'src/services/shell_service.cpp'),
           str(root / 'src/common/api_exception.cpp'), '-lcomdlg32', '-lshell32', '-luser32', '-o', str(exe)]
subprocess.run(command, cwd=root, env=env, check=True)
subprocess.run([str(exe)], cwd=build, check=True, timeout=10)
