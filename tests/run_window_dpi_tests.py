"""Validate the real native DPI/window code without starting proxy or DNS.

Requires Windows and Zig. The test embeds the production DPI/icon resources;
only its UAC level is changed to asInvoker because it has no privileged code.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx', type=Path, default=ROOT/'build/test-toolchain/ziglang/zig.exe')
    args = parser.parse_args()
    build = ROOT/'build/window-dpi-tests'
    build.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which(str(args.cxx)) or str(args.cxx.resolve())
    if Path(compiler).stem != 'zig':
        parser.error('this resource compilation runner currently requires Zig')
    env = os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR'] = str(ROOT/'build/dns-network-tests/zig-global-cache')
    env['ZIG_LOCAL_CACHE_DIR'] = str(ROOT/'build/dns-network-tests/zig-local-cache')
    manifest = build/'test.manifest'
    manifest.write_text((ROOT/'assets/proxyclaw.manifest').read_text(encoding='utf-8')
                        .replace('requireAdministrator', 'asInvoker'), encoding='utf-8')
    resource = build/'test.rc'
    resource.write_text(f'1 ICON "{(ROOT/"assets/proxyclaw.ico").as_posix()}"\n'
                        f'1 24 "{manifest.as_posix()}"\n', encoding='utf-8')
    obj = build/'test.res'
    subprocess.run([compiler, 'rc', '/fo', str(obj), str(resource)], check=True)
    exe = build/'test_window_dpi.exe'
    subprocess.run([compiler, 'c++', '-std=c++23', '-DNOMINMAX',
                    '-I'+str(ROOT/'tests/network_fakes'), '-I'+str(ROOT/'src'),
                    str(ROOT/'tests/test_window_dpi.cpp'), str(obj),
                    '-ldwmapi', '-lshell32', '-luser32', '-lgdi32', '-lole32',
                    '-o', str(exe)], cwd=ROOT, env=env, check=True)
    subprocess.run([str(exe)], cwd=ROOT, timeout=20, check=True)
    icon_exe = build/'test_icon_resolution.exe'
    subprocess.run([compiler, 'c++', '-std=c++23', '-DNOMINMAX',
                    '-I'+str(ROOT/'tests/network_fakes'), '-I'+str(ROOT/'src'),
                    str(ROOT/'tests/test_icon_resolution.cpp'),
                    '-lgdiplus', '-lshell32', '-luser32', '-lole32', '-luuid',
                    '-o', str(icon_exe)], cwd=ROOT, env=env, check=True)
    subprocess.run([str(icon_exe)], cwd=ROOT, timeout=20, check=True)

if __name__ == '__main__':
    main()
