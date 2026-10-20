"""Compile/run TCP tuple tests with MSVC, without administrator access.

Run in a Visual Studio developer shell. A normal WinDivert SDK (x64 DLL
and import library) is required, but the test never opens the driver.
"""
import argparse
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx', default='cl')
    parser.add_argument('--windivert-dir', type=Path, default=ROOT / 'WinDivert-2.2.2-A/x64')
    parser.add_argument('--exe', type=Path)
    args = parser.parse_args()
    if args.exe:
        subprocess.run([str(args.exe.resolve())], check=True, timeout=10)
        return
    native = args.windivert_dir.resolve()
    for name in ('WinDivert.lib', 'WinDivert.dll'):
        if not (native / name).is_file():
            parser.error(f'{native / name} is missing; provide --windivert-dir')
    build = ROOT / 'build/tcp-redirect-tests'
    build.mkdir(parents=True, exist_ok=True)
    exe = build / 'test_tcp_redirect.exe'
    subprocess.run([args.cxx, '/nologo', '/std:c++latest', '/EHsc', '/W4', '/WX',
                    '/utf-8', '/DNOMINMAX', '/I' + str(ROOT / 'src'),
                    '/I' + str(ROOT / 'WinDivert-2.2.2-A/include'),
                    str(ROOT / 'tests/test_tcp_redirect.cpp'),
                    '/Fe:' + str(exe), '/Fo:' + str(build / 'test_tcp_redirect.obj'),
                    '/link', str(native / 'WinDivert.lib'), 'ws2_32.lib'], check=True, timeout=120)
    shutil.copy2(native / 'WinDivert.dll', build / 'WinDivert.dll')
    subprocess.run([str(exe)], check=True, timeout=10)

if __name__ == '__main__':
    main()
