"""Compile Windows configuration/path checks without touching system settings.

python tests/run_ui_config_tests.py --cxx path/to/zig.exe --json-include build/test-deps
python tests/run_ui_config_tests.py --cxx cl --json-include path/to/vcpkg/installed/x64-windows/include

Dialog/Explorer and logging calls are replaced; real configuration parsing,
UTF conversion and legacy configuration migration are exercised.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx',default=os.environ.get('CXX','cl'))
    parser.add_argument('--json-include',type=Path,default=ROOT/'build/test-deps')
    args = parser.parse_args()
    json_include = args.json_include.resolve()
    if not (json_include/'nlohmann/json.hpp').exists():
        parser.error('--json-include must contain nlohmann/json.hpp')
    build = ROOT/'build/ui-config-tests'; build.mkdir(parents=True,exist_ok=True)
    compiler = shutil.which(args.cxx) or str(Path(args.cxx).resolve())
    env = os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR'] = str(build/'zig-global-cache')
    env['ZIG_LOCAL_CACHE_DIR'] = str(build/'zig-local-cache')
    includes = [ROOT/'tests/network_fakes',ROOT/'src',json_include]
    for test in ['test_ui_config_and_paths','test_config_migration']:
        exe = build/(test+'.exe')
        sources = [str(ROOT/'tests'/(test+'.cpp'))]
        if test == 'test_ui_config_and_paths': sources.append(str(ROOT/'src/common/api_exception.cpp'))
        command = [compiler]
        if Path(compiler).stem == 'zig': command.append('c++')
        if Path(compiler).stem in ['cl','clang-cl']:
            command += ['/EHsc','/std:c++latest','/W4','/WX','/utf-8']
            command += ['/I'+str(p) for p in includes]
            command += sources + ['/Fe:'+str(exe),'/Fo:'+str(build)+'\\','/link','shell32.lib','ws2_32.lib']
        else:
            command += ['-std=c++23','-Wall','-Wextra','-Werror']
            command += ['-I'+str(p) for p in includes]
            command += sources + ['-lshell32','-lws2_32','-o',str(exe)]
        subprocess.run(command,cwd=ROOT,env=env,check=True)
        subprocess.run([str(exe)],cwd=ROOT,check=True)

if __name__ == '__main__':
    main()
