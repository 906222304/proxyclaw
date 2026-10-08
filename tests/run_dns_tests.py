"""Compile and run DNS lifecycle tests without changing system DNS.

Examples:
    python tests/run_dns_tests.py --cxx clang++
    python tests/run_dns_tests.py --cxx path/to/zig.exe

The production DnsManager is compiled with fake Windows/network dependencies.
DNS wire parsing is also checked, including malformed/compressed names.
No administrator privileges, driver, running proxy, or vcpkg are required.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    build = root / "build" / "dns-tests"
    build.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which(args.cxx) or str(Path(args.cxx).resolve())
    env = os.environ.copy()
    env["ZIG_GLOBAL_CACHE_DIR"] = str(build / "zig-global-cache")
    env["ZIG_LOCAL_CACHE_DIR"] = str(build / "zig-local-cache")
    for test in ("test_dns_manager", "test_dns_wire"):
        exe = build / (test + (".exe" if os.name == "nt" else ""))
        command = [compiler]
        if Path(compiler).stem == "zig":
            command.append("c++")
        if Path(compiler).stem in ("cl", "clang-cl"):
            command += ["/EHsc", "/std:c++latest", "/W4", "/WX", "/utf-8",
                        "/I" + str(root / "tests" / "dns_fakes"), "/I" + str(root / "src"),
                        str(root / "tests" / (test + ".cpp")),
                        "/Fe:" + str(exe), "/Fo:" + str(build / (test + ".obj"))]
        else:
            command += ["-std=c++23", "-Wall", "-Wextra", "-Werror",
                        "-I" + str(root / "tests" / "dns_fakes"), "-I" + str(root / "src"),
                        str(root / "tests" / (test + ".cpp")), "-o", str(exe)]
        subprocess.run(command, check=True, cwd=root, env=env)
        subprocess.run([str(exe)], check=True, cwd=root)


if __name__ == "__main__":
    main()
