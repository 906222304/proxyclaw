"""Local end-to-end verification (replaces scripts/verify.sh).

Stages, each with its own wall-clock budget:
  1. frontend unit tests and build (npm test, npm run build)
  2. native build (cmake --build build --config Release)
  3. unit tests (ctest)
  4. layering checks (scripts/check_layering.py)
  5. HTTP e2e (tests/run_all.py; launches proxyclaw.exe)
  6. Playwright + WebView2 e2e (tests/playwright_e2e/run_pw.py via uv)

Stages 5-6 need an administrator shell; skip them with --no-e2e. The build
directory must already be configured (cmake --preset windows).
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(label: str, seconds: int, command: list[str], cwd: Path = ROOT) -> None:
    print(f"\n==> {label}", flush=True)
    exe = shutil.which(command[0]) or command[0]
    try:
        result = subprocess.run([exe, *command[1:]], cwd=cwd, timeout=seconds)
    except subprocess.TimeoutExpired:
        sys.exit(f"FAIL: {label} exceeded {seconds}s timeout")
    if result.returncode != 0:
        sys.exit(f"FAIL: {label} exited {result.returncode}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-e2e", action="store_true", help="skip the elevated e2e stages")
    args = parser.parse_args()

    if not (ROOT / "build").is_dir():
        sys.exit("FAIL: build/ missing. Run 'python scripts/prepare_release_deps.py' and 'cmake --preset windows' first.")

    run("frontend unit tests", 180, ["npm", "test"], ROOT / "frontend")
    run("frontend build", 240, ["npm", "run", "build"], ROOT / "frontend")
    run("native build", 900, ["cmake", "--build", "build", "--config", "Release"])
    run("unit tests", 300, ["ctest", "--test-dir", "build", "-C", "Release", "--output-on-failure"])
    run("layering checks", 30, [sys.executable, "scripts/check_layering.py"])
    if not args.no_e2e:
        run("HTTP e2e", 240, [sys.executable, "tests/run_all.py"])
        if not shutil.which("uv"):
            sys.exit("FAIL: uv not found on PATH (required for the PEP 723 Playwright script)")
        run("Playwright e2e", 300, ["uv", "run", "--script", "tests/playwright_e2e/run_pw.py"])
    print("\nALL GREEN")


if __name__ == "__main__":
    main()
