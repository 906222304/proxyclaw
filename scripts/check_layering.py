"""Assert the three-layer source boundaries (H1/H5 in docs/ARCHITECTURE.md).

Pure text checks, safe to run anywhere (CI included). Exit code 1 on the first
violation, printing up to five offending lines.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

FORBIDDEN = [
    (r"asio\.hpp|asio::", "services", "services must not touch asio (H1 layering)"),
    (r"httplib\.h|httplib::", "services", "services must not touch httplib (H1 layering)"),
    (r"sse_hub", "services", "services must not reference sse_hub (H5)"),
    (r"strand_bound", "transport/handlers", "handlers must not use strand_bound (H1 layering)"),
]
NEW_ARCH = ["services", "projection", "transport", "common", "domain"]


def sources(folder: str):
    base = SRC / folder
    return sorted(p for p in base.rglob("*") if p.suffix in {".hpp", ".cpp", ".h"})


def fail(message: str, hits: list[str]) -> None:
    for hit in hits[:5]:
        print(hit, file=sys.stderr)
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    for pattern, folder, message in FORBIDDEN:
        rx = re.compile(pattern)
        hits = [f"{p.relative_to(ROOT)}:{n}: {line.strip()}"
                for p in sources(folder)
                for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
                if rx.search(line)]
        if hits:
            fail(message, hits)

    leaks = [str(p.relative_to(ROOT)) for folder in NEW_ARCH for p in sources(folder)
             if p.name != "config_store.hpp"
             and "config_manager.hpp" in p.read_text(encoding="utf-8", errors="replace")]
    if leaks:
        fail("config_manager.hpp leaked into new-arch code (only config_store.hpp may include it)", leaks)

    for cpp in sorted((SRC / "services").glob("*.cpp")):
        own = f'services/{cpp.stem}.hpp'
        bad = [line.strip() for line in cpp.read_text(encoding="utf-8", errors="replace").splitlines()
               if line.startswith('#include "services/') and own not in line]
        if bad:
            fail("service-to-service include detected (services must not depend on each other)",
                 [f"{cpp.relative_to(ROOT)}: {b}" for b in bad])

    print("layering OK")


if __name__ == "__main__":
    main()
