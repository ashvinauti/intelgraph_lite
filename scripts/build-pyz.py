#!/usr/bin/env python3
"""Build dist/iglite.pyz: the whole app in one file, runnable with any Python 3.11+.

    python scripts/build-pyz.py
    python dist/iglite.pyz demo        # share this one file; nothing to install

The runtime needs only the standard library, so the archive is just the package
(code, dashboard, ATT&CK catalogue). The AI analyst still needs `pip install anthropic`.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "iglite"


def build(output: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        shutil.copytree(PACKAGE, stage / "iglite", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        output.parent.mkdir(parents=True, exist_ok=True)
        zipapp.create_archive(
            stage, output, interpreter="/usr/bin/env python3", main="iglite.cli:main_exit", compressed=True
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-o", "--output", default=str(ROOT / "dist" / "iglite.pyz"))
    out = build(Path(parser.parse_args().output))
    print(f"Built {out} ({out.stat().st_size / 1024:.0f} KB). Run: python {out.name} demo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
