"""Checks used by the CI/CD pipeline to validate the Docker image (before and after the deploy).

Usage:
    python scripts/image_check.py expected-version        # prints sentiel.__version__ from the source tree
    python scripts/image_check.py demo-output <file>      # fails unless `sentiel demo --no-ai` output looks right
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def expected_version() -> str:
    text = (ROOT / "sentiel" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not match:
        raise SystemExit("sentiel/__init__.py has no __version__")
    return match.group(1)


def check_demo_output(text: str) -> list[str]:
    problems = []
    if "Detected attacks" not in text:
        problems.append("demo output has no 'Detected attacks' table")
    if "Traceback" in text:
        problems.append("demo output contains a traceback")
    return problems


def main(argv: list[str]) -> int:
    if argv[:1] == ["expected-version"]:
        print(expected_version())
        return 0
    if len(argv) == 2 and argv[0] == "demo-output":
        problems = check_demo_output(Path(argv[1]).read_text(encoding="utf-8", errors="replace"))
        for p in problems:
            print(f"::error::{p}")
        if not problems:
            print("demo output OK")
        return 1 if problems else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
