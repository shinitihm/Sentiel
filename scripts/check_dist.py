"""Verifies the built sdist/wheel in a folder: no secrets or junk, wheel carries rules and demo data, versions match.

Usage: python scripts/check_dist.py <dist_dir>
"""
import fnmatch
import re
import sys
import tarfile
import zipfile
from email.parser import BytesHeaderParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_DIRS = {".superpowers", "docs", ".venv", ".claude", "__pycache__"}
FORBIDDEN_FILES = ("sentiel.toml", "*.db", "*.sqlite*", ".env*", "*.pyc")
WHEEL_REQUIRED = ("sentiel/demo/events.jsonl", "sentiel/demo/auth_log.txt", "sentiel/demo/expected.json")
MIN_RULES = 8


def source_version() -> str:
    text = (ROOT / "sentiel" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else ""


def check_members(names: list[str], kind: str) -> list[str]:
    """Returns the problems found in the member names of one archive ('sdist' or 'wheel')."""
    problems = []
    for name in names:
        parts = [p for p in name.replace("\\", "/").split("/") if p]
        if not parts:
            continue
        if any(p in FORBIDDEN_DIRS for p in parts[:-1]) or parts[-1] in FORBIDDEN_DIRS:
            problems.append(f"{kind}: forbidden path {name}")
        elif any(fnmatch.fnmatchcase(parts[-1], pat) for pat in FORBIDDEN_FILES):
            problems.append(f"{kind}: forbidden file {name}")
    if kind == "wheel":
        rules = [n for n in names if fnmatch.fnmatchcase(n, "sentiel/rules/*.yml")]
        if len(rules) < MIN_RULES:
            problems.append(f"wheel: sentiel/rules/*.yml has {len(rules)} files, expected at least {MIN_RULES}")
        for required in WHEEL_REQUIRED:
            if required not in names:
                problems.append(f"wheel: missing {required}")
    return problems


def _version_of(raw: bytes) -> str:
    return str(BytesHeaderParser().parsebytes(raw).get("Version", ""))


def check_dir(dist_dir: Path) -> list[str]:
    problems = []
    expected = source_version()
    archives = sorted(dist_dir.glob("*.tar.gz")) + sorted(dist_dir.glob("*.whl"))
    if not archives:
        return [f"no *.tar.gz or *.whl in {dist_dir}"]
    for path in archives:
        if path.name.endswith(".whl"):
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                meta = [n for n in names if n.endswith(".dist-info/METADATA")]
                found = _version_of(zf.read(meta[0])) if meta else ""
            problems += check_members(names, "wheel")
        else:
            with tarfile.open(path) as tf:
                names = tf.getnames()
                info = [m for m in tf.getmembers() if m.isfile() and re.fullmatch(r"[^/]+/PKG-INFO", m.name)]
                found = _version_of(tf.extractfile(info[0]).read()) if info else ""
            problems += check_members(names, "sdist")
        if found != expected:
            problems.append(f"{path.name}: metadata version {found or '?'} differs from sentiel.__version__ {expected}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_dist.py <dist_dir>", file=sys.stderr)
        return 2
    problems = check_dir(Path(argv[1]))
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print("dist OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
