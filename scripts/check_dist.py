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
FORBIDDEN_DIRS = {".superpowers", "docs", ".venv", ".claude", ".git", ".pytest_cache", ".ruff_cache", "__pycache__"}
FORBIDDEN_FILES = ("sentiel.toml*", "*.db*", "*.sqlite*", ".env*", "*.pyc")
WHEEL_REQUIRED = ("sentiel/demo/events.jsonl", "sentiel/demo/auth_log.txt", "sentiel/demo/expected.json")
MIN_RULES = 8


def source_version() -> str:
    text = (ROOT / "sentiel" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    return match.group(1) if match else ""


def check_members(names: list[str], kind: str) -> list[str]:
    """Returns the problems found in the member names of one archive ('sdist' or 'wheel')."""
    problems = []
    for name in names:
        norm = name.replace("\\", "/").lower()
        parts = [p for p in norm.split("/") if p]
        if not parts:
            continue
        if norm.startswith("/") or ".." in parts or re.match(r"[a-z]:", norm):
            problems.append(f"{kind}: unsafe path {name}")
        elif any(p in FORBIDDEN_DIRS or any(fnmatch.fnmatchcase(p, pat) for pat in FORBIDDEN_FILES) for p in parts):
            problems.append(f"{kind}: forbidden path {name}")
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
    if not expected:
        return ["could not read __version__ from sentiel/__init__.py"]
    archives = sorted(dist_dir.glob("*.tar.gz")) + sorted(dist_dir.glob("*.whl"))
    if not archives:
        return [f"no *.tar.gz or *.whl in {dist_dir}"]
    for path in archives:
        try:
            if path.name.endswith(".whl"):
                with zipfile.ZipFile(path) as zf:
                    names = zf.namelist()
                    meta = [n for n in names if re.fullmatch(r"[^/]+\.dist-info/METADATA", n)]
                    found = _version_of(zf.read(meta[0])) if len(meta) == 1 else None
                problems += check_members(names, "wheel")
                if found is None:
                    problems.append(f"{path.name}: expected exactly one <name>.dist-info/METADATA, found {len(meta)}")
            else:
                with tarfile.open(path) as tf:
                    members = tf.getmembers()
                    names = [m.name for m in members]
                    info = [m for m in members if m.isfile() and re.fullmatch(r"[^/]+/PKG-INFO", m.name)]
                    found = _version_of(tf.extractfile(info[0]).read()) if len(info) == 1 else None
                problems += check_members(names, "sdist")
                problems += [f"sdist: non-regular member {m.name}" for m in members if not (m.isfile() or m.isdir())]
                if found is None:
                    problems.append(f"{path.name}: expected exactly one <root>/PKG-INFO, found {len(info)}")
        except (zipfile.BadZipFile, tarfile.TarError, OSError, KeyError, EOFError):
            problems.append(f"{path.name}: unreadable archive")
            continue
        if found is not None and found != expected:
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
