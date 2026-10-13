import importlib.util
import re
import tomllib
from pathlib import Path

import sentiel

ROOT = Path(__file__).resolve().parent.parent


def load_check_dist():
    spec = importlib.util.spec_from_file_location("check_dist", ROOT / "scripts" / "check_dist.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_version_is_single_sourced():
    data = pyproject()
    assert "version" in data["project"]["dynamic"]
    assert "version" not in data["project"]
    assert data["tool"]["hatch"]["version"]["path"] == "sentiel/__init__.py"
    assert re.fullmatch(r"\d+\.\d+\.\d+", sentiel.__version__)


def test_metadata_is_complete():
    project = pyproject()["project"]
    assert project["classifiers"]
    assert project["keywords"]
    assert project["urls"]
    assert "Programming Language :: Python :: 3.14" in project["classifiers"]
    assert any(c.startswith("License :: OSI Approved :: MIT") for c in project["classifiers"])


def test_check_members_flags_secrets_and_missing_data():
    check_members = load_check_dist().check_members
    assert any("sentiel.toml" in p for p in check_members(["sentiel/cli.py", "sentiel.toml"], "sdist"))
    for bad in ["sentiel/x.db", ".env", "docs/memoria.md", ".superpowers/sdd/a", "sentiel/__pycache__/a.pyc"]:
        assert check_members(["sentiel/cli.py", bad], "sdist"), bad
    # sdist nao exige as regras/dados; o wheel sim
    assert check_members(["sentiel/cli.py"], "sdist") == []
    missing = check_members(["sentiel/cli.py"], "wheel")
    assert any("rules" in p for p in missing)
    assert any("events.jsonl" in p for p in missing)
    clean = [f"sentiel/rules/r{i}.yml" for i in range(8)] + [
        "sentiel/demo/events.jsonl",
        "sentiel/demo/auth_log.txt",
        "sentiel/demo/expected.json",
        "sentiel/cli.py",
    ]
    assert check_members(clean, "wheel") == []


def test_source_version_accepts_single_quotes_and_reports_unreadable(tmp_path, monkeypatch):
    mod = load_check_dist()
    (tmp_path / "sentiel").mkdir()
    init = tmp_path / "sentiel" / "__init__.py"
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    init.write_text("__version__ = '9.8.7'\n", encoding="utf-8")
    assert mod.source_version() == "9.8.7"
    init.write_text("# no version here\n", encoding="utf-8")
    assert mod.source_version() == ""
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "x.whl").write_bytes(b"")
    assert any("could not read __version__" in p for p in mod.check_dir(tmp_path / "dist"))


def test_check_members_is_case_insensitive_and_any_level():
    check = load_check_dist().check_members
    for bad in ["Sentiel.TOML", "x/.ENV", "DOCS/a", "sentiel/x.DB", "x/sentiel.toml/y", "a/x.db-wal", ".git/config"]:
        assert check(["sentiel/cli.py", bad], "sdist"), bad
    for bad in [".pytest_cache/a", ".ruff_cache/a", "sentiel.toml.bak", "x.sqlite3"]:
        assert check([bad], "sdist"), bad
    assert check(["pkg/sentiel.example.toml", "pkg/Sentiel.Example.toml"], "sdist") == []


def test_check_members_rejects_unsafe_paths():
    check = load_check_dist().check_members
    for bad in ["/etc/x", "../../evil", "a/../b", "C:/x", "c:\\x", "\\abs"]:
        assert check([bad], "sdist"), bad


def _tar_with(path, specs):
    import io
    import tarfile

    with tarfile.open(path, "w:gz") as tf:
        for name, kind in specs:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tf.addfile(info)
            else:
                data = b"Metadata-Version: 2.1\nVersion: 0.0.0\n"
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))


def test_check_dir_flags_unsafe_tar_members(tmp_path):
    mod = load_check_dist()
    specs = [("s-0/PKG-INFO", "file"), ("/etc/x", "file"), ("../../evil", "file"), ("s-0/l", "symlink")]
    _tar_with(tmp_path / "s-0.tar.gz", specs)
    problems = "\n".join(mod.check_dir(tmp_path))
    assert "/etc/x" in problems
    assert "../../evil" in problems
    assert "s-0/l" in problems


def test_check_dir_unreadable_archives(tmp_path):
    mod = load_check_dist()
    (tmp_path / "a-1.whl").write_text("not a zip")
    (tmp_path / "b-1.tar.gz").write_text("not a tar")
    (tmp_path / "c-1.tar.gz").write_bytes(b"")
    problems = mod.check_dir(tmp_path)
    for name in ["a-1.whl", "b-1.tar.gz", "c-1.tar.gz"]:
        assert f"{name}: unreadable archive" in problems
    assert mod.main(["check_dist.py", str(tmp_path)]) == 1


def test_check_dir_requires_single_metadata(tmp_path):
    import zipfile

    mod = load_check_dist()
    with zipfile.ZipFile(tmp_path / "w-1.whl", "w") as zf:
        zf.writestr("sentiel/cli.py", "")
    assert any("METADATA" in p for p in mod.check_dir(tmp_path))
    _tar_with(tmp_path / "w-1.tar.gz", [("s/a", "file")])
    assert any("PKG-INFO" in p for p in mod.check_dir(tmp_path))
