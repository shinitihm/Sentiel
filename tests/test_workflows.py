import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

GITHUB = Path(__file__).resolve().parent.parent / ".github"


def load(relative: str) -> dict:
    return yaml.safe_load((GITHUB / relative).read_text(encoding="utf-8"))


def triggers(doc: dict) -> dict:
    # PyYAML le a chave `on` como o booleano True.
    return doc.get("on", doc.get(True))


def test_all_yaml_files_load():
    files = list(GITHUB.rglob("*.yml"))
    assert files
    for path in files:
        assert yaml.safe_load(path.read_text(encoding="utf-8")) is not None, path


def test_ci_matrix_includes_314_as_informative():
    doc = load("workflows/ci.yml")
    test_job = doc["jobs"]["test"]
    assert "3.14" in test_job["strategy"]["matrix"]["python"]
    assert test_job["continue-on-error"] == "${{ matrix.python == '3.14' }}"


def test_ci_has_build_job_checking_dist():
    steps = load("workflows/ci.yml")["jobs"]["build"]["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "python -m build" in commands
    assert "twine check dist/*" in commands
    assert "python scripts/check_dist.py dist" in commands


def test_release_triggers_only_on_version_tags():
    doc = load("workflows/release.yml")
    on = triggers(doc)
    assert set(on) == {"push"}
    assert on["push"] == {"tags": ["v*"]}


def test_release_build_job_is_minimal_and_checks_tag():
    doc = load("workflows/release.yml")
    build = doc["jobs"]["build"]
    assert build["permissions"] == {"contents": "read"}
    steps_text = yaml.safe_dump(build["steps"])
    assert "id-token" not in steps_text
    runs = "\n".join(step.get("run", "") for step in build["steps"])
    assert "scripts/check_dist.py" in runs
    assert "GITHUB_REF_NAME" in runs
    for job in doc["jobs"].values():
        for step in job["steps"]:
            assert "${{" not in step.get("run", "")


def tag_check_script() -> str:
    steps = load("workflows/release.yml")["jobs"]["build"]["steps"]
    (step,) = [s for s in steps if s.get("name") == "Check tag matches package version"]
    assert step.get("shell") == "bash"
    return step["run"]


def find_bash() -> str | None:
    candidates = [r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")]
    for candidate in candidates:
        if not candidate or not Path(candidate).exists():
            continue
        probe = subprocess.run([candidate, "-c", "echo ok"], capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip() == "ok":
            return candidate
    return None


BASH = find_bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="bash funcional ausente")


def run_tag_check(tmp_path: Path, ref_name: str):
    (tmp_path / "sentiel").mkdir(exist_ok=True)
    (tmp_path / "sentiel" / "__init__.py").write_text('__version__ = "1.2.3"\n', encoding="utf-8")
    env = {**os.environ, "GITHUB_REF_NAME": ref_name}
    script = tag_check_script().replace("python3", f'"{Path(sys.executable).as_posix()}"')
    return subprocess.run(
        [BASH, "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=tmp_path, env=env, capture_output=True, text=True,
    )


@needs_bash
def test_tag_check_accepts_matching_tag(tmp_path):
    assert run_tag_check(tmp_path, "v1.2.3").returncode == 0


@needs_bash
@pytest.mark.parametrize(
    "ref",
    [
        "v1.2.3; touch pwned",
        "v1.2.3; rm -rf /",
        "v",
        "v1.2",
        "v1.2.3-rc1",
        "vv1.2.3",
        "v$(touch pwned; echo 1.2.3)",
        "v1.2.3`touch pwned`",
        "v1.2.3 ",
        "1.2.3",
    ],
)
def test_tag_check_rejects_bad_tags_without_executing(tmp_path, ref):
    result = run_tag_check(tmp_path, ref)
    assert result.returncode != 0
    assert not (tmp_path / "pwned").exists()


def test_tag_check_runs_before_build():
    steps = load("workflows/release.yml")["jobs"]["build"]["steps"]
    names = [s.get("name") or s.get("run", "") for s in steps]
    assert names.index("Check tag matches package version") < names.index("python -m build")


def test_checkouts_do_not_persist_credentials_and_ci_is_read_only():
    for rel in ("workflows/ci.yml", "workflows/release.yml"):
        doc = load(rel)
        for job in doc["jobs"].values():
            for step in job["steps"]:
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] is False
    assert load("workflows/ci.yml")["permissions"] == {"contents": "read"}


def test_release_publish_job_uses_trusted_publishing():
    doc = load("workflows/release.yml")
    publish = doc["jobs"]["publish"]
    assert publish["needs"] == "build"
    assert publish["environment"] == "pypi"
    assert publish["permissions"] == {"id-token": "write"}
    uses = [step.get("uses") for step in publish["steps"]]
    assert "pypa/gh-action-pypi-publish@release/v1" in uses
    assert any(str(u).startswith("actions/download-artifact@") for u in uses)


def test_release_has_no_pypi_secrets():
    text = (GITHUB / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "secrets." not in text
    assert "password" not in text.lower()


def test_dependabot_covers_pip_and_actions():
    doc = load("dependabot.yml")
    updates = {item["package-ecosystem"]: item for item in doc["updates"]}
    assert set(updates) == {"pip", "github-actions"}
    for item in updates.values():
        assert item["schedule"]["interval"] == "weekly"


ROOT = GITHUB.parent


def test_issue_templates_are_valid_forms():
    templates = sorted((GITHUB / "ISSUE_TEMPLATE").glob("*.yml"))
    assert {t.name for t in templates} == {"config.yml", "false-positive.yml", "new-rule.yml"}
    for path in templates:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if path.name == "config.yml":
            assert doc["blank_issues_enabled"] is False
            assert any("SECURITY.md" in link["url"] for link in doc["contact_links"])
            continue
        assert doc["name"] and doc["description"], path
        assert doc["body"], path
        ids = [item["id"] for item in doc["body"] if "id" in item]
        assert len(ids) == len(set(ids)), path
        assert any(item["type"] != "markdown" and item.get("validations", {}).get("required") for item in doc["body"])
    false_positive = (GITHUB / "ISSUE_TEMPLATE" / "false-positive.yml").read_text(encoding="utf-8")
    assert "sensitive" in false_positive.lower()


def test_readmes_have_no_relative_links_or_state_language():
    # README.md becomes the PyPI page: relative links break there and the page is immutable per version.
    import re

    for name in ("README.md", "README.pt-BR.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        targets = re.findall(r"\]\(([^)\s]*)", text)
        relative = [t for t in targets if not t.startswith(("http://", "https://", "#", "mailto:"))]
        assert not relative, (name, relative)
        assert "not yet published" not in text and "ainda não publicada" not in text, name
        assert "- [x] v1.0 release (PyPI)" in text or "- [x] release v1.0 (PyPI)" in text, name
        assert "cp sentiel.example.toml sentiel.toml  #" not in text, name


def test_community_files_exist_and_cross_link():
    for name in ("CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "contrib/sysmon.md"):
        assert (ROOT / name).is_file(), name
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_pt = (ROOT / "README.pt-BR.md").read_text(encoding="utf-8")
    assert "pipx install sentiel" in readme and "pipx install sentiel" in readme_pt
    for text in (readme, readme_pt):
        for link in ("CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "contrib/sysmon.md"):
            assert link in text, link
        assert "pypi.org" not in text  # no PyPI badge before the first publication
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "rules test" in contributing and "pending publisher" in contributing
    assert "v*" in contributing and "release.yml" in contributing
    assert "git push --tags" not in contributing and "git push origin vX.Y.Z" in contributing
    assert "README" in contributing.split("Each release:")[1]
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "32 MiB" in security and "first event" in security
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for heading in ("[1.0.0]", "[0.4.0]", "[0.3.0]", "[0.2.0]", "[0.1.1]"):
        assert f"## {heading}" in changelog
        