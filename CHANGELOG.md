# Changelog

All notable changes to Sentiel are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- CI/CD: `.github/workflows/ci.yml` now runs on pushes and pull requests to `main` and, after `test`, `build` and the new `container` job pass on a push to `main`, a `deploy` job publishes the Docker image to `ghcr.io/shinitihm/sentiel` (`latest`, `main`, `sha-<commit>`) and verifies the published image (pull, `version`, `demo --no-ai`).
- `Dockerfile` (non-root, installs the wheel that passed CI) and `scripts/image_check.py`.

### Fixed
- CI on `main` was red since Dependabot bumped `actions/download-artifact` to v8: `tests/test_workflows.py` pinned `@v4`. The test now checks the action, not its major version.

## [1.0.0] - unreleased (tag v1.0.0 pending)

The version is set to 1.0.0 in the code, but it is not published yet. The maintainer replaces "unreleased (tag v1.0.0 pending)" with the release date when tagging `v1.0.0`.

### Added
- Release to PyPI: `pipx install sentiel`. Tags `vX.Y.Z` trigger `.github/workflows/release.yml`, which checks the tag against `sentiel.__version__`, builds the sdist and wheel and publishes with PyPI trusted publishing (no token).
- `scripts/check_dist.py` verifies the built sdist and wheel: rule files and demo data are in the wheel, and secrets, databases and local folders (`sentiel.toml`, `*.db`, `.env*`, `.venv/`, `docs/`) are in neither.
- `sentiel bench MODELS --readme` refreshes the benchmark table between the `<!-- BENCH:START -->` and `<!-- BENCH:END -->` markers of a README (`--readme-file PATH` picks the file). With missing, duplicated or reversed markers it fails without writing. Model names are escaped in the table.
- CI: Python 3.14 in the test matrix (informational, `continue-on-error`) and a `build` job (`python -m build`, `twine check`, `scripts/check_dist.py`). Dependabot for `pip` and GitHub Actions.
- Community files: `CONTRIBUTING.md`, `SECURITY.md`, this changelog, issue templates (new rule, false positive) and `contrib/sysmon.md`.
- Package metadata (authors, keywords, classifiers, URLs). The version lives only in `sentiel/__init__.py`.

### Changed
- Strict config: an unknown key at the top level, in `[sources]`, in `[[sources.files]]`, in `[keys]` or in `[notify]` is now an error (exit 2, or FAIL in `sentiel doctor`) that names the key and never echoes its value. Valid keys are unchanged, including the `json` alias in `[sources]`.
- `sentiel scan` shows only the exception class name in the `triage failed` warning.

### Fixed
- Rule titles, MITRE tags, notes and AI summaries from third parties are stripped of terminal control and bidi characters before display in `alerts`, `show`, `report`, `rules list` and `rules test`.
- `rules test` with a non-UTF-8 rule or events file prints a short error instead of a traceback.
- `demo` and `bench` close the database connection on errors, and `bench --out` is written even if a later model fails.

## [0.4.0]

### Added
- Database migrations (`PRAGMA user_version`), applied automatically and atomically when the database is opened. A database newer than the installed Sentiel is refused and left untouched.
- Alert status and notes: `sentiel set <id> open|ack|closed|false_positive [--note TEXT]`, and `sentiel alerts --all`. Only a human changes status. Closed, false-positive and suppressed alerts are never triaged or notified.
- `[[suppress]]` entries in the config (`rule_id`, `field`, `equals`, `reason`), and `sentiel set <id> false_positive --suppress FIELD` to print one. Only the first event of an alert is checked.
- Alert grouping with `group_window` (default 3600 seconds, `0` disables). A grown alert is not notified again.
- Daily digest: `digest_hour` for `sentiel watch`, and `sentiel digest` to send it now.

### Changed
- Invalid config makes every command exit with code 2 and a short message, without a traceback or the offending value.

## [0.3.0]

### Added
- Your own rules with `rules_dirs` and `disabled_rules`. Rules that do not convert, or that target a product Sentiel does not collect, are skipped with one summary warning per cycle.
- Sigma correlation rules (`event_count`, `gte`, one `group-by`). The two brute-force detections are now rule files (`win_logon_bruteforce.yml`, `lnx_ssh_bruteforce.yml`); alert ids are unchanged.
- Regex text-log sources with `[[sources.files]]`.
- `sentiel rules list [--skipped]` and `sentiel rules test RULE.yml EVENTS.jsonl`.

### Fixed
- Events with an out-of-range timestamp no longer break the scan cycle: the line is skipped.
- A rule that fails at run time becomes a warning instead of stopping detection.
- Text logs are read at most 32 MiB per cycle and split only on `\n`, so a log line cannot forge events with other separators.

## [0.2.0]

### Added
- LLM backoff (30 s up to 1800 s) when the model is down, with a hint to force a retry using `sentiel triage`.
- Concurrent triage with `triage_concurrency`.
- Notification per channel: one failing channel does not block the others.
- `sentiel doctor` (database, rules, sources, model, notifications, heartbeat) and a heartbeat on every scan.
- Services: `contrib/sentiel.service` (systemd) and `contrib/sentiel-task.xml` (Windows Task Scheduler).

### Changed
- Rules are cached by path and modification time.

## [0.1.1]

### Fixed
- Restored the `demo`, `bench`, `chat` and `version` commands.
- `auth.log` dates across the new year, including 29 February. An invalid date skips the line instead of failing the whole scan.
