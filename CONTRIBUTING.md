# Contributing to Sentiel

Thanks for helping. Sentiel is small on purpose, so the best contributions are usually a new detection rule, a false-positive fix or a clear bug report.

## Setup

Python 3.11 or newer.

Linux and macOS:

```
git clone https://github.com/shinitihm/Sentiel && cd Sentiel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Windows:

```
git clone https://github.com/shinitihm/Sentiel; cd Sentiel
python -m venv .venv; .venv\Scripts\activate
pip install -e ".[dev]"
```

Before opening a pull request:

```
pytest -q
ruff check .
sentiel demo --no-ai      # must still show 7 alerts
```

Ruff uses 120 columns. Tests that need a real LLM (`tests/test_llm_live.py`) are skipped unless you opt in; the rest run offline.

## Adding a rule

Sentiel reads Sigma rules. You do not need to write Python.

### A rule of your own, or a rule to propose

1. Write the Sigma rule as a `.yml` file. The `id` must be a UUID. In a Sigma rule, `logsource.product` is `windows`, `linux` or omitted. A rule for any other product is skipped with a warning ("product not collected"). A rule **without** `logsource.product` matches generic events (source `json`). `sentiel/rules/win_run_key_persistence.yml` is a Windows example. This is a generic one:

   ```yaml
   title: Example Backup Tool Run
   id: 6f1c1d52-3a0e-4b7e-9d0f-0a1b2c3d4e5f
   logsource:
     category: process_creation
   detection:
     selection:
       Image|endswith: '\backup-tool.exe'
     condition: selection
   level: medium
   ```

2. Write a `.jsonl` file with a few events, one JSON object per line. For a rule without a product, plain objects work: `ts` (ISO 8601 with offset), `host` and the event fields at the top level. Include at least one event that should match and, ideally, one that should not:

   ```
   {"ts": "2026-10-09T08:00:00+00:00", "host": "PC1", "Image": "C:\\Tools\\backup-tool.exe"}
   {"ts": "2026-10-09T08:05:00+00:00", "host": "PC1", "Image": "C:\\Windows\\notepad.exe"}
   ```

   For a rule with `product: windows` or `product: linux`, each line needs the full shape `{"ts": ..., "source": "windows", "host": ..., "fields": {...}}`, with `source` equal to the rule's product. `sentiel/demo/events.jsonl` has real examples.
3. Check it:

   ```
   sentiel rules test my_rule.yml events.jsonl
   ```

   The rule file must be self-contained. The command prints what the rule would alert on (here, one match) and exits 1 when nothing matches.
4. To use it locally, put the `.yml` in a folder listed in `rules_dirs` in `sentiel.toml`, then run `sentiel rules list` to confirm it loaded without warnings (`sentiel rules list --skipped` shows load warnings).

Correlation rules support `event_count` with `gte` and exactly one `group-by`. See `sentiel/rules/lnx_ssh_bruteforce.yml`.

### A built-in rule (pull request)

1. Add the `.yml` to `sentiel/rules/`.
2. Add events that trigger it to the demo data (`sentiel/demo/events.jsonl`, or `sentiel/demo/auth_log.txt` for Linux `auth.log`).
3. Add the rule `id` to `sentiel/demo/expected.json` with the attack name, expected severity and MITRE techniques. `tests/test_detect.py` checks that the demo detects exactly the rules listed there, and the demo must keep working with `--no-ai`.
4. Run `pytest -q` and `ruff check .`.

## Style

- YAGNI. Prefer the standard library, a few clear lines and no new runtime dependency. A new dependency needs a strong reason.
- Mark deliberate shortcuts with a `# ponytail:` comment saying what was skipped and why, so they can be found later.
- Match the style of the file you are editing. Keep each file's line endings (`sentiel/cli.py` uses CRLF).
- Add a test with every behavior change. Tests are offline and must not call a real model.
- Do not print secrets or config values in errors. Name the offending key, never its value.

## Principles that do not change

A pull request that breaks one of these will not be merged.

- The model never decides which alerts exist, and it cannot lower an alert's effective severity (`max(rule level, AI severity)`).
- Logs are hostile input. They reach the model only inside an `<untrusted_log_data>` block, and the model has no tools. Text from logs and third-party rules is sanitised before it reaches the terminal.
- No alert is lost. Each stage writes to SQLite before the next, and a pending alert is retried.
- A broken source or rule becomes a warning, not a crash.
- Status changes and suppressions come only from a human (`sentiel set`, `[[suppress]]` in the config).
- Secrets are never logged or echoed. Data leaves the machine only with a non-local model.

## Reporting bugs and rule issues

Use the issue templates: "New rule" and "False positive". Do not paste sensitive logs. For vulnerabilities, follow [SECURITY.md](SECURITY.md) and do not open a public issue.

## Releasing (maintainer only)

Releases are published to PyPI by `.github/workflows/release.yml` when a `vX.Y.Z` tag is pushed. It uses PyPI trusted publishing, so there is no PyPI token anywhere. The workflow checks that the tag equals `sentiel.__version__`, builds the sdist and wheel, runs `scripts/check_dist.py`, and publishes from the `pypi` environment.

One-time setup:

1. On PyPI, create a *pending publisher* (Account settings, Publishing): project `sentiel`, repository `shinitihm/Sentiel`, workflow `release.yml`, environment `pypi`. Keep the workflow and environment fields filled in, so the publisher cannot be used from another workflow.
2. On GitHub, create the environment `pypi` (Settings, Environments). Add required reviewers, and restrict deployment to tags matching `v*` (deployment branches and tags rule).
3. Add a tag ruleset (or tag protection) for `v*` so that only maintainers can create those tags. Anyone who can push a `v*` tag can start a release.

Each release:

1. Make sure CI is green on the exact commit you will tag. The release workflow does **not** run `pytest`; it only builds, checks the distribution and publishes.
2. Set the version in `sentiel/__init__.py` (the only place; `pyproject.toml` reads it).
3. Update `CHANGELOG.md`: put the release date on the new version heading (for 1.0.0, replace "unreleased (tag v1.0.0 pending)" with the date).
4. Check that the README (the page PyPI shows) describes the state of this release: roadmap, install steps and links. A PyPI page cannot be changed for a published version. Then tag and push only that tag:

   ```
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

5. Approve the `pypi` deployment on GitHub, then check the project page on PyPI and try `pipx install sentiel` in a clean environment.

Notes:

- CI also runs on Python 3.14 as informational only (`continue-on-error`), because some native dependencies may lack 3.14 wheels. The README does not promise 3.14 until that job is green.
- The PyPI badge in the README is added only after the first publication.
