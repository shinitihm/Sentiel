# Sentiel

![GitHub repo size](https://img.shields.io/github/repo-size/shinitihm/Sentiel?style=for-the-badge)
![GitHub language count](https://img.shields.io/github/languages/count/shinitihm/Sentiel?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/shinitihm/Sentiel?style=for-the-badge)
![GitHub open issues](https://img.shields.io/github/issues/shinitihm/Sentiel?style=for-the-badge)
![GitHub open pull requests](https://img.shields.io/github/issues-pr/shinitihm/Sentiel?style=for-the-badge)
![Python](https://img.shields.io/badge/python-%E2%89%A53.11-blue?style=for-the-badge)
![License](https://img.shields.io/github/license/shinitihm/Sentiel?style=for-the-badge)

[Português](README.pt-BR.md)

> A personal SOC with AI triage that works with any LLM. Sigma rules detect attacks in your own logs, and a language model explains and prioritises each alert. The model never decides which alerts exist, and it cannot be talked into downgrading one.

### Improvements and roadmap

The project is still under development. The next releases follow this roadmap:

- [x] v0.1.1: CLI repair (`demo`, `bench`, `chat`, `version`) and `auth.log` dates across the new year
- [x] v0.2: orchestration (LLM backoff, concurrent triage, `sentiel doctor`, heartbeat, systemd and Task Scheduler services)
- [x] v0.3: data-driven extension (your own rules with `rules_dirs`/`disabled_rules`, Sigma correlations, regex sources, `sentiel rules list/test`)
- [x] v0.4: database migrations, alert status and notes (`sentiel set`), suppressions, grouping and a daily digest
- [ ] v1.0: PyPI release, CONTRIBUTING, SECURITY, CHANGELOG and CI on Python 3.14

## 💻 Prerequisites

Before you start, make sure you meet these requirements:

- Python **3.11 or newer**.
- Windows, Linux or macOS. On Windows, reading the **Security** log requires an administrator shell. Without it, Sentiel says so and continues with the other sources.
- Optional, for AI triage: [Ollama](https://ollama.com) with a local model, or an API key for any provider supported by [LiteLLM](https://github.com/BerriAI/litellm) (Anthropic, OpenAI, Gemini and 100+ more).

## 🚀 Installing Sentiel

To install Sentiel, follow these steps:

Linux and macOS:

```
git clone https://github.com/shinitihm/Sentiel && cd Sentiel
python -m venv .venv && source .venv/bin/activate
pip install .
```

Windows:

```
git clone https://github.com/shinitihm/Sentiel; cd Sentiel
python -m venv .venv; .venv\Scripts\activate
pip install .
```

## ☕ Using Sentiel

To use Sentiel, follow these steps:

```
sentiel demo --no-ai                  # 7 simulated attacks, detection only, offline
sentiel demo -m ollama/llama3.1:8b    # the same, with local AI triage

cp sentiel.example.toml sentiel.toml  # edit the model, sources and notifications
sentiel doctor                        # checks config, database, rules, sources, model and notifications
sentiel scan                          # one pass over your logs
sentiel watch                         # continuous monitoring
sentiel alerts / show 3 / report      # browse alerts (open and ack; `alerts --all` shows the rest)
sentiel set 3 ack --note "looking"    # open | ack | closed | false_positive
sentiel digest                        # last-24h summary, sent now
sentiel chat "which IPs failed to log in most?"
sentiel rules list --skipped          # loaded rules and warnings
sentiel rules test my_rule.yml events.jsonl
sentiel bench ollama/llama3.1:8b,anthropic/claude-sonnet-5-5
```

To run it as a service, use `contrib/sentiel.service` on Linux (systemd) or `contrib/sentiel-task.xml` on Windows (Task Scheduler). The steps are in each file's header. LLM provider keys come only from the environment: use `/etc/sentiel/env` on Linux and machine-level variables on Windows.

### Extending Sentiel

- **Your own rules:** `rules_dirs = ["~/.sentiel/rules"]` loads extra Sigma rules. For a SigmaHQ clone, point it at its `rules/` folder. `disabled_rules` turns rules off. Rules that do not convert, or that target a product Sentiel does not collect, are skipped with one summary warning per cycle (`sentiel rules list --skipped`).
- **Correlation:** Sigma correlation rules with `event_count`, `gte` and a single `group-by`. See `sentiel/rules/lnx_ssh_bruteforce.yml`.
- **Any text log:** `[[sources.files]]` with a regex. Named groups become Sigma fields, and `ts` and `host` are special groups. Keep the regex linear: log lines are attacker-controlled and Python's `re` has no timeout.

### Alert lifecycle

- **Status and notes:** `sentiel set <id> <status> [--note TEXT]` with `open`, `ack`, `closed` or `false_positive` (note up to 1000 characters). `suppressed` exists but only comes from the config file. `sentiel alerts` lists `open` and `ack`; `--all` also shows `closed`, `false_positive` and `suppressed`. Only humans change status: the model never does. Closed, false-positive and suppressed alerts are never triaged or notified.
- **Suppressions:** `sentiel set <id> false_positive --suppress FIELD` prints a `[[suppress]]` block (`rule_id`, `field`, `equals`, `reason`) for you to paste into the config. Nothing is edited for you, and the model never creates suppressions. Only the **first** event of an alert is checked, so a correlated burst that opens with a suppressed event is suppressed as a whole. See `sentiel.example.toml`.
- **Grouping:** `group_window` (default 3600 seconds, `0` turns it off) merges repeats of the same rule, host and group into one alert whose `count` grows. An alert that was already notified is **not** notified again when it grows: the `count` shows in `sentiel show` and in the digest.
- **Daily digest:** `digest_hour = 9` (local hour, 0-23) makes `sentiel watch` send a 24-hour summary once a day to your notification channels. `sentiel digest` sends it now, or prints it when no channel is set. The digest has counts and rule titles, never raw logs. The digest uses the event time (`last_ts`), so old logs ingested now may not show up in it.
- **Database upgrades:** the schema is migrated automatically (`PRAGMA user_version`) when the database is opened, and your alerts and logs are kept. Copy `sentiel.db` before upgrading Sentiel. A database newer than the installed Sentiel is refused with a clear message and left untouched.
- **Invalid config:** every command exits with code 2 and a short message, without a traceback and without echoing the offending value. Exception: `sentiel doctor` exits 1 and shows FAIL in its table.

### Security by design

- **Prompt injection cannot hide an alert:** effective severity is `max(rule level, AI severity)`. If the AI calls a `high` rule "benign", the alert shows as **CONTESTED** and is still notified.
- **Logs are data, not instructions:** events reach the model in an `<untrusted_log_data>` block, and the model has no tools.
- **Read-only chat:** the database is opened with `mode=ro`, a SQLite authorizer allows only `SELECT` on `logs`/`alerts`, and queries have time and row limits.
- **No alert is lost:** every stage writes to SQLite before the next. If the model is down, alerts stay pending and are retried.

## 📫 Contributing to Sentiel

To contribute to Sentiel, follow these steps:

1. Fork this repository.
2. Create a branch: `git checkout -b <branch_name>`.
3. Make your changes, run `pip install -e ".[dev]"`, `pytest -q` and `ruff check .`, then commit them: `git commit -m '<commit_message>'`.
4. Push to your fork: `git push origin <branch_name>`.
5. Open a pull request.

See also GitHub's documentation on [creating a pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request).

## 🤝 Contributors

Thanks to the following people who have contributed to this project:

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/shinitihm" title="shinitihm on GitHub">
        <img src="https://github.com/shinitihm.png" width="100px;" alt="shinitihm's photo on GitHub"/><br>
        <sub>
          <b>shinitihm</b>
        </sub>
      </a>
    </td>
  </tr>
</table>

## 😄 Become a contributor

Want to be part of this project? Open an issue or a pull request. A `CONTRIBUTING.md` guide arrives with v1.0.

## 📝 License

This project is under the MIT license. See the [LICENSE](LICENSE) file for details.
