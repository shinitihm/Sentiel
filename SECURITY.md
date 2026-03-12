# Security Policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: open the repository's **Security** tab, then **Report a vulnerability**. Do not open a public issue for a vulnerability, and do not include real logs, tokens or webhooks in a report.

Sentiel is maintained by one person: reports are handled on a best-effort basis, with no fixed response time.

## Supported versions

Only the latest released version gets security fixes. Upgrade before reporting, and read [CHANGELOG.md](CHANGELOG.md) first. The SQLite schema migrates automatically on open, so copy `sentiel.db` before upgrading.

## Threat model

Sentiel reads logs that an attacker may control, and sends a summary of them to a language model. It is built around these assumptions.

- **Logs are hostile input.** Event text reaches the model only inside an `<untrusted_log_data>` block. Text from logs, third-party rule titles and notes is stripped of terminal control characters before it is shown.
- **The model never decides and never acts.** It has no tools. Detection comes from Sigma rules, and the effective severity is `max(rule level, AI severity)`: if the model calls a `high` rule benign, the alert shows as CONTESTED and is still notified.
- **Only humans change status and suppressions.** `sentiel set` and the `[[suppress]]` blocks in the config are the only ways. The model cannot close, acknowledge or suppress an alert, and `--suppress` only prints a block for you to paste.
- **Data leaves the machine only with a non-local model.** With a local model (for example Ollama) triage stays on the machine. With a cloud model, event data is sent to that provider, and Sentiel warns about it. The daily digest has counts and rule titles, never raw logs.
- **Secrets are not logged.** Provider keys, Telegram tokens and Discord webhooks come from the environment or the config and are never written to logs or echoed in errors. Config errors name the offending key, never its value. Keep `sentiel.toml` out of version control, and out of any package you build.
- **Chat is read-only.** The database is opened with `mode=ro`, a SQLite authorizer allows only `SELECT` on `logs` and `alerts`, and queries have time and row limits.
- **No alert is lost.** Each stage writes to SQLite before the next one. If the model is down, alerts stay pending and are retried.
- **Releases** are built by CI and published with PyPI trusted publishing from a protected environment, with no long-lived PyPI token.

## Known limits

These are known and accepted for now. Reports about them are welcome as ordinary issues.

- **Regexes you write are not time-limited.** `[[sources.files]]` regexes and `|re` modifiers in rules run on attacker-controlled lines, and Python's `re` has no timeout. A badly written pattern (nested quantifiers) can stall a scan cycle. Keep patterns linear, and only load rules you trust.
- **Text logs are read up to 32 MiB per cycle.** For each text source (`auth.log` and regex sources), at most 32 MiB is read per scan cycle and the rest is read in later cycles. A very large burst is delayed, not dropped, but the delay can be long.
- **A suppression checks only the first event of an alert.** A correlated burst whose first event matches a `[[suppress]]` entry is suppressed as a whole, including later events that would not match. Write suppressions narrowly.
- **Merging into an existing alert is silent.** When grouping adds events to an alert that was already notified, its `count` grows without a new notification. A correlation that continues after you closed it or marked it false positive is also added to that same alert, without notifying, until the correlation lookback window passes. Check `count` in `sentiel show` and in the digest.
- **Status and suppressions need a human.** There is no automation for them, on purpose. If nobody reviews alerts, nothing closes them.
- **Rules from third parties are code-like input.** Sentiel validates and sanitises them, but a rule you did not review can still produce noisy or misleading alerts.
- **Windows Security log needs an administrator shell.** Without it, that source is skipped with a message and other sources continue.
