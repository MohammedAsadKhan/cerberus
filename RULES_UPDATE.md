# Cerberus — Live Rules Update System

## Overview

Cerberus ships with a set of NIST SP 800-63B compliance rules compiled directly into the binary. These bundled rules guarantee the tool works in any environment — including air-gapped systems with no internet access.

In addition to the bundled rules, Cerberus supports a **live update system** that pulls the latest rules from this repository. This means compliance logic can be updated in response to new NIST guidance, revised breach statistics, or newly identified policy risks — without requiring users to download a new version of the binary.

---

## How It Works

Cerberus resolves rules using a three-tier priority system:

```
1. Live (--update-rules flag)   — fetched from GitHub at runtime
        ↓ if unavailable
2. Cached                       — last successful fetch, stored on disk
        ↓ if unavailable
3. Bundled                      — compiled into the binary at build time
```

Each audit run prints which source is active so the user always knows exactly what ruleset they are running against.

---

## Usage

### Standard audit (uses cached or bundled rules)

```bash
cerberus audit --min-length 12 --expiry-days 90 --complexity
```

### Audit with live rule update

```bash
cerberus audit --min-length 12 --expiry-days 90 --complexity --update-rules
```

The `--update-rules` flag instructs Cerberus to fetch the latest `nist_rules.json` from this repository before running the audit. If the fetch succeeds, the rules are cached locally for all subsequent runs. If the fetch fails — due to network unavailability or any other error — Cerberus falls back gracefully to the cached or bundled ruleset and proceeds normally.

---

## Rule Cache Location

Fetched rules are cached locally at:

| Platform | Cache Path |
|---|---|
| Windows | `%LOCALAPPDATA%\cerberus\nist_rules.json` |
| macOS | `~/Library/Caches/cerberus/nist_rules.json` |
| Linux | `~/.cache/cerberus/nist_rules.json` |

The cache persists across sessions. Cerberus will continue using the last successfully fetched rules until a new `--update-rules` run succeeds.

---

## Rule Source File

The live rules are maintained at:

```
rules/nist_rules.json
```

This file is the authoritative source for all compliance logic. It follows this structure:

```json
{
  "version": "1.0.0",
  "last_updated": "2025-04-17",
  "source": "NIST Special Publication 800-63B (Digital Identity Guidelines)",
  "rules": [
    {
      "id": "MIN_LENGTH",
      "description": "Human-readable description of the rule",
      "recommendation": "Actionable remediation guidance for stakeholders",
      "breach_stat": "Supporting evidence from real-world breach data",
      "weight": 20
    }
  ]
}
```

### Field Reference

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique rule identifier used internally by the auditor |
| `description` | string | Plain-English explanation of the NIST requirement |
| `recommendation` | string | Remediation guidance shown when a policy fails the rule |
| `breach_stat` | string | Real-world breach statistic used as evidence (optional) |
| `weight` | integer | Contribution to the overall compliance score (all weights sum to 100) |

---

## Maintaining the Rules

When NIST publishes updated guidance, the process to update Cerberus is:

1. Edit `rules/nist_rules.json` in this repository
2. Increment the `version` field following semantic versioning
3. Update the `last_updated` field
4. Commit and push to `main`

Users will receive the updated rules on their next `cerberus audit --update-rules` run. No binary release or recompile is required.

---

## Offline and Air-Gapped Environments

Cerberus is designed to operate fully offline. If `--update-rules` is not passed, or if the network is unavailable, the tool falls back silently to cached or bundled rules and completes the audit normally. No internet connection is ever required to run Cerberus.

---

## Security Note

The rules manifest is fetched over HTTPS from a public GitHub raw content URL. The fetched JSON is validated for structure before being accepted. Cerberus will reject and fall back if the response is malformed, empty, or returns a non-200 status code.

The HaveIBeenPwned integration uses a separate network call and is controlled independently via the `--hibp` flag. See the main [README](README.md) for details on how k-Anonymity protects your passwords during that check.
