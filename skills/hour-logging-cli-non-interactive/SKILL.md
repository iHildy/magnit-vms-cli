---
name: hour-logging-cli-non-interactive
description: Use this skill to run the `hours` CLI in fully non-interactive mode for authentication, logging, and verification. Trigger when an agent must log work hours deterministically via command flags (not natural language), avoid prompts, emit JSON for automation, or operate in CI/headless execution.
---

# Hour Logging CLI Non-Interactive

## Overview

Execute `hours` commands with explicit flags so the run is deterministic, scriptable, and prompt-free.
Prefer `--json`, `--yes`, `--engagement`, and `--password-stdin` where needed to avoid interactive input.

## Non-Interactive Workflow

1. Resolve executable:
- Prefer `./hours` if present in the repo root.
- If missing, run `go build ./cmd/hours` first.

2. Authenticate non-interactively:
- Run `./hours auth login --username <email> --password '<password>'`.
- Alternative for complex passwords: `printf '%s' '<password>' | ./hours auth login --username <email> --password-stdin`.

3. Verify authentication:
- Run `./hours auth status --json`.
- Proceed only when `"authenticated": true`.

4. Configure defaults (optional but recommended):
- Set engagement once: `./hours config set-default-engagement --id <engagement_id>`.
- Set timezone once: `./hours config set-timezone --tz <IANA_TZ>`.

5. Run logging operations:
- Set day spans (authoritative replace):
`./hours set --date YYYY-MM-DD --span labor:09:00-12:00 --span lunch:12:00-12:30 --span labor:12:30-17:00 --engagement <id> --yes --json`
- Mark did-not-work day:
`./hours mark-dnw --date YYYY-MM-DD --engagement <id> --yes --json`
- Read back day state:
`./hours show --date YYYY-MM-DD --engagement <id> --json`

6. Use dry-run before write when safety is required:
- `./hours set ... --dry-run --json`
- `./hours mark-dnw ... --dry-run --json`

## Command Patterns

Authentication:

```bash
./hours auth login --username "$HOURS_USERNAME" --password "$HOURS_PASSWORD"
or
printf '%s' "$HOURS_PASSWORD" | ./hours auth login --username "$HOURS_USERNAME" --password-stdin
./hours auth status --json
```

Set hours for one day:

```bash
./hours set \
  --date 2026-02-18 \
  --span labor:09:00-12:00 \
  --span lunch:12:00-12:30 \
  --span labor:12:30-17:00 \
  --engagement "$HOURS_ENGAGEMENT_ID" \
  --yes \
  --json
```

Mark day as did-not-work:

```bash
./hours mark-dnw --date 2026-02-19 --engagement "$HOURS_ENGAGEMENT_ID" --yes --json
```

Verify day:

```bash
./hours show --date 2026-02-18 --engagement "$HOURS_ENGAGEMENT_ID" --json
```

## Reliability Rules

- Always pass `--json` for machine-readable output.
- Always pass `--yes` for non-interactive writes to bypass confirmation prompts.
- Always pass `--engagement <id>` unless a default engagement is already configured.
- Always use `YYYY-MM-DD` dates and `type:HH:MM-HH:MM` spans.
- Treat non-zero exit status as failure.
- Prefer `--password-stdin` for passwords with shell-sensitive characters and to reduce shell-history/process-list exposure:
`printf '%s' "$HOURS_PASSWORD" | ./hours auth login --username "$HOURS_USERNAME" --password-stdin`.

## Failure Handling

- If auth fails (`authenticated: false`), run `auth login` again; for complex passwords prefer `--password-stdin` over `--password`.
- If a command errors on engagement resolution, pass `--engagement <id>` or configure a default.
- If span validation fails, fix overlaps/order/format and rerun.
- If uncertain about payload impact, rerun with `--dry-run --json`.
