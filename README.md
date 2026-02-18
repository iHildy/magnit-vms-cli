# magnit-vms-hour-logging-cli

Deterministic Go CLI for logging hours to `prowand.pro-unlimited.com`.

## Install

```bash
go install github.com/ihildy/magnit-vms-hour-logging-cli/cmd/hours@latest
```

If you see `command not found: hours`, add Go's bin directory to your `PATH`:

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc
source ~/.zshrc
rehash
hours --help
```

## Setup (Skill)

Install this repo's skill for agents to log hours for you:

```bash
npx skills add https://github.com/ihildy/magnit-vms-hour-logging-cli --skill hour-logging-cli-non-interactive
```

This CLI does **not** parse natural language and does **not** call AI models. It accepts structured command input so humans or external automation can drive it safely.

## Commands

- `hours auth login --username <email> [--password '<password>' | --password-stdin]`
- `hours auth status`
- `hours auth logout`
- `hours engagement list`
- `hours config set-default-engagement --id <engagement_id>`
- `hours config set-timezone --tz <IANA_TZ>`
- `hours show --date YYYY-MM-DD [--engagement ID] [--json]`
- `hours set --date YYYY-MM-DD --span labor:09:00-12:00 --span lunch:12:00-12:30 --span labor:12:30-17:00 [--engagement ID] [--dry-run] [--yes] [--json]`
- `hours mark-dnw --date YYYY-MM-DD [--engagement ID] [--dry-run] [--yes] [--json]`

## Behavior

- Day-level patching on top of fetched weekly metadata.
- Strict validation for spans.
- Conflict confirmation when replacing an already-populated day.
- `--dry-run` prints proposed diff and payload without saving.
- Credentials stored in OS keychain via go-keyring.

## Build

```bash
go mod tidy
go build ./cmd/hours
```

## Login Examples

Interactive password prompt:

```bash
./hours auth login --username your-email@example.com
```

Non-interactive password flag:

```bash
./hours auth login --username your-email@example.com --password 'your-password'
```

Non-interactive stdin password (safest for special characters like `&`, `$`, `*`, `^`):

```bash
printf '%s' 'b5&$^*1h6' | ./hours auth login --username your-email@example.com --password-stdin
```

Check auth:

```bash
./hours auth status --json
```

## Notes

- Basic unit tests are included for time parsing/validation and day patching logic.
- API behavior is based on observed request/response flow and current implementation tests.
