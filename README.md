# magnit-vms-cli

Deterministic Go CLI for logging hours to `prowand.pro-unlimited.com` (magnit vms).

## Install

```bash
go install github.com/ihildy/magnit-vms-cli/cmd/magnit@latest
```

If you see `command not found: magnit`, add Go's bin directory to your `PATH`:

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc
source ~/.zshrc
rehash
magnit --help
```

## Setup (Skill)

Install this repo's skill for agents to log hours for you:

```bash
npx skills add https://github.com/ihildy/magnit-vms-cli --skill magnit-vms-cli-non-interactive
```

This CLI does **not** parse natural language and does **not** call AI models. It accepts structured command input so humans or external automation can drive it safely.

## Commands

- `magnit auth login --username <email> [--password '<password>' | --password-stdin]`
- `magnit auth status`
- `magnit auth logout`
- `magnit engagement list`
- `magnit config set-default-engagement --id <engagement_id>`
- `magnit config set-timezone --tz <IANA_TZ>`
- `magnit config set-credential-store --store <auto|keyring|file>`
- `magnit show --date YYYY-MM-DD [--engagement ID] [--json]`
- `magnit set --date YYYY-MM-DD --span labor:09:00-12:00 --span lunch:12:00-12:30 --span labor:12:30-17:00 [--engagement ID] [--dry-run] [--yes] [--json]`
- `magnit mark-dnw --date YYYY-MM-DD [--engagement ID] [--dry-run] [--yes] [--json]`

## Behavior

- Day-level patching on top of fetched weekly metadata.
- Strict validation for spans.
- Conflict confirmation when replacing an already-populated day.
- `--dry-run` prints proposed diff and payload without saving.
- Credential store supports `auto` (default), `keyring`, and `file`.
- In `auto`, CLI tries OS keyring first and falls back to `~/.config/magnit-vms-cli/credentials.yaml` on systems without Secret Service.
- Override per process with `MAGNIT_CREDENTIAL_STORE=auto|keyring|file`.

## Build

```bash
go mod tidy
go build ./cmd/magnit
```

## Login Examples

Interactive password prompt:

```bash
./magnit auth login --username your-email@example.com
```

Non-interactive password flag:

```bash
./magnit auth login --username your-email@example.com --password 'your-password'
```

Non-interactive stdin password (safest for special characters like `&`, `$`, `*`, `^`):

```bash
printf '%s' 'b5&$^*1h6' | ./magnit auth login --username your-email@example.com --password-stdin
```

Check auth:

```bash
./magnit auth status --json
```

## Ubuntu Server Notes

For headless Ubuntu servers, use file-backed credentials explicitly:

```bash
magnit config set-credential-store --store file
```

Or per command:

```bash
MAGNIT_CREDENTIAL_STORE=file magnit auth login --username your-email@example.com
```

## Notes

- Basic unit tests are included for time parsing/validation and day patching logic.
- API behavior is based on observed request/response flow and current implementation tests.
