# grants

grants lists and revokes the permissions you gave AI coding agents.

## Why

Every time you choose "always allow" or "trust this folder", your agent saves a grant. These grants pile up. You forget them. Some point to folders you deleted. Some hold a one-off command or a pasted token. Nothing shows you the full list, so nothing prompts you to clean it.

grants finds every standing grant, shows when it was given and when it was last used, flags the risky and stale ones, and removes the ones you pick. It backs up each file first. One command undoes the change.

## Install

With Go 1.24 or newer:

```sh
go install github.com/yihanzhu/grants@latest
```

Or download a binary for macOS or Linux (amd64 or arm64) from [GitHub Releases](https://github.com/yihanzhu/grants/releases).

## Quick start

```sh
grants
```

The summary below comes from a made-up home folder.

```text
grants: 13 active grants across 2 agents. 4 need a look. 4 point to deleted paths.

                      rules   trusted folders   high risk   removed
Claude Code   5 (1 deleted)     2 (1 deleted)           3         0
Codex         4 (1 deleted)     2 (1 deleted)           2         0

Needs a look
  f74bd7d  claude-code  Bash(curl -H 'Authorization: [redacted]' https://example.com/x)  high · one-off · never used · curl to …
  f2b6f3d  claude-code  Bash(make:*)                                                     high · last used 2026-10-03 · any subc…
  c9751cd  claude-code  Bash(git push:*)                                                 high · never used · pushes code to a r…
  7bdf7c2  codex        git push                                                         high · never used · pushes code to a r…

Clean up
  4 grants point to deleted paths: grants revoke --dead
  2 one-off rules, approved for a single URL or script: grants revoke --one-off
  6 grants not used in 90 days: grants revoke --unused
  Files are backed up first. Preview with --dry-run. Undo with grants undo.

History covers Claude Code from 2026-06-01 and Codex from 2026-06-01.
Next: grants show f74bd7d · grants revoke f74bd7d · grants log
```

"Needs a look" lists grants that are high risk or hold a credential. "Clean up" lists the bulk commands. Each count is what that command would select, so a grant with two flags is in two counts.

Look at one grant, preview its removal, then remove it:

```sh
grants show 1af2cd9
grants revoke 1af2cd9 --dry-run
grants revoke 1af2cd9
grants undo
```

```text
$ grants revoke 1af2cd9 --dry-run
Plan: revoke 1 grant in 1 file. Nothing is written until you confirm.

  1af2cd9  remove "Read(~/notes/**)" from permissions.allow
           ~/.claude/settings.json
           - "Bash(git push:*)",
           - "Read(~/notes/**)"
           + "Bash(git push:*)"
           Claude Code applies it on the next tool call.

Dry run. Nothing was changed.
```

## Commands

| Command | What it does |
|---|---|
| `grants` | Summary: what you granted, what needs a look, how to clean up |
| `grants list` | Table of grants. Flags: `--agent`, `--kind rule\|trust`, `--all`, `--risk`, `--flag`, `--json` |
| `grants show <id>` | One grant with its evidence timeline. `--json` |
| `grants log` | Granted, removed, revoked and undone, newest first. Grants with no known date follow in their own section. `--agent`, `--since`, `--all`, `--json` |
| `grants revoke <id>...` | Remove grants. Selectors: `--dead` (points to a deleted path), `--one-off` (approved for a single URL or script), `--unused [days]` (no use in the window). They combine with each other and with ids. `--dry-run`, `--yes` |
| `grants undo` | Restore the files changed by the latest revoke. `--force` |
| `grants scan` | Read the history and show what it covers and how long it took |
| `grants version` | Print the version |

Every command also takes `--no-color`, `--unused <days>` (default 90, at most 36500) and `--no-cache`. With `revoke`, `--unused` also picks the grants that were not used for that long. Run `grants help <command>` for details. Exit codes: 0 success, 1 error, 2 usage error.

## How it works

- **Grants.** A grant is a rule (an allowed command or tool) or a trusted folder. Each one is `active`, `gone` (seen before, removed since) or `unknown` (the file that may hold it cannot be read).
- **Dating.** Agents do not record when you approved something. grants rebuilds the date from the agent's own history: settings backups, session snapshots, first sessions in a folder and file times. It also keeps its own record from the first run on. A date can be a range or an estimate (`~`). When no history shows a lower bound, `grants log` lists the grant under "Dates unknown" with the day it was first seen.
- **Usage.** grants matches each command and tool call in history against your rules. It matches with hashed keys and does not keep your command history. A grant is flagged `unused` when history covers the whole window and nothing matched.
- **Risk.** Each grant is `high`, `medium` or `low`, with reasons. A trusted folder that holds three or more projects is broad: high for Codex, medium for Claude Code. Flags: `dead-path`, `one-off`, `unused`, `secret`, `committed`.

The full design is in [docs/design.md](docs/design.md).

## Safety and privacy

- grants never opens a network connection.
- It is read-only. Only `revoke` and `undo` write, and `revoke` asks first (or use `--dry-run` to only look).
- It edits only the bytes that hold the grant, then parses the file again to check the result.
- It copies each file to its state folder before writing. `grants undo` restores it, and refuses if the file changed since. `--force` restores it anyway and keeps a copy of your newer file.
- It does not store conversation text. The saved state holds hashed usage keys, your rules, and short excerpts (at most 160 characters) of approved commands and agent justifications, with credentials redacted.
- It never edits organization-managed settings.
- State lives in `~/.local/state/grants` (override with `GRANTS_STATE_DIR`).
- On macOS, some folders are protected by privacy controls. Give your terminal Full Disk Access to include them. Without it, grants shows what it could not read.

## Supported agents

| Agent | Covered |
|---|---|
| Claude Code | `permissions.allow` rules in user, project, local and managed settings; trusted folders in `~/.claude.json` |
| Codex | `prefix_rule` allow rules in `rules/*.rules`; trusted folders in `config.toml` |

Not covered yet: modes such as `defaultMode`, `approval_policy` and sandbox settings; MCP servers, plugins and hooks; other agents (Gemini CLI, Cursor, Copilot CLI and more). See the [roadmap](docs/design.md#roadmap).

## License

[MIT](LICENSE)
