# grants design

grants is a local ledger of the permissions you have given AI coding agents. It finds every standing grant, dates it from the agent's own local history, shows how often it is used, and removes it safely when you no longer need it.

## Principles

- **Local only.** grants never opens a network connection.
- **Read-only by default.** Only `revoke` and `undo` write. `revoke` shows a plan and asks first. `undo` restores only files that have not changed since the revoke, unless you pass `--force`.
- **Change only what you asked for.** Edits touch the bytes that hold the grant, are checked by parsing the file again, and are backed up first. `grants undo` restores the backup.
- **No copy of your history.** grants reads session transcripts to date grants and measure use. Its cache keeps hashed usage keys and short, redacted excerpts (approved commands up to 120 characters, Codex justifications up to 160), never conversation text.
- **Show what can't be known.** When a date is a range or an estimate, the output says so.

## What counts as a grant

| Kind | Claude Code | Codex |
|---|---|---|
| rule | `permissions.allow` entries in user, project, local, managed and legacy settings | `prefix_rule(..., decision="allow")` in `rules/*.rules`, user and project layers |
| trust | `projects[<path>].hasTrustDialogAccepted` in `~/.claude.json` | `[projects."<path>"] trust_level = "trusted"` in `config.toml` |

Each grant has a status: `active` (in config now), `gone` (seen in history, removed since), or `unknown` (seen in history, but the file that may hold it cannot be read, for example a folder protected by macOS privacy controls).

Modes (`defaultMode`, `approval_policy`, `sandbox_mode`), MCP servers, plugins, hooks and other agents are on the [roadmap](#roadmap).

## Dating a grant

Agents do not record when you clicked "always allow". grants rebuilds it from point-in-time observations of whether a grant was present:

| Agent | Source | What it shows |
|---|---|---|
| Codex | "approved command prefixes" snapshot written into each session | the rule set at session start, from the first session on |
| Codex | escalation requests in sessions (`prefix_rule` proposals) | when the agent first asked for the rule and why |
| Codex | first session whose working folder is the trusted path | approximate trust date (the desktop app trusts on first use) |
| Claude Code | file-history backups of settings files, Edit/Write tool results on settings files | settings content before and after each agent edit |
| Claude Code | `permissionDecision` records with source `user_permanent` | the moment you chose "don't ask again" (recent versions) |
| Claude Code | first session in a project (transcripts, desktop sessions, prompt history) | approximate trust date |
| both | backup files next to config files, git history of committed settings, file birth and modification times | more snapshots and bounds |
| grants | its own snapshot of what it saw on each run | dates for new grants and removals from the first run on, even after agents clean up old sessions |

The grant was created after the latest snapshot where it is absent and at or before the first snapshot where it is present. The output shows one date when that window is narrow, a range when it is wide, and "before <date>" when no earlier snapshot exists.

A grant with no lower bound and no estimate has an unknown date: the only fact is that it existed by a day. `grants log` keeps these out of the dated list. It prints them after it, in a section "Dates unknown; these existed by:", with one line per day (a count and up to 3 grants; `--all` lists each one). In JSON, such an event has `"existence_only": true`.

## Measuring use

For each tool call or command in history, grants stores hashed keys: one per command prefix (up to 8 words), one for the whole command, one per folder for file tools, one per host for web fetches, one per tool and MCP server. A rule is turned into the same kind of key, so counting its use is a lookup. Rules whose wildcards cannot be expressed as keys show usage as unknown.

A grant is flagged `unused` when its use is measurable, history covers the whole unused window (90 days by default, `--unused <days>`), nothing matched in it, and the grant is older than the window. A grant with no known date counts as old. Only active grants get the flag.

## Risk

Each grant gets `high`, `medium` or `low` with reasons, plus flags:

A trusted folder that holds three or more known projects is broad. A project is another trusted folder of either agent inside it, or a git repository directly inside it. A broad Codex folder is `high` (every project inside inherits the trust). A broad Claude Code folder is at least `medium` (folders inside it share the trust). Core counts the projects after it has the whole grant list.

Flags:

- `dead-path`: the rule or trusted folder points to a path that no longer exists. Only active grants carry it.
- `one-off`: a rule that names a specific URL, script or long argument list, which usually means a single approval was kept forever.
- `unused`: no matching use in the unused window.
- `secret`: the rule text contains something that looks like a credential.
- `committed`: the rule lives in a git-tracked team file; revoking it changes the repository.

## Revoking

| Grant | Edit | Takes effect |
|---|---|---|
| Claude rule | remove the string from the `allow` array | next tool call (Claude Code reloads settings) |
| Claude trust | set `hasTrustDialogAccepted` to `false` | next session |
| Codex rule | delete the `prefix_rule(...)` statement | after restarting Codex |
| Codex trust | set `trust_level = "untrusted"`; delete the table when the folder no longer exists | after restarting Codex |

Grants in the same file are planned together, so several grants in one file become one edit. A selector (`--dead`, `--one-off`, `--unused [days]`) plans each grant on its own, so one stale grant does not block the rest. A selector picks every active grant that grants can edit and that has its flag. Selectors combine with each other and with ids, and a grant that matches more than one is revoked once. The plan and the confirmation are the same for every selector. Managed (organization) settings are never edited. Codex trust is set to `untrusted` instead of deleted because the Codex desktop app trusts any folder with no decision again on its next thread.

Before writing, grants copies each file to `<state>/backups/<batch>/` and checks the file still has the content it planned against. `grants undo` restores the latest batch if the files have not changed since.

## Summary

`grants` with no command prints a headline, a table, then two lists:

- **Needs a look**: active grants that are high risk or hold a credential (`secret`). A grant flagged `dead-path` or `one-off` that grants can revoke moves to Clean up, unless it holds a credential. Credentials always stay in view.
- **Clean up**: the bulk commands. Each count is what the command next to it would select, so a grant with two flags is in two counts: `dead-path` (`grants revoke --dead`), `one-off` (`grants revoke --one-off`) and `unused` (`grants revoke --unused`, with the number of days when it is not 90). The list shows the backup, preview and undo hint once.

## Display

- A Codex rule shows its tokens joined by spaces. A token is quoted only when it holds white space (double quotes, or single quotes when it holds a double quote). The text is for reading. Keys and revoke use the real pattern.
- A value that is too long for its column is cut in two steps: each URL in it becomes `scheme://host/…/last-segment` (no query), then the middle is cut.
- The GRANT column gets width first. In `grants list` the scope column shrinks first (`project …/<last segment>`) and goes last of all.
- `grants show` prints evidence files relative to the agent home (`sessions/2026/…`) and wraps them to the terminal width.

## Storage

State lives in `$GRANTS_STATE_DIR`, default `~/.local/state/grants`:

- `cache-*.gob`: per-file history results, keyed by path, size, modification time, inode and a hash of the first 4 KB.
- `seen.json`: which grants each run saw, and when. It keeps each grant's rule text or folder with credentials redacted, never a full command history. A grant seen before and absent now is shown as `gone`, with a removal window. A grant with no adapter date is dated from the previous run to now, with the source "first seen by grants".
- `journal.jsonl`, `backups/`: every revoke and undo.

## Roadmap

1. Modes and wider access: Claude `defaultMode`, bypass acceptance, `additionalDirectories`, sandbox settings; Codex `approval_policy`, `sandbox_mode`, `writable_roots`, network access, desktop agent mode.
2. Extensions: MCP servers and tool approvals, plugins, hooks, Codex automations and computer-use app allowlists.
3. Review: `grants review` walks through new, risky and unused grants; an optional weekly reminder.
4. More agents: Gemini CLI, Cursor, GitHub Copilot CLI, VS Code, opencode.
5. Grants outside files: manual entries and import for chat connectors and OAuth apps, and links to where each can be revoked.
