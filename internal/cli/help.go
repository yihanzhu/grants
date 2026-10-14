package cli

import (
	"fmt"
	"strings"
)

const globalFlags = `
Flags for every command:
  --no-color      no colors (also off when output is not a terminal, or NO_COLOR is set)
  --unused DAYS   a grant with no use for this long is flagged unused (default 90)
  --no-cache      read all history again instead of using the saved results
`

const overview = `grants lists and revokes the permissions you gave AI coding agents.

Usage: grants [command] [flags]

  (no command)   Summary: what you granted, what is risky or stale, how to clean up
`

var usages = map[string]string{
	"summary": `Usage: grants

Shows how many grants you have, which ones need a look (high risk or a credential),
and the commands that clean up in bulk: deleted paths, one-off rules, unused grants.
` + globalFlags,
	"list": `Usage: grants list [flags]

Shows grants in a table.

Flags:
  --agent NAME    claude-code or codex
  --kind KIND     rule or trust
  --all           include grants that are gone or cannot be checked
  --risk LEVEL    show this risk level and above: high, medium or low
  --flag NAME     dead-path, unused, one-off, secret or committed
  --json          print JSON
` + globalFlags,
	"show": `Usage: grants show <id> [--json]

Shows one grant: where it lives, when it was given, how it was used, its risk, and the
evidence for its date. An id can be shortened to 4 characters if it stays unique.
` + globalFlags,
	"log": `Usage: grants log [flags]

Shows what happened to grants, newest first: granted, removed, revoked, undone.

Some grants have no known date. No history shows when they were given, only that they
existed by a day (the day grants first saw them, or when their file last changed).
grants log lists them in a separate section, one line per day. --all lists each one.

Flags:
  --agent NAME       claude-code or codex
  --since YYYY-MM-DD only events on or after this day
  --all              list every grant whose date is unknown, not one line per day
  --json             print JSON (existence_only marks events with no known date)
` + globalFlags,
	"revoke": `Usage: grants revoke <id>... [flags]
       grants revoke --dead | --one-off | --unused [DAYS] [flags]

Removes grants from the agent config files. grants shows the plan, then asks.
Each file is backed up first. grants undo puts the files back.

The selectors pick active grants that grants can edit. They combine with each other
and with ids; a grant that matches several is revoked once.

Flags:
  --dead          revoke every grant that points to a deleted path
  --one-off       revoke every rule approved for a single URL, script or long command
  --unused [DAYS] revoke every grant with no use in the last DAYS days (default 90)
  --dry-run       show the plan and stop
  --yes           do not ask
` + globalFlags,
	"undo": `Usage: grants undo [--force]

Restores the files changed by the latest revoke. If one of them changed since, grants
stops and tells you which. --force restores it anyway.
` + globalFlags,
	"scan": `Usage: grants scan [flags]

Reads the agents' files and history, then shows what was read and how long it took.
` + globalFlags,
	"version": "Usage: grants version\n",
}

func (a *app) cmdHelp(args []string) int {
	if len(args) > 0 {
		if u, ok := usages[args[0]]; ok {
			fmt.Fprint(a.stdout, u)
			return exitOK
		}
		fmt.Fprintf(a.stderr, "grants: no help for %q\n", args[0])
		return exitUsage
	}
	var sb strings.Builder
	sb.WriteString(overview)
	for _, c := range commands {
		fmt.Fprintf(&sb, "  %-14s %s\n", c.name, c.short)
	}
	sb.WriteString("  help           Show this list, or help for one command\n")
	sb.WriteString("\nRun grants help <command> for the flags of one command.\n")
	sb.WriteString(globalFlags)
	fmt.Fprint(a.stdout, sb.String())
	return exitOK
}
