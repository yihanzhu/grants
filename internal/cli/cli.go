// Package cli is the grants command line: argument parsing, and every message the
// user reads.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

// Version is set by main from the build.
var Version = "dev"

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// stdinIsTerminal tells revoke whether it can ask a question. Tests replace it.
var stdinIsTerminal = func(r io.Reader) bool { return isTerminal(r) }

type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	st     style
}

type command struct {
	name  string
	short string // one line for the help list
	run   func(a *app, args []string) int
}

var commands []command

func init() {
	commands = []command{
		{"list", "Show every grant in a table", (*app).cmdList},
		{"show", "Show one grant with its evidence", (*app).cmdShow},
		{"log", "Show when grants were given, removed and revoked", (*app).cmdLog},
		{"revoke", "Remove grants from the agent config files", (*app).cmdRevoke},
		{"undo", "Restore the files changed by the last revoke", (*app).cmdUndo},
		{"scan", "Read the history and show what it covers", (*app).cmdScan},
		{"version", "Print the version", (*app).cmdVersion},
	}
}

// Main runs grants and returns the exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "grants: unexpected failure: %v\n", r)
			code = exitError
		}
	}()
	if len(args) == 0 {
		return a.cmdSummary(args)
	}
	if strings.HasPrefix(args[0], "-") && !isHelp(args[0]) && !isVersionFlag(args[0]) {
		// Flags before the command, as in "grants --no-color list": find the command
		// and move it to the front. Every command takes its flags in any position.
		i := leadingFlags(args)
		if i == len(args) || !isCommandName(args[i]) {
			return a.cmdSummary(args)
		}
		args = append([]string{args[i]}, append(append([]string{}, args[:i]...), args[i+1:]...)...)
	}
	name, rest := args[0], args[1:]
	switch {
	case name == "help" || isHelp(name):
		return a.cmdHelp(rest)
	case isVersionFlag(name):
		return a.cmdVersion(nil)
	}
	for _, c := range commands {
		if c.name == name {
			return c.run(a, rest)
		}
	}
	fmt.Fprintf(stderr, "grants: unknown command %q\nRun grants help to see the commands.\n", name)
	return exitUsage
}

// leadingFlags returns the index of the first argument that is not a flag. The
// number after --unused belongs to it, but a word such as a command name does not.
func leadingFlags(args []string) int {
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		f := strings.TrimLeft(args[i], "-")
		i++
		if f == "unused" && i < len(args) {
			if _, err := strconv.Atoi(args[i]); err == nil {
				i++
			}
		}
	}
	return i
}

func isCommandName(s string) bool {
	if s == "help" {
		return true
	}
	for _, c := range commands {
		if c.name == s {
			return true
		}
	}
	return false
}

func isHelp(s string) bool {
	return s == "-h" || s == "--help" || s == "-help"
}

func isVersionFlag(s string) bool { return s == "--version" || s == "-version" }

// globals are the flags every command takes.
type globals struct {
	noColor bool
	noCache bool
	unused  int
}

const defaultUnusedDays = int(core.DefaultUnusedAfter / (24 * time.Hour))

// maxUnusedDays keeps the window far from overflowing a time.Duration.
const maxUnusedDays = 36500

func (g *globals) register(fs *flag.FlagSet) {
	g.registerBase(fs)
	fs.IntVar(&g.unused, "unused", defaultUnusedDays, "")
}

// registerBase registers the flags every command takes except --unused, for commands
// that read --unused in their own way (revoke).
func (g *globals) registerBase(fs *flag.FlagSet) {
	fs.BoolVar(&g.noColor, "no-color", false, "")
	fs.BoolVar(&g.noCache, "no-cache", false, "")
	g.unused = defaultUnusedDays
}

// parse reads flags that may come before or after the other arguments. done is true
// when the command must stop with code (help was shown, or the flags were wrong).
func (a *app) parse(name, usage string, fs *flag.FlagSet, g *globals, args []string) (rest []string, code int, done bool) {
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(a.stdout, usage)
				return nil, exitOK, true
			}
			fmt.Fprintf(a.stderr, "grants %s: %v\nRun grants help %s for usage.\n", name, err, name)
			return nil, exitUsage, true
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		rest = append(rest, args[0])
		args = args[1:]
	}
	if g != nil {
		if g.unused < 1 || g.unused > maxUnusedDays {
			fmt.Fprintf(a.stderr, "grants %s: --unused needs a number of days, 1 to %d\n", name, maxUnusedDays)
			return nil, exitUsage, true
		}
		a.st = style{on: !g.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(a.stdout)}
	}
	return rest, exitOK, false
}

// collect reads every agent. It shows a progress line on a terminal when the read is slow.
func (a *app) collect(g *globals) (core.Result, int) {
	env, err := core.EnvFromOS(time.Duration(g.unused) * 24 * time.Hour)
	if err != nil {
		fmt.Fprintf(a.stderr, "grants: %v\n", err)
		return core.Result{}, exitError
	}
	opt := scan.Options{NoCache: g.noCache}
	if isTerminal(a.stderr) {
		p := startProgress(a.stderr, termWidth(a.stderr))
		defer p.finish()
		opt.Progress = p.update
	}
	res, err := core.Run(env, opt)
	if err != nil {
		fmt.Fprintf(a.stderr, "grants: %v\n", err)
		return res, exitError
	}
	return res, exitOK
}

func (a *app) fail(format string, args ...any) int {
	fmt.Fprintf(a.stderr, "grants: "+format+"\n", args...)
	return exitError
}

// resolve finds a grant by a unique id prefix of at least 4 characters.
func resolve(grants []model.Grant, q string, home string) (model.Grant, error) {
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) < 4 {
		return model.Grant{}, fmt.Errorf("%q is too short for an id: give at least 4 characters (see grants list)", q)
	}
	var hits []model.Grant
	for _, g := range grants {
		if g.ID == q {
			return g, nil
		}
		if strings.HasPrefix(g.ID, q) {
			hits = append(hits, g)
		}
	}
	switch len(hits) {
	case 0:
		return model.Grant{}, fmt.Errorf("no grant has the id %q (grants list --all shows every id)", q)
	case 1:
		return hits[0], nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "the id %q matches %s; give more characters:", q, plural(len(hits), "grant", "grants"))
	for i, g := range hits {
		if i == 6 {
			fmt.Fprintf(&sb, "\n  ... and %d more", len(hits)-i)
			break
		}
		fmt.Fprintf(&sb, "\n  %s  %s  %s", g.ID, g.Agent, truncMiddle(grantText(g, home), 60))
	}
	return model.Grant{}, errors.New(sb.String())
}

func (a *app) cmdVersion(args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(a.stderr, "grants version: unexpected argument %q\nRun grants help version for usage.\n", args[0])
		return exitUsage
	}
	fmt.Fprintf(a.stdout, "grants %s\n", Version)
	return exitOK
}
