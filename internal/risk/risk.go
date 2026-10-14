// Package risk rates how much a grant lets an agent do and flags grants that look stale.
package risk

import (
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
)

// maxExpansions caps how many alternatives of a Codex pattern are classified.
const maxExpansions = 64

// Assess sets g.Risk and adds the flags it can decide from the grant alone:
// FlagSecret, FlagOneOff and FlagDeadPath. exists reports whether a path exists.
// It keeps flags set elsewhere (FlagUnused, FlagCommitted) and never adds a flag twice.
func Assess(g *model.Grant, env model.Env, exists func(path string) bool) {
	if exists == nil {
		exists = func(string) bool { return true }
	}
	var (
		v      verdict
		oneOff bool
		dead   bool
	)
	switch {
	case g.Kind == model.KindTrust:
		dead = assessTrust(g, env, exists, &v)
	case g.Agent == model.Codex || g.Tool == "exec":
		oneOff, dead = assessCodex(g, env, exists, &v)
	default:
		oneOff, dead = assessClaude(g, env, exists, &v)
	}
	if hasURLPath(g.Value) {
		oneOff = true
	}
	if hasSecret(g.Value) || hasSecret(shellQuote(flatten(g.Pattern))) {
		g.Flags = addFlag(g.Flags, model.FlagSecret)
		v.add(model.RiskHigh, "contains a credential")
	}
	if oneOff {
		g.Flags = addFlag(g.Flags, model.FlagOneOff)
	}
	if dead {
		g.Flags = addFlag(g.Flags, model.FlagDeadPath)
	}
	g.Risk = v.result()
}

func hasSecret(s string) bool { return Redact(s) != s }

// flatten lists every alternative of every position, for text checks.
func flatten(pattern [][]string) []string {
	var out []string
	for _, alts := range pattern {
		out = append(out, alts...)
	}
	return out
}

func addFlag(flags []model.Flag, f model.Flag) []model.Flag {
	for _, x := range flags {
		if x == f {
			return flags
		}
	}
	return append(flags, f)
}

// assessTrust rates a trusted folder and reports whether the folder is missing.
func assessTrust(g *model.Grant, env model.Env, exists func(string) bool, v *verdict) (dead bool) {
	dir := filepath.Clean(g.Value)
	home := ""
	if env.Home != "" {
		home = filepath.Clean(env.Home)
	}
	switch {
	case g.Value == "":
		v.add(model.RiskLow, "no folder recorded")
		return false
	case dir == "/" || (home != "" && fsx.Within(home, dir)):
		// the folder is the root, the home folder, or a folder that holds the home folder
		v.add(model.RiskHigh, "trusts a very broad folder")
	case home != "" && isBroadHomeFolder(dir, home):
		v.add(model.RiskHigh, "trusts a broad personal folder")
	default:
		if file := configFile(g.Agent, dir, exists); file != "" {
			v.add(model.RiskMedium, "the folder can change how the agent runs code ("+file+")")
		} else {
			v.add(model.RiskLow, "limited to one folder")
		}
	}
	return !exists(dir)
}

func isBroadHomeFolder(dir, home string) bool {
	for _, p := range []string{"Documents", "Desktop", "Downloads", "Library", "Library/Mobile Documents"} {
		if dir == filepath.Join(home, p) {
			return true
		}
	}
	return false
}

// configFile returns the first agent config file in dir that can run code.
func configFile(agent model.Agent, dir string, exists func(string) bool) string {
	files := []string{".claude/settings.json", ".claude/settings.local.json", ".mcp.json"}
	if agent == model.Codex {
		files = []string{".codex/config.toml", ".codex/rules", ".codex/hooks.json"}
	}
	for _, f := range files {
		if exists(filepath.Join(dir, f)) {
			return f
		}
	}
	return ""
}

// assessCodex classifies every expansion of a prefix_rule pattern.
func assessCodex(g *model.Grant, env model.Env, exists func(string) bool, v *verdict) (oneOff, dead bool) {
	pattern := g.Pattern
	if len(pattern) == 0 {
		for _, t := range match.Tokens(g.Value) {
			pattern = append(pattern, []string{t})
		}
	}
	if len(pattern) > 6 {
		oneOff = true
	}
	for _, combo := range expand(pattern) {
		classifyArgv(combo, v)
		if tooLong(combo) {
			oneOff = true
		}
		if hasScript(combo) {
			oneOff = true
		}
	}
	if len(pattern) > 0 {
		for _, prog := range pattern[0] {
			if deadProgram(prog, env, exists) {
				dead = true
			}
		}
	}
	return oneOff, dead
}

// expand lists the token sequences a pattern allows, capped at maxExpansions.
func expand(pattern [][]string) [][]string {
	combos := [][]string{nil}
	for _, alts := range pattern {
		var next [][]string
		for _, c := range combos {
			for _, a := range alts {
				if len(next) >= maxExpansions {
					break
				}
				next = append(next, append(append([]string(nil), c...), a))
			}
		}
		if len(next) > 0 {
			combos = next
		}
	}
	if len(combos) == 1 && len(combos[0]) == 0 {
		return nil
	}
	return combos
}

// classifyArgv rates one token sequence. The tokens are quoted into a command line
// first so that the shell splitter in match handles wrappers the same way it does for Claude rules.
func classifyArgv(tokens []string, v *verdict) {
	if len(tokens) == 0 {
		return
	}
	if len(tokens) == 1 && path.Base(tokens[0]) == "env" {
		v.add(model.RiskHigh, "env can run any program")
		return
	}
	cmds := match.Commands(shellQuote(tokens))
	if len(cmds) == 0 {
		v.add(model.RiskMedium, "unrecognized command")
		return
	}
	classifyCommands(cmds, v)
}

func shellQuote(tokens []string) string {
	q := make([]string, len(tokens))
	for i, t := range tokens {
		q[i] = "'" + strings.ReplaceAll(t, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

func tooLong(tokens []string) bool {
	for _, t := range tokens {
		if len([]rune(t)) > 60 {
			return true
		}
	}
	return false
}

// hasScript reports whether the command is a shell with a literal script argument.
func hasScript(tokens []string) bool {
	if len(tokens) < 3 || !shellNames[path.Base(tokens[0])] {
		return false
	}
	for i, a := range tokens[1 : len(tokens)-1] {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "c") {
			return len(tokens[i+2]) > 0
		}
	}
	return false
}

// deadProgram reports whether prog is an absolute or ~/ path that does not exist.
func deadProgram(prog string, env model.Env, exists func(string) bool) bool {
	switch {
	case strings.HasPrefix(prog, "~/"):
		if env.Home == "" {
			return false
		}
		return !exists(filepath.Join(env.Home, prog[2:]))
	case strings.HasPrefix(prog, "/"):
		return !exists(prog)
	}
	return false
}

var urlRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s'"` + "`" + `]+`)

// hasURLPath reports whether text names a URL with a path or a query, which points at
// one specific page and usually means a single approval was kept.
func hasURLPath(text string) bool {
	for _, m := range urlRe.FindAllString(text, -1) {
		u, err := url.Parse(m)
		if err != nil {
			continue
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return true
		}
	}
	return false
}
