package risk

import (
	"path/filepath"
	"strings"
	"unicode"

	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
)

// assessClaude rates a Claude Code permission rule such as Bash(git push:*).
func assessClaude(g *model.Grant, env model.Env, exists func(string) bool, v *verdict) (oneOff, dead bool) {
	r := match.ParseClaudeRule(g.Value)
	if r.Tool == "" {
		r.Tool = g.Tool
	}
	spec := strings.TrimSpace(r.Spec)
	anything := !r.HasSpec || spec == "" || spec == "*"

	switch {
	case r.Tool == "Bash":
		if anything {
			v.add(model.RiskHigh, "allows any command")
			return false, false
		}
		return assessBash(spec, env, exists, v)
	case isEditTool(r.Tool):
		if anything {
			v.add(model.RiskHigh, "allows editing any file")
			return false, false
		}
		return false, assessPath(g, env, exists, spec, true, v)
	case r.Tool == "Read":
		if anything {
			v.add(model.RiskMedium, "allows reading any file")
			return false, false
		}
		return false, assessPath(g, env, exists, spec, false, v)
	case r.Tool == "WebFetch":
		switch {
		case anything || spec == "domain:*":
			v.add(model.RiskHigh, "allows fetching any website")
		default:
			v.add(model.RiskLow, "fetches from a named site")
		}
	case r.Tool == "WebSearch":
		v.add(model.RiskLow, "web search only")
	case strings.HasPrefix(r.Tool, "mcp__"):
		assessMCP(r.Tool, v)
	default:
		v.add(model.RiskMedium, "unrecognized tool")
	}
	return false, false
}

func isEditTool(tool string) bool {
	switch tool {
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		return true
	}
	return false
}

// assessBash rates the specifier of a Bash rule: a command prefix, an exact command,
// or a pattern with wildcards.
func assessBash(spec string, env model.Env, exists func(string) bool, v *verdict) (oneOff, dead bool) {
	body := spec
	switch {
	case strings.HasSuffix(body, ":*"):
		body = strings.TrimSuffix(body, ":*")
	case strings.HasSuffix(body, " *"):
		body = strings.TrimSuffix(body, " *")
	case strings.HasSuffix(body, "*"):
		body = strings.TrimSuffix(body, "*")
		v.add(model.RiskMedium, "wildcard inside the command")
	}
	if strings.Contains(body, "*") {
		v.add(model.RiskMedium, "wildcard inside the command")
	}
	body = strings.TrimSpace(body)
	if body == "" {
		v.add(model.RiskHigh, "allows any command")
		return false, false
	}
	tokens := match.Tokens(body)
	if len(tokens) > 6 {
		oneOff = true
	}
	if tooLong(tokens) {
		oneOff = true
	}
	cmds := match.Commands(body)
	switch {
	case len(tokens) == 1 && filepath.Base(tokens[0]) == "env":
		v.add(model.RiskHigh, "env can run any program")
	case len(cmds) == 0:
		v.add(model.RiskMedium, "unrecognized command")
	default:
		classifyCommands(cmds, v)
	}
	for _, c := range cmds {
		if hasScript(c) {
			oneOff = true
		}
		if deadProgram(c[0], env, exists) {
			dead = true
		}
	}
	return oneOff, dead
}

// assessPath rates a Read, Edit or Write rule and reports whether its folder is missing.
func assessPath(g *model.Grant, env model.Env, exists func(string) bool, spec string, write bool, v *verdict) (dead bool) {
	base := match.RuleBase{Home: env.Home, Settings: g.Project, Project: g.Project}
	if g.Scope == model.ScopeUser || g.Project == "" {
		base.Settings = env.ClaudeDir
	}
	if base.Project == "" {
		base.Project = env.Home
	}
	abs := match.ResolvePath(spec, base)
	dir := strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(abs, "**"), "*"), "/")
	if dir == "" {
		dir = "/"
	}
	relative := !strings.HasPrefix(spec, "/") && !strings.HasPrefix(spec, "~")

	switch {
	case spec == "**":
		v.add(model.RiskHigh, "matches every file")
	case dir == "/" || (env.Home != "" && filepath.Clean(env.Home) == dir):
		v.add(model.RiskHigh, "covers the whole disk or home folder")
	default:
		if why := sensitive(abs, env.Home); why != "" {
			v.add(model.RiskHigh, why)
		} else if inProject(g, abs, relative) {
			v.add(model.RiskLow, "limited to the project folder")
		} else if write {
			v.add(model.RiskMedium, "edits files outside the project")
		} else if broadRead(dir, env.Home) {
			v.add(model.RiskMedium, "reads a whole folder tree outside the project")
		} else {
			v.add(model.RiskLow, "reads files outside the project")
		}
	}
	return !exists(baseFolder(abs, !write))
}

// inProject reports whether abs lies inside the grant's project folder.
func inProject(g *model.Grant, abs string, relative bool) bool {
	if g.Project != "" {
		return fsx.Within(strings.TrimSuffix(abs, "/**"), g.Project)
	}
	return relative
}

// broadRead reports whether dir is a folder directly under home (like ~/code) that
// probably holds many projects.
func broadRead(dir, home string) bool {
	if home == "" {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(home), dir)
	return err == nil && rel != "." && !strings.HasPrefix(rel, "..") && !strings.Contains(rel, string(filepath.Separator))
}

// baseFolder returns the path whose existence decides dead-path: the part of abs before
// the first glob character, or the path itself when readable files count, else its folder.
func baseFolder(abs string, pathItself bool) string {
	if i := strings.IndexAny(abs, "*?["); i >= 0 {
		return filepath.Dir(abs[:i] + "x")
	}
	if pathItself {
		return abs
	}
	return filepath.Dir(abs)
}

var homeSecretDirs = map[string]bool{".ssh": true, ".aws": true, ".gnupg": true, ".config": true, ".netrc": true}

// sensitive explains why abs holds credentials or private config, or returns "".
func sensitive(abs, home string) string {
	const why = "reaches credentials or private config"
	if home != "" {
		if rel, err := filepath.Rel(filepath.Clean(home), abs); err == nil && !strings.HasPrefix(rel, "..") {
			if homeSecretDirs[strings.Split(rel, string(filepath.Separator))[0]] {
				return why
			}
		}
	}
	for _, c := range strings.Split(abs, string(filepath.Separator)) {
		switch {
		case c == ".ssh" || c == ".aws" || c == ".gnupg" || c == "Keychains":
			return why
		case strings.HasSuffix(c, ".keychain") || strings.HasSuffix(c, ".keychain-db"):
			return why
		}
	}
	b := filepath.Base(strings.TrimRight(abs, "*/"))
	switch b {
	case ".netrc", ".npmrc", ".pypirc", ".git-credentials", "id_rsa", "id_ed25519":
		return why
	}
	if b == ".env" || strings.HasPrefix(b, ".env.") || strings.HasSuffix(b, ".env") {
		for _, ok := range []string{".example", ".sample", ".template"} {
			if strings.HasSuffix(b, ok) {
				return ""
			}
		}
		return "reaches .env files, which usually hold secrets"
	}
	return ""
}

// changeVerbs mark MCP tools that write, send or run things.
var changeVerbs = []string{"delete", "remove", "drop", "push", "send", "write", "create", "update",
	"exec", "run", "merge", "deploy", "post", "edit", "kill", "apply", "upload", "commit", "patch",
	"put", "install", "reset", "revoke", "grant", "move", "rename", "publish"}

func assessMCP(tool string, v *verdict) {
	name := strings.TrimPrefix(tool, "mcp__")
	_, rest, hasTool := strings.Cut(name, "__")
	switch {
	case !hasTool || rest == "*":
		v.add(model.RiskMedium, "allows every tool of an MCP server")
	case strings.Contains(rest, "*"):
		v.add(model.RiskMedium, "wildcard inside the tool name")
	default:
		for _, w := range words(rest) {
			for _, verb := range changeVerbs {
				if strings.HasPrefix(w, verb) {
					v.add(model.RiskMedium, "MCP tool that can change things ("+verb+")")
					return
				}
			}
		}
		v.add(model.RiskLow, "MCP tool that looks read-only")
	}
}

// words splits a tool name such as createIssue or delete-file into lower-case words.
func words(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	for _, r := range s {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}
