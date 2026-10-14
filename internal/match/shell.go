// Package match turns executed commands and tool calls into hashed usage keys, and
// turns grant rules into the keys they would match. Hashing lets grants count how
// often a rule was used without keeping a copy of anyone's command history.
package match

import (
	"path"
	"strings"
)

// maxUnwrap limits how deep `bash -c '...'` scripts are unwrapped.
const maxUnwrap = 3

var shells = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "fish": true}

// Commands splits a shell command line into simple commands, each as unquoted tokens.
//
// It splits on && || ; | & and newlines outside quotes, drops redirections and
// heredoc bodies, strips leading VAR=value assignments and the wrappers timeout,
// nice, nohup, time, command and env. When a command is a shell wrapper such as
// `bash -lc '<script>'`, both the wrapper and the commands inside the script are
// returned, because agents can grant either one.
func Commands(line string) [][]string {
	return commands(line, 0)
}

func commands(line string, depth int) [][]string {
	var out [][]string
	for _, raw := range split(line) {
		cmd := strip(raw)
		if len(cmd) == 0 {
			continue
		}
		out = append(out, cmd)
		if depth < maxUnwrap {
			if script, ok := shellScript(cmd); ok {
				out = append(out, commands(script, depth+1)...)
			}
		}
	}
	return out
}

// shellScript returns the script of `sh -c script` style commands.
func shellScript(cmd []string) (string, bool) {
	if !shells[path.Base(cmd[0])] {
		return "", false
	}
	for i := 1; i < len(cmd)-1; i++ {
		a := cmd[i]
		if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") {
			return "", false
		}
		if a == "-o" || a == "+o" || a == "-O" || a == "+O" || a == "--rcfile" || a == "--init-file" {
			i++ // the option takes a value, which is not the script
			continue
		}
		if strings.HasPrefix(a, "--") || strings.HasPrefix(a, "+") {
			continue
		}
		if strings.Contains(a, "c") {
			return cmd[i+1], true
		}
	}
	return "", false
}

// split tokenizes line and groups tokens into simple commands.
func split(line string) [][]string {
	var (
		cmds     [][]string
		cur      []string
		tok      strings.Builder
		inTok    bool
		heredocs []heredoc
	)
	flushTok := func() {
		if inTok {
			cur = append(cur, tok.String())
			tok.Reset()
			inTok = false
		}
	}
	flushCmd := func() {
		flushTok()
		if len(cur) > 0 {
			cmds = append(cmds, cur)
			cur = nil
		}
	}
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\\' && i+1 < len(rs):
			if rs[i+1] == '\n' { // line continuation
				i++
				continue
			}
			tok.WriteRune(rs[i+1])
			inTok = true
			i++
		case c == '\'':
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			tok.WriteString(string(rs[i+1 : min(j, len(rs))]))
			inTok = true
			i = j
		case c == '"':
			j := i + 1
			for j < len(rs) && rs[j] != '"' {
				if rs[j] == '\\' && j+1 < len(rs) && strings.ContainsRune("\"\\$`", rs[j+1]) {
					tok.WriteRune(rs[j+1])
					j += 2
					continue
				}
				tok.WriteRune(rs[j])
				j++
			}
			inTok = true
			i = j
		case c == '#' && !inTok:
			for i+1 < len(rs) && rs[i+1] != '\n' {
				i++
			}
		case c == '\n':
			flushCmd()
			if len(heredocs) > 0 {
				i = skipHeredocs(rs, i+1, heredocs) - 1
				heredocs = nil
			}
		case c == '$' && i+1 < len(rs) && rs[i+1] == '(': // $(cmd) stays in the word; its commands are listed too
			end := closeParen(rs, i+1)
			if i+2 < len(rs) && rs[i+2] != '(' { // not $(( arithmetic ))
				cmds = append(cmds, split(string(rs[i+2:min(end, len(rs))]))...)
			}
			tok.WriteString(string(rs[i:min(end+1, len(rs))]))
			inTok = true
			i = end
		case c == ';' || c == '|' || c == '&' || c == '(' || c == ')' || c == '`':
			if c == '&' && tok.Len() > 0 && strings.HasSuffix(tok.String(), ">") { // 2>&1, >&2
				tok.WriteRune(c)
				continue
			}
			if c == '(' && (tok.String() == "<" || tok.String() == ">") { // process substitution <(cmd)
				tok.Reset()
				inTok = false
			}
			flushCmd()
		case c == ' ' || c == '\t' || c == '\r':
			flushTok()
		case c == '<' && i+2 < len(rs) && rs[i+1] == '<' && rs[i+2] == '<': // here-string: the next word is its input
			flushTok()
			cur = append(cur, "<")
			i += 2
		case c == '<' && i+1 < len(rs) && rs[i+1] == '<':
			flushTok()
			i += 2
			strip := false
			if i < len(rs) && rs[i] == '-' {
				strip = true
				i++
			}
			for i < len(rs) && (rs[i] == ' ' || rs[i] == '\t') {
				i++
			}
			var word strings.Builder
			for i < len(rs) && !strings.ContainsRune(" \t\n;|&()<>", rs[i]) {
				if rs[i] != '\'' && rs[i] != '"' {
					word.WriteRune(rs[i])
				}
				i++
			}
			i--
			if word.Len() > 0 {
				heredocs = append(heredocs, heredoc{word.String(), strip})
			}
		default:
			tok.WriteRune(c)
			inTok = true
		}
	}
	flushCmd()
	return cmds
}

// closeParen returns the index of the ')' that closes the '(' at open, or len(rs).
func closeParen(rs []rune, open int) int {
	depth := 0
	for j := open; j < len(rs); j++ {
		switch rs[j] {
		case '\\':
			j++
		case '\'':
			for j++; j < len(rs) && rs[j] != '\''; j++ {
			}
		case '"':
			for j++; j < len(rs) && rs[j] != '"'; j++ {
				if rs[j] == '\\' {
					j++
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return len(rs)
}

type heredoc struct {
	delim string
	strip bool // <<- allows leading tabs before the delimiter
}

// skipHeredocs returns the index just past the bodies of the pending heredocs.
func skipHeredocs(rs []rune, i int, docs []heredoc) int {
	for _, d := range docs {
		for i < len(rs) {
			j := i
			for j < len(rs) && rs[j] != '\n' {
				j++
			}
			l := string(rs[i:j])
			if d.strip {
				l = strings.TrimLeft(l, "\t")
			}
			i = j + 1
			if strings.TrimRight(l, " \r") == d.delim {
				break
			}
		}
	}
	return min(i, len(rs))
}

// strip removes redirections, leading assignments and transparent wrappers.
func strip(tokens []string) []string {
	var out []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if op, attached := redirection(t); op {
			if !attached {
				i++ // the target is the next token
			}
			continue
		}
		out = append(out, t)
	}
	for len(out) > 0 {
		w := wrapperName(out[0])
		switch {
		case isAssignment(out[0]):
			out = out[1:]
		case w == "nohup" || w == "time" || w == "command" || w == "builtin":
			out = out[1:]
		case syntaxWords[w]: // if/then/do/{ ... : the command follows
			out = out[1:]
		case blockWords[w]: // for x in ...; case ...: a header, not a command
			return nil
		case w == "env":
			out = out[1:]
			for len(out) > 0 && (isAssignment(out[0]) || strings.HasPrefix(out[0], "-")) {
				if (out[0] == "-u" || out[0] == "-C") && len(out) > 1 {
					out = out[1:]
				}
				out = out[1:]
			}
		case w == "nice":
			out = out[1:]
			if len(out) > 1 && out[0] == "-n" {
				out = out[2:]
			} else if len(out) > 0 && strings.HasPrefix(out[0], "-") {
				out = out[1:]
			}
		case w == "timeout":
			out = out[1:]
			for len(out) > 0 && strings.HasPrefix(out[0], "-") {
				if (out[0] == "-s" || out[0] == "-k" || out[0] == "--signal" || out[0] == "--kill-after") && len(out) > 1 {
					out = out[1:]
				}
				out = out[1:]
			}
			if len(out) > 0 { // duration
				out = out[1:]
			}
		default:
			return out
		}
	}
	return out
}

// syntaxWords are shell keywords that only introduce the real command after them.
var syntaxWords = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "{": true, "!": true}

// blockWords are keywords whose line holds no command, or only loop and case headers.
var blockWords = map[string]bool{"fi": true, "done": true, "esac": true, "}": true, "for": true,
	"select": true, "case": true, "in": true, ";;": true, "function": true}

// wrapperName returns the name used to recognize a wrapper: the base name of a path.
func wrapperName(t string) string {
	if strings.Contains(t, "/") && !isAssignment(t) {
		return path.Base(t)
	}
	return t
}

// redirection reports whether t is a redirection operator, and whether its target is
// attached to it (">out", "2>&1") rather than in the next token.
func redirection(t string) (op, attached bool) {
	s := strings.TrimLeft(t, "0123456789")
	if strings.HasPrefix(s, "&>") {
		s = s[2:]
	} else {
		var ok bool
		for _, p := range []string{">>", ">|", "<>", ">&", "<&", ">", "<"} {
			if strings.HasPrefix(s, p) {
				s, ok = s[len(p):], true
				break
			}
		}
		if !ok {
			return false, false
		}
		if s == "" && strings.HasSuffix(t, "&") { // "2>&" followed by fd
			return true, false
		}
	}
	if len(s) > 0 && s[0] == '>' { // ">>"-like leftovers
		s = s[1:]
	}
	return true, s != ""
}

func isAssignment(t string) bool {
	eq := strings.IndexByte(t, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range t[:eq] {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// Tokens splits s into shell words without splitting it into commands. Used for
// rule specifiers such as `git commit -m *`.
func Tokens(s string) []string {
	var out []string
	for _, c := range split(s) {
		out = append(out, c...)
	}
	return out
}
