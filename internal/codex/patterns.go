package codex

import (
	"encoding/json"
	"strings"
)

// maxExpansions caps how many concrete prefixes one pattern may expand to. Real
// patterns have a handful; the cap keeps a hostile rules file from exploding.
const maxExpansions = 64

// PatternJSON is the canonical key form of a pattern: a compact JSON array with one
// element per position. A position with a single alternative is a string and a
// position with several is an array of strings. A history snapshot lists a prefix as
// plain tokens, so for patterns without alternatives this is the same text.
func PatternJSON(p [][]string) string {
	out := make([]any, len(p))
	for i, alts := range p {
		if len(alts) == 1 {
			out[i] = alts[0]
		} else {
			out[i] = alts
		}
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false) // keep & < > readable in keys
	if err := enc.Encode(out); err != nil {
		return "[]"
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

// PatternDisplay shows a pattern as shell words, with alternatives as a|b.
func PatternDisplay(p [][]string) string {
	words := make([]string, len(p))
	for i, alts := range p {
		q := make([]string, len(alts))
		for j, a := range alts {
			q[j] = shellQuote(a)
		}
		words[i] = strings.Join(q, "|")
	}
	return strings.Join(words, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_@%+=:,./-~", r):
		default:
			safe = false
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// expand lists every concrete token sequence a pattern accepts. It returns nil when
// the pattern is empty or has more than maxExpansions sequences.
func expand(p [][]string) [][]string {
	if len(p) == 0 {
		return nil
	}
	combos := [][]string{nil}
	for _, alts := range p {
		if len(alts) == 0 {
			return nil
		}
		next := make([][]string, 0, len(combos)*len(alts))
		for _, c := range combos {
			for _, a := range alts {
				next = append(next, append(append([]string(nil), c...), a))
			}
		}
		if len(next) > maxExpansions {
			return nil
		}
		combos = next
	}
	return combos
}

func samePattern(a, b [][]string) bool { return PatternJSON(a) == PatternJSON(b) }

// under reports whether path is dir or a folder inside dir.
func under(path, dir string) bool {
	if dir == "" || path == "" {
		return false
	}
	if path == dir {
		return true
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return strings.HasPrefix(path, dir)
}
