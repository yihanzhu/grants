package edit

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// The TOML scanner splits a document into statements: blank lines, comments, table
// headers and key/value pairs. A value that spans lines (multi-line string, array,
// inline table) belongs to one statement, so text inside it is never mistaken for a
// header. It assumes the document already decoded with a real TOML parser; it only
// finds byte spans.

type tomlKind int

const (
	tomlBlank tomlKind = iota
	tomlComment
	tomlTable      // [a.b]
	tomlArrayTable // [[a.b]]
	tomlKV
)

type tomlStmt struct {
	kind  tomlKind
	start int // start of the first line
	end   int // after the newline of the last line (or end of file)
	key   []string
	// For key/value statements: the span of the value text, without comment.
	valStart, valEnd int
}

var bom = []byte{0xEF, 0xBB, 0xBF}

func blanksEnd(doc []byte, i int) int {
	for i < len(doc) && (doc[i] == ' ' || doc[i] == '\t') {
		i++
	}
	return i
}

// lineEnd returns the index after the newline at or after i.
func lineEnd(doc []byte, i int) int {
	if j := bytes.IndexByte(doc[i:], '\n'); j >= 0 {
		return i + j + 1
	}
	return len(doc)
}

func scanTOML(doc []byte) ([]tomlStmt, error) {
	var out []tomlStmt
	for i := 0; i < len(doc); {
		st := tomlStmt{start: i}
		j := i
		if i == 0 && bytes.HasPrefix(doc, bom) {
			j = len(bom)
		}
		j = blanksEnd(doc, j)
		switch {
		case j >= len(doc):
			st.kind, st.end = tomlBlank, len(doc)
		case doc[j] == '\n' || doc[j] == '\r':
			st.kind, st.end = tomlBlank, lineEnd(doc, j)
		case doc[j] == '#':
			st.kind, st.end = tomlComment, lineEnd(doc, j)
		case doc[j] == '[':
			k := j + 1
			st.kind = tomlTable
			if k < len(doc) && doc[k] == '[' {
				st.kind = tomlArrayTable
				k++
			}
			key, k, err := parseTOMLKey(doc, k)
			if err != nil {
				return nil, err
			}
			k = blanksEnd(doc, k)
			closers := 1
			if st.kind == tomlArrayTable {
				closers = 2
			}
			for c := 0; c < closers; c++ {
				if k >= len(doc) || doc[k] != ']' {
					return nil, fmt.Errorf("edit: malformed table header at byte %d", j)
				}
				k++
			}
			st.key, st.end = key, lineEnd(doc, k)
		default:
			key, k, err := parseTOMLKey(doc, j)
			if err != nil {
				return nil, err
			}
			k = blanksEnd(doc, k)
			if k >= len(doc) || doc[k] != '=' {
				return nil, fmt.Errorf("edit: expected '=' at byte %d", k)
			}
			k = blanksEnd(doc, k+1)
			ve, err := scanTOMLValue(doc, k)
			if err != nil {
				return nil, err
			}
			st.kind, st.key, st.valStart, st.valEnd, st.end = tomlKV, key, k, ve, lineEnd(doc, ve)
		}
		if st.end <= i {
			return nil, errors.New("edit: TOML scanner made no progress")
		}
		out = append(out, st)
		i = st.end
	}
	return out, nil
}

func isBareKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// parseTOMLKey parses a bare, "basic", 'literal' or dotted key starting at i and
// returns its parts and the index after it.
func parseTOMLKey(doc []byte, i int) ([]string, int, error) {
	var parts []string
	for {
		i = blanksEnd(doc, i)
		if i >= len(doc) {
			return nil, 0, errors.New("edit: unexpected end of TOML key")
		}
		var part string
		switch c := doc[i]; {
		case c == '"':
			e, err := skipTOMLString(doc, i)
			if err != nil {
				return nil, 0, err
			}
			s, ok := unescapeTOMLBasic(doc[i+1 : e-1])
			if !ok {
				return nil, 0, fmt.Errorf("edit: bad escape in TOML key at byte %d", i)
			}
			part, i = s, e
		case c == '\'':
			e, err := skipTOMLString(doc, i)
			if err != nil {
				return nil, 0, err
			}
			part, i = string(doc[i+1:e-1]), e
		case isBareKeyByte(c):
			e := i
			for e < len(doc) && isBareKeyByte(doc[e]) {
				e++
			}
			part, i = string(doc[i:e]), e
		default:
			return nil, 0, fmt.Errorf("edit: unexpected byte %q in TOML key at %d", c, i)
		}
		parts = append(parts, part)
		i = blanksEnd(doc, i)
		if i < len(doc) && doc[i] == '.' {
			i++
			continue
		}
		return parts, i, nil
	}
}

// skipTOMLString returns the index after the string literal that starts at i.
func skipTOMLString(doc []byte, i int) (int, error) {
	q := doc[i]
	if len(doc)-i >= 3 && doc[i+1] == q && doc[i+2] == q {
		for j := i + 3; j < len(doc); {
			switch {
			case q == '"' && doc[j] == '\\':
				j += 2
			case doc[j] == q && len(doc)-j >= 3 && doc[j+1] == q && doc[j+2] == q:
				// One or two quotes may sit just before the closing three.
				j += 3
				for extra := 0; extra < 2 && j < len(doc) && doc[j] == q; extra++ {
					j++
				}
				return j, nil
			default:
				j++
			}
		}
		return 0, errors.New("edit: unterminated multi-line TOML string")
	}
	for j := i + 1; j < len(doc); {
		switch {
		case q == '"' && doc[j] == '\\':
			j += 2
		case doc[j] == q:
			return j + 1, nil
		case doc[j] == '\n':
			return 0, errors.New("edit: newline in TOML string")
		default:
			j++
		}
	}
	return 0, errors.New("edit: unterminated TOML string")
}

// scanTOMLValue returns the index after the value that starts at i.
func scanTOMLValue(doc []byte, i int) (int, error) {
	if i >= len(doc) {
		return 0, errors.New("edit: missing TOML value")
	}
	switch doc[i] {
	case '"', '\'':
		return skipTOMLString(doc, i)
	case '[', '{':
		depth := 0
		for j := i; j < len(doc); {
			switch doc[j] {
			case '"', '\'':
				e, err := skipTOMLString(doc, j)
				if err != nil {
					return 0, err
				}
				j = e
				continue
			case '#':
				j = lineEnd(doc, j)
				continue
			case '[', '{':
				depth++
			case ']', '}':
				depth--
				if depth == 0 {
					return j + 1, nil
				}
			}
			j++
		}
		return 0, errors.New("edit: unterminated TOML array or table")
	}
	// Number, boolean or date. A date-time may contain a space, so read to the comment
	// or the end of the line and trim.
	e := i
	for e < len(doc) && doc[e] != '\n' && doc[e] != '#' {
		e++
	}
	for e > i && (doc[e-1] == ' ' || doc[e-1] == '\t' || doc[e-1] == '\r') {
		e--
	}
	return e, nil
}

// unescapeTOMLBasic decodes the inside of a basic string.
func unescapeTOMLBasic(raw []byte) (string, bool) {
	if bytes.IndexByte(raw, '\\') < 0 {
		return string(raw), true
	}
	var out []byte
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			continue
		}
		i++
		if i >= len(raw) {
			return "", false
		}
		switch raw[i] {
		case 'b':
			out = append(out, '\b')
		case 't':
			out = append(out, '\t')
		case 'n':
			out = append(out, '\n')
		case 'f':
			out = append(out, '\f')
		case 'r':
			out = append(out, '\r')
		case 'e':
			out = append(out, 0x1b)
		case '"':
			out = append(out, '"')
		case '\\':
			out = append(out, '\\')
		case 'x', 'u', 'U':
			n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[raw[i]]
			if i+1+n > len(raw) {
				return "", false
			}
			v, err := strconv.ParseUint(string(raw[i+1:i+1+n]), 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return "", false
			}
			out = utf8.AppendRune(out, rune(v))
			i += n
		default:
			return "", false
		}
	}
	return string(out), true
}

// tomlQuote returns s as a TOML basic string.
func tomlQuote(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", errors.New("edit: value is not valid UTF-8")
	}
	b := []byte{'"'}
	for _, r := range s {
		switch {
		case r == '"':
			b = append(b, '\\', '"')
		case r == '\\':
			b = append(b, '\\', '\\')
		case r == '\n':
			b = append(b, '\\', 'n')
		case r == '\t':
			b = append(b, '\\', 't')
		case r == '\r':
			b = append(b, '\\', 'r')
		case r == '\b':
			b = append(b, '\\', 'b')
		case r == '\f':
			b = append(b, '\\', 'f')
		case r < 0x20 || r == 0x7f:
			b = append(b, fmt.Sprintf("\\u%04X", r)...)
		default:
			b = utf8.AppendRune(b, r)
		}
	}
	return string(append(b, '"')), nil
}
