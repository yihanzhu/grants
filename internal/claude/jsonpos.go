package claude

import (
	"bytes"
	"encoding/json"
)

// A tiny JSON navigator. It finds where a value starts, so a grant can show the line
// it lives on. It never decodes the values it skips, which keeps it cheap on a large
// ~/.claude.json, and it never panics on bad input.

const maxJSONDepth = 200

type jscan struct {
	b []byte
	i int
}

func (s *jscan) ws() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

// str reads the string starting at s.i and moves past it.
func (s *jscan) str() (string, bool) {
	if s.i >= len(s.b) || s.b[s.i] != '"' {
		return "", false
	}
	start := s.i
	for j := s.i + 1; j < len(s.b); j++ {
		switch s.b[j] {
		case '\\':
			j++
		case '"':
			var out string
			if err := json.Unmarshal(s.b[start:j+1], &out); err != nil {
				return "", false
			}
			s.i = j + 1
			return out, true
		}
	}
	return "", false
}

// skip moves past one value of any kind.
func (s *jscan) skip(depth int) bool {
	if depth > maxJSONDepth {
		return false
	}
	s.ws()
	if s.i >= len(s.b) {
		return false
	}
	switch c := s.b[s.i]; {
	case c == '"':
		_, ok := s.str()
		return ok
	case c == '{' || c == '[':
		closer := byte('}')
		if c == '[' {
			closer = ']'
		}
		s.i++
		s.ws()
		if s.i < len(s.b) && s.b[s.i] == closer {
			s.i++
			return true
		}
		for {
			if c == '{' {
				if _, ok := s.str(); !ok {
					return false
				}
				s.ws()
				if s.i >= len(s.b) || s.b[s.i] != ':' {
					return false
				}
				s.i++
			}
			if !s.skip(depth + 1) {
				return false
			}
			s.ws()
			if s.i >= len(s.b) {
				return false
			}
			switch s.b[s.i] {
			case ',':
				s.i++
				s.ws()
			case closer:
				s.i++
				return true
			default:
				return false
			}
		}
	default:
		start := s.i
		for s.i < len(s.b) && !isDelim(s.b[s.i]) {
			s.i++
		}
		return s.i > start // no progress means garbage such as a stray "}"
	}
}

// valueOffset returns the byte offset where the value at path (object keys) starts.
func valueOffset(doc []byte, path []string) (int, bool) {
	s := &jscan{b: doc}
	s.ws()
	for _, key := range path {
		if s.i >= len(s.b) || s.b[s.i] != '{' {
			return 0, false
		}
		s.i++
		found := false
		for !found {
			s.ws()
			if s.i >= len(s.b) || s.b[s.i] == '}' {
				return 0, false
			}
			k, ok := s.str()
			if !ok {
				return 0, false
			}
			s.ws()
			if s.i >= len(s.b) || s.b[s.i] != ':' {
				return 0, false
			}
			s.i++
			s.ws()
			if k == key {
				found = true
				break
			}
			if !s.skip(0) {
				return 0, false
			}
			s.ws()
			if s.i < len(s.b) && s.b[s.i] == ',' {
				s.i++
			}
		}
	}
	return s.i, true
}

// lineAt returns the 1-based line of the byte at offset.
func lineAt(doc []byte, offset int) int {
	if offset > len(doc) {
		offset = len(doc)
	}
	return 1 + bytes.Count(doc[:offset], []byte{'\n'})
}

// arrayLines returns the line of each string element of the array at path. When a
// string appears twice, the first line wins.
func arrayLines(doc []byte, path []string) map[string]int {
	off, ok := valueOffset(doc, path)
	if !ok || off >= len(doc) || doc[off] != '[' {
		return nil
	}
	out := map[string]int{}
	s := &jscan{b: doc, i: off + 1}
	for {
		s.ws()
		if s.i >= len(doc) || doc[s.i] == ']' {
			return out
		}
		at := s.i
		if doc[s.i] == '"' {
			v, ok := s.str()
			if !ok {
				return out
			}
			if _, dup := out[v]; !dup {
				out[v] = lineAt(doc, at)
			}
		} else if !s.skip(0) {
			return out
		}
		s.ws()
		if s.i < len(doc) && doc[s.i] == ',' {
			s.i++
		}
	}
}

// valueLine returns the 1-based line where the value at path starts, or 0.
func valueLine(doc []byte, path []string) int {
	off, ok := valueOffset(doc, path)
	if !ok {
		return 0
	}
	return lineAt(doc, off)
}

func isDelim(c byte) bool {
	switch c {
	case ',', '}', ']', ' ', '\t', '\r', '\n':
		return true
	}
	return false
}
