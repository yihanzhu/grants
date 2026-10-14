package edit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// jsonScanner finds byte spans of values in a JSON document. It assumes the document
// already passed json.Valid, but every access is bounds-checked so a bug cannot panic.
type jsonScanner struct{ b []byte }

var errJSONTruncated = errors.New("edit: unexpected end of JSON")

func (s jsonScanner) at(i int) byte {
	if i < 0 || i >= len(s.b) {
		return 0
	}
	return s.b[i]
}

func (s jsonScanner) ws(i int) int {
	for i < len(s.b) {
		switch s.b[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// stringEnd returns the index after the string that starts at i.
func (s jsonScanner) stringEnd(i int) (int, error) {
	if s.at(i) != '"' {
		return 0, fmt.Errorf("edit: expected string at byte %d", i)
	}
	for j := i + 1; j < len(s.b); {
		switch s.b[j] {
		case '\\':
			j += 2
		case '"':
			return j + 1, nil
		default:
			j++
		}
	}
	return 0, errJSONTruncated
}

// valueEnd returns the index after the value that starts at i.
func (s jsonScanner) valueEnd(i int) (int, error) {
	if i >= len(s.b) {
		return 0, errJSONTruncated
	}
	switch s.b[i] {
	case '"':
		return s.stringEnd(i)
	case '{', '[':
		depth := 0
		for i < len(s.b) {
			switch s.b[i] {
			case '"':
				j, err := s.stringEnd(i)
				if err != nil {
					return 0, err
				}
				i = j
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1, nil
				}
			}
			i++
		}
		return 0, errJSONTruncated
	}
	j := i
	for j < len(s.b) && !strings.ContainsRune(" \t\r\n,]}", rune(s.b[j])) {
		j++
	}
	if j == i {
		return 0, fmt.Errorf("edit: unexpected byte at %d", i)
	}
	return j, nil
}

// decodeString decodes the quoted string span.
func decodeJSONString(span []byte) (string, error) {
	inner := span[1 : len(span)-1]
	if bytes.IndexByte(inner, '\\') < 0 && utf8.Valid(inner) {
		return string(inner), nil
	}
	var s string
	if err := json.Unmarshal(span, &s); err != nil {
		return "", err
	}
	return s, nil
}

// members calls fn for each member of the object that starts at i.
func (s jsonScanner) members(i int, fn func(key string, vs, ve int)) error {
	i = s.ws(i + 1)
	if s.at(i) == '}' {
		return nil
	}
	for {
		i = s.ws(i)
		ke, err := s.stringEnd(i)
		if err != nil {
			return err
		}
		key, err := decodeJSONString(s.b[i:ke])
		if err != nil {
			return err
		}
		i = s.ws(ke)
		if s.at(i) != ':' {
			return fmt.Errorf("edit: expected ':' at byte %d", i)
		}
		i = s.ws(i + 1)
		ve, err := s.valueEnd(i)
		if err != nil {
			return err
		}
		fn(key, i, ve)
		i = s.ws(ve)
		switch s.at(i) {
		case ',':
			i++
		case '}':
			return nil
		default:
			return fmt.Errorf("edit: expected ',' or '}' at byte %d", i)
		}
	}
}

type span struct{ start, end int }

// elements returns the spans of the array elements; the array starts at i.
func (s jsonScanner) elements(i int) ([]span, error) {
	i = s.ws(i + 1)
	if s.at(i) == ']' {
		return nil, nil
	}
	var out []span
	for {
		i = s.ws(i)
		ve, err := s.valueEnd(i)
		if err != nil {
			return nil, err
		}
		out = append(out, span{i, ve})
		i = s.ws(ve)
		switch s.at(i) {
		case ',':
			i++
		case ']':
			return out, nil
		default:
			return nil, fmt.Errorf("edit: expected ',' or ']' at byte %d", i)
		}
	}
}

// locate returns the span of the value at path. When several members share a key it
// picks the last one, as encoding/json does.
func (s jsonScanner) locate(path []string) (int, int, error) {
	vs := s.ws(0)
	ve, err := s.valueEnd(vs)
	if err != nil {
		return 0, 0, err
	}
	for depth, key := range path {
		if s.at(vs) != '{' {
			return 0, 0, fmt.Errorf("%w: %s is %s, not an object", ErrNotFound, pathString(path[:depth]), jsonTypeName(s.at(vs)))
		}
		found := false
		var fs, fe int
		err := s.members(vs, func(k string, a, b int) {
			if k == key {
				fs, fe, found = a, b, true
			}
		})
		if err != nil {
			return 0, 0, err
		}
		if !found {
			return 0, 0, fmt.Errorf("%w: no key %q at %s", ErrNotFound, key, pathString(path[:depth]))
		}
		vs, ve = fs, fe
	}
	return vs, ve, nil
}

func pathString(path []string) string {
	if len(path) == 0 {
		return "the document root"
	}
	q := make([]string, len(path))
	for i, p := range path {
		q[i] = fmt.Sprintf("%q", p)
	}
	return strings.Join(q, ".")
}

func jsonTypeName(c byte) string {
	switch c {
	case '{':
		return "an object"
	case '[':
		return "an array"
	case '"':
		return "a string"
	case 't', 'f':
		return "a boolean"
	case 'n':
		return "null"
	}
	return "a number"
}

// decodeJSON decodes doc with numbers kept as json.Number.
func decodeJSON(doc []byte) (any, error) {
	if !json.Valid(doc) {
		var v any
		err := json.Unmarshal(doc, &v)
		if err == nil {
			err = errors.New("invalid JSON")
		}
		return nil, fmt.Errorf("edit: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("edit: %w", err)
	}
	return v, nil
}

// mutateDecoded applies f to the decoded value at path, in place.
func mutateDecoded(root any, path []string, f func(any) (any, error)) (any, error) {
	if len(path) == 0 {
		return f(root)
	}
	m, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("edit: %s is not an object", path[0])
	}
	child, ok := m[path[0]]
	if !ok {
		return nil, fmt.Errorf("edit: missing key %q", path[0])
	}
	nc, err := mutateDecoded(child, path[1:], f)
	if err != nil {
		return nil, err
	}
	m[path[0]] = nc
	return root, nil
}

// verifyJSON requires that newDoc decodes to oldDoc with f applied at path.
func verifyJSON(oldDoc, newDoc []byte, path []string, f func(any) (any, error)) error {
	want, err := decodeJSON(oldDoc)
	if err != nil {
		return err
	}
	got, err := decodeJSON(newDoc)
	if err != nil {
		return fmt.Errorf("edit: result is not valid JSON: %w", err)
	}
	want, err = mutateDecoded(want, path, f)
	if err != nil {
		return err
	}
	if !equalDecoded(want, got) {
		return errors.New("edit: verification failed: the edited document differs from the intended change")
	}
	return nil
}

func recoverErr(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("edit: internal error: %v", r)
	}
}

// RemoveArrayString removes every element equal to value from the JSON string array
// at path (object keys), keeping all other bytes as they were. It returns the new
// document and how many elements it removed. A missing path returns ErrNotFound; a
// value that is not in the array returns the document unchanged and a count of 0.
func RemoveArrayString(doc []byte, path []string, value string) (out []byte, n int, err error) {
	defer recoverErr(&err)
	if _, err := decodeJSON(doc); err != nil {
		return nil, 0, err
	}
	s := jsonScanner{doc}
	vs, ve, err := s.locate(path)
	if err != nil {
		return nil, 0, err
	}
	if s.at(vs) != '[' {
		return nil, 0, fmt.Errorf("edit: %s is %s, not an array", pathString(path), jsonTypeName(s.at(vs)))
	}
	elems, err := s.elements(vs)
	if err != nil {
		return nil, 0, err
	}
	var kept []int // indexes of the elements that stay
	for i, e := range elems {
		if doc[e.start] == '"' {
			str, err := decodeJSONString(doc[e.start:e.end])
			if err != nil {
				return nil, 0, err
			}
			if str == value {
				n++
				continue
			}
		}
		kept = append(kept, i)
	}
	if n == 0 {
		return append([]byte(nil), doc...), 0, nil
	}

	var buf bytes.Buffer
	buf.Write(doc[:vs+1])
	if len(kept) > 0 {
		// The separator before each kept element carries its indentation, so reuse it;
		// the first kept element takes the original lead so no comma starts the array.
		buf.Write(doc[vs+1 : elems[0].start])
		for j, i := range kept {
			if j > 0 {
				buf.Write(doc[elems[i-1].end:elems[i].start])
			}
			buf.Write(doc[elems[i].start:elems[i].end])
		}
		buf.Write(doc[elems[len(elems)-1].end:ve])
	} else {
		buf.Write(doc[ve-1 : ve])
	}
	buf.Write(doc[ve:])
	out = buf.Bytes()

	err = verifyJSON(doc, out, path, func(v any) (any, error) {
		arr, ok := v.([]any)
		if !ok {
			return nil, errors.New("edit: not an array")
		}
		res := make([]any, 0, len(arr))
		for _, e := range arr {
			if str, ok := e.(string); ok && str == value {
				continue
			}
			res = append(res, e)
		}
		return res, nil
	})
	if err != nil {
		return nil, 0, err
	}
	return out, n, nil
}

// SetBool sets the existing boolean at path (object keys) to v, changing only the
// value bytes.
func SetBool(doc []byte, path []string, v bool) (out []byte, err error) {
	defer recoverErr(&err)
	if _, err := decodeJSON(doc); err != nil {
		return nil, err
	}
	s := jsonScanner{doc}
	vs, ve, err := s.locate(path)
	if err != nil {
		return nil, err
	}
	if c := s.at(vs); c != 't' && c != 'f' {
		return nil, fmt.Errorf("edit: %s is %s, not a boolean", pathString(path), jsonTypeName(c))
	}
	lit := "false"
	if v {
		lit = "true"
	}
	out = make([]byte, 0, len(doc)+1)
	out = append(out, doc[:vs]...)
	out = append(out, lit...)
	out = append(out, doc[ve:]...)
	err = verifyJSON(doc, out, path, func(any) (any, error) { return v, nil })
	if err != nil {
		return nil, err
	}
	return out, nil
}
