package edit

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
)

func decodeTOML(doc []byte) (map[string]any, error) {
	m := map[string]any{}
	if _, err := toml.Decode(string(doc), &m); err != nil {
		return nil, fmt.Errorf("edit: invalid TOML: %w", err)
	}
	return m, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// decodedTable returns the table at path in a decoded document.
func decodedTable(root map[string]any, path []string) (map[string]any, bool) {
	cur := root
	for _, p := range path {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// findTable returns the index of the [table] header statement. It returns
// ErrUnsupportedLayout when the table exists but not as a plain header (inline table,
// dotted keys, array of tables) and ErrNotFound when it does not exist.
func findTable(stmts []tomlStmt, doc map[string]any, table []string) (int, error) {
	if len(table) == 0 {
		return 0, errors.New("edit: empty table name")
	}
	found := -1
	for i, st := range stmts {
		if !equalStrings(st.key, table) {
			continue
		}
		switch st.kind {
		case tomlArrayTable:
			return 0, fmt.Errorf("%w: %s is an array of tables", ErrUnsupportedLayout, pathString(table))
		case tomlTable:
			if found >= 0 {
				return 0, fmt.Errorf("%w: %s is defined twice", ErrUnsupportedLayout, pathString(table))
			}
			found = i
		}
	}
	if found >= 0 {
		return found, nil
	}
	if _, ok := decodedTable(doc, table); ok {
		return 0, fmt.Errorf("%w: %s is not defined by its own [header]", ErrUnsupportedLayout, pathString(table))
	}
	return 0, fmt.Errorf("%w: table %s", ErrNotFound, pathString(table))
}

// bodyEnd returns the index of the first statement after the body of the header at h.
func bodyEnd(stmts []tomlStmt, h int) int {
	for j := h + 1; j < len(stmts); j++ {
		if k := stmts[j].kind; k == tomlTable || k == tomlArrayTable {
			return j
		}
	}
	return len(stmts)
}

// TOMLSetString sets key = "value" inside the table named by table (e.g.
// ["projects", "/a/b"] for [projects."/a/b"]), changing only the value bytes. The key
// must already exist in that table. A trailing comment on the line is kept. When the
// table is not defined by its own [header], it returns ErrUnsupportedLayout.
func TOMLSetString(doc []byte, table []string, key, value string) (out []byte, err error) {
	defer recoverErr(&err)
	old, err := decodeTOML(doc)
	if err != nil {
		return nil, err
	}
	stmts, err := scanTOML(doc)
	if err != nil {
		return nil, err
	}
	h, err := findTable(stmts, old, table)
	if err != nil {
		return nil, err
	}
	quoted, err := tomlQuote(value)
	if err != nil {
		return nil, err
	}
	at := -1
	for i := h + 1; i < bodyEnd(stmts, h); i++ {
		st := stmts[i]
		if st.kind != tomlKV {
			continue
		}
		if equalStrings(st.key, []string{key}) {
			at = i
			break
		}
		if st.key[0] == key {
			return nil, fmt.Errorf("%w: %q is defined with dotted keys", ErrUnsupportedLayout, key)
		}
	}
	if at < 0 {
		return nil, fmt.Errorf("%w: key %q in table %s", ErrNotFound, key, pathString(table))
	}
	st := stmts[at]
	out = make([]byte, 0, len(doc)+len(quoted))
	out = append(out, doc[:st.valStart]...)
	out = append(out, quoted...)
	out = append(out, doc[st.valEnd:]...)

	tbl, ok := decodedTable(old, table)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedLayout, pathString(table))
	}
	tbl[key] = value
	if err := verifyTOML(old, out); err != nil {
		return nil, err
	}
	return out, nil
}

// verifyTOML requires that newDoc decodes to want.
func verifyTOML(want map[string]any, newDoc []byte) error {
	got, err := decodeTOML(newDoc)
	if err != nil {
		return fmt.Errorf("edit: result is not valid: %w", err)
	}
	if !equalDecoded(want, got) {
		return errors.New("edit: verification failed: the edited document differs from the intended change")
	}
	return nil
}

// TOMLDeleteTable removes the table header named by table and its body, up to the
// next table header. Comment lines directly above the next header stay with that
// header (comments above the deleted header stay too). The blank line that separated
// the deleted table goes with it, so no double blank line is left. A table with
// sub-tables, or one not defined by its own [header], returns ErrUnsupportedLayout.
func TOMLDeleteTable(doc []byte, table []string) (out []byte, err error) {
	defer recoverErr(&err)
	old, err := decodeTOML(doc)
	if err != nil {
		return nil, err
	}
	stmts, err := scanTOML(doc)
	if err != nil {
		return nil, err
	}
	h, err := findTable(stmts, old, table)
	if err != nil {
		return nil, err
	}
	for _, st := range stmts {
		if (st.kind == tomlTable || st.kind == tomlArrayTable) && len(st.key) > len(table) &&
			equalStrings(st.key[:len(table)], table) {
			return nil, fmt.Errorf("%w: %s has sub-tables", ErrUnsupportedLayout, pathString(table))
		}
	}

	j := bodyEnd(stmts, h)
	from := stmts[h].start
	var to int
	if j == len(stmts) {
		// Last table: delete its body up to the last key/value. A comment block after
		// that is not part of the table and stays. With nothing left after it, drop
		// the blank lines before the header too.
		r := j
		for r-1 > h && (stmts[r-1].kind == tomlBlank || stmts[r-1].kind == tomlComment) {
			r--
		}
		for r < j && stmts[r].kind == tomlBlank {
			r++
		}
		to = len(doc)
		if r < j {
			to = stmts[r].start
		} else {
			for h > 0 && stmts[h-1].kind == tomlBlank {
				h--
				from = stmts[h].start
			}
		}
	} else {
		// Comments directly above the next header belong to it. The blank lines before
		// them go with the deleted table, unless the text before it has no blank line.
		r := j
		for r-1 > h && stmts[r-1].kind == tomlComment {
			r--
		}
		if h > 0 && stmts[h-1].kind != tomlBlank {
			for r-1 > h && stmts[r-1].kind == tomlBlank {
				r--
			}
		}
		to = stmts[r].start
	}
	if from == 0 && bytes.HasPrefix(doc, bom) {
		from = len(bom) // keep the byte order mark
	}
	out = append(append([]byte(nil), doc[:from]...), doc[to:]...)

	// Apply the same change to the decoded document: drop the table, and drop parents
	// that only existed because of it (an implicit super-table disappears with its
	// last child; a parent with its own header stays).
	if parent, ok := decodedTable(old, table[:len(table)-1]); ok {
		delete(parent, table[len(table)-1])
	}
	for depth := len(table) - 1; depth > 0; depth-- {
		prefix := table[:depth]
		tbl, ok := decodedTable(old, prefix)
		if !ok || len(tbl) > 0 || hasHeader(stmts, prefix) {
			break
		}
		if gp, ok := decodedTable(old, prefix[:depth-1]); ok {
			delete(gp, prefix[depth-1])
		}
	}
	if err := verifyTOML(old, out); err != nil {
		return nil, err
	}
	return out, nil
}

func hasHeader(stmts []tomlStmt, table []string) bool {
	for _, st := range stmts {
		if st.kind == tomlTable && equalStrings(st.key, table) {
			return true
		}
	}
	return false
}
