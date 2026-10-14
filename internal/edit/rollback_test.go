package edit

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// A rollback undoes only what grants wrote. A file that an agent changed after that
// write keeps its content, and the error names it.

func TestApplyRollbackKeepsFileChangedAfterGrantsWroteIt(t *testing.T) {
	state, files, changes := fixture(t)
	agentJSON := `{"a":["agent"]}`
	hookOnce(t, "config.toml", func() {
		write(t, files[0], agentJSON, 0o644)          // written by grants a moment ago, now changed
		write(t, files[1], "[a]\nk = \"x\"\n", 0o600) // makes the second write fail
	})
	_, err := Apply(state, t0, changes)
	if err == nil || !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
	if read(t, files[0]) != agentJSON {
		t.Errorf("rollback overwrote the agent's change: %q", read(t, files[0]))
	}
	if !strings.Contains(err.Error(), files[0]) || !strings.Contains(err.Error(), "left as is") {
		t.Errorf("error does not name the file left alone: %v", err)
	}
	// The originals stay on disk, because the rollback was not complete.
	if list, _ := Batches(state); len(list) != 1 {
		t.Errorf("batches = %+v", list)
	}
}

func TestUndoRollbackKeepsFileChangedAfterGrantsRestoredIt(t *testing.T) {
	state, files, changes := fixture(t)
	if _, err := Apply(state, t0, changes); err != nil {
		t.Fatal(err)
	}
	agentJSON := `{"a":["agent"]}`
	hookOnce(t, "config.toml", func() {
		write(t, files[0], agentJSON, 0o644)          // restored by this undo a moment ago, now changed
		write(t, files[1], "[a]\nk = \"x\"\n", 0o600) // makes the second restore fail
	})
	_, err := Undo(state, t0, false)
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
	if read(t, files[0]) != agentJSON {
		t.Errorf("rollback overwrote the agent's change: %q", read(t, files[0]))
	}
	if !strings.Contains(err.Error(), files[0]) {
		t.Errorf("error does not name the file left alone: %v", err)
	}
	if list, _ := Batches(state); list[0].Undone {
		t.Error("refused undo was journaled")
	}
}

func TestForcedUndoChecksTheFileBeforeRename(t *testing.T) {
	state, files, changes := fixture(t)
	if _, err := Apply(state, t0, changes); err != nil {
		t.Fatal(err)
	}
	newer := "[a]\nk = \"newer\"\n"
	write(t, files[1], newer, 0o600)
	newest := "[a]\nk = \"newest\"\n"
	hookOnce(t, "config.toml", func() { write(t, files[1], newest, 0o600) })

	_, err := Undo(state, t0, true)
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
	if read(t, files[1]) != newest {
		t.Errorf("forced undo overwrote content it had not read: %q", read(t, files[1]))
	}
	if read(t, files[0]) != `{"a":["y"]}` {
		t.Errorf("first file was not rolled back: %q", read(t, files[0]))
	}
	if list, _ := Batches(state); list[0].Undone {
		t.Error("refused undo was journaled")
	}
}

func TestForcedUndoOfMissingFileChecksItStaysMissing(t *testing.T) {
	state, files, changes := fixture(t)
	if _, err := Apply(state, t0, changes); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(files[1]); err != nil {
		t.Fatal(err)
	}
	created := "[a]\nk = \"agent\"\n"
	hookOnce(t, "config.toml", func() { write(t, files[1], created, 0o600) })
	if _, err := Undo(state, t0, true); !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
	if read(t, files[1]) != created {
		t.Errorf("forced undo overwrote a file that appeared: %q", read(t, files[1]))
	}
}
