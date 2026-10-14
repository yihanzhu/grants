package edit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

type journalApply struct {
	Type  string `json:"type"`
	Batch Batch  `json:"batch"`
}

type journalUndo struct {
	Type string    `json:"type"`
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
}

// journalRecord reads either kind of line.
type journalRecord struct {
	Type  string `json:"type"`
	Batch *Batch `json:"batch"`
	ID    string `json:"id"`
}

func journalPath(stateDir string) string { return filepath.Join(stateDir, "journal.jsonl") }

// appendJournal writes one record as a line and flushes it to disk.
func appendJournal(stateDir string, rec any) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(journalPath(stateDir), os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	// A crash can leave a last line without its newline; start on a fresh line so the
	// new record is not glued to it.
	if fi, err := f.Stat(); err == nil && fi.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], fi.Size()-1); err == nil && last[0] != '\n' {
			line = append([]byte{'\n'}, line...)
		}
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// readJournal returns the apply batches in journal order and the set of undone IDs.
// Lines that do not parse (for example one cut short by a crash) are skipped.
func readJournal(stateDir string) ([]Batch, map[string]bool, error) {
	f, err := os.Open(journalPath(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, map[string]bool{}, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("edit: open journal: %w", err)
	}
	defer f.Close()

	var batches []Batch
	undone := map[string]bool{}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 {
			var rec journalRecord
			if json.Unmarshal(line, &rec) == nil {
				switch {
				case rec.Type == "apply" && rec.Batch != nil && rec.Batch.ID != "":
					batches = append(batches, *rec.Batch)
				case rec.Type == "undo" && rec.ID != "":
					undone[rec.ID] = true
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("edit: read journal: %w", err)
		}
	}
	return batches, undone, nil
}
