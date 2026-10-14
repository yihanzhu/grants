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

// journalAbort marks a batch whose write failed and was rolled back.
type journalAbort struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// journalRecord reads either kind of line.
type journalRecord struct {
	Type  string    `json:"type"`
	Batch *Batch    `json:"batch"`
	ID    string    `json:"id"`
	Time  time.Time `json:"time"`
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

// readJournal returns the apply batches in journal order and the undone IDs with the
// time of the undo. Batches that were aborted (rolled back) are left out.
// Lines that do not parse (for example one cut short by a crash) are skipped.
func readJournal(stateDir string) ([]Batch, map[string]time.Time, error) {
	f, err := os.Open(journalPath(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, map[string]time.Time{}, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("edit: open journal: %w", err)
	}
	defer f.Close()

	var batches []Batch
	undone := map[string]time.Time{}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 {
			var rec journalRecord
			if json.Unmarshal(line, &rec) == nil {
				switch {
				case rec.Type == "apply" && rec.Batch != nil && rec.Batch.ID != "":
					batches = append(batches, *rec.Batch)
				case rec.Type == "abort" && rec.ID != "":
					// Drop the latest batch with this ID; an earlier one is a different run.
					for i := len(batches) - 1; i >= 0; i-- {
						if batches[i].ID == rec.ID {
							batches = append(batches[:i], batches[i+1:]...)
							break
						}
					}
				case rec.Type == "undo" && rec.ID != "":
					undone[rec.ID] = rec.Time
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
