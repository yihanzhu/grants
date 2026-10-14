package edit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/yihanzhu/grants/internal/fsx"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func fileKey(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeNew creates path with mode 0600 and fails if it exists.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// saveCopy writes data to a new file in dir (mode 0600, name from the CreateTemp
// pattern) and returns its path.
func saveCopy(dir, pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	return f.Name(), f.Close()
}

// newBatchDir creates backups/<id> for the next batch. The ID is the UTC time; a
// number is appended when the ID is already in the backups folder or the journal.
func newBatchDir(stateDir string, now time.Time, taken map[string]bool) (string, string, error) {
	root := filepath.Join(stateDir, "backups")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", "", err
	}
	base := now.UTC().Format("20060102T150405Z")
	for n := 1; n < 10000; n++ {
		id := base
		if n > 1 {
			id = base + "-" + strconv.Itoa(n)
		}
		if taken[id] {
			continue
		}
		dir := filepath.Join(root, id)
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			return id, dir, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", "", err
		}
	}
	return "", "", errors.New("edit: no free batch id")
}

// rollback puts the original content back into the files written so far.
func rollback(changes []Change, originals [][]byte, written int) error {
	var errs []error
	for i := 0; i < written; i++ {
		if err := WriteFileAtomic(changes[i].File, originals[i]); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", changes[i].File, err))
		}
	}
	return errors.Join(errs...)
}

// Apply backs up every file, checks each still holds Change.Before, writes the new
// content atomically, and records the batch in the journal under stateDir before the
// first write. It takes one change per file. If any file differs from Before it returns ErrChanged and
// writes nothing; if a write fails it restores the files already written.
func Apply(stateDir string, now time.Time, changes []Change) (Batch, error) {
	if len(changes) == 0 {
		return Batch{}, errors.New("edit: no changes to apply")
	}
	seen := map[string]string{}
	for _, c := range changes {
		k := fileKey(c.File)
		if prev, dup := seen[k]; dup {
			return Batch{}, fmt.Errorf("edit: more than one change for %s (also %s)", c.File, prev)
		}
		seen[k] = c.File
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return Batch{}, fmt.Errorf("edit: create state folder: %w", err)
	}
	unlock, err := fsx.Lock(filepath.Join(stateDir, "lock"))
	if err != nil {
		return Batch{}, err
	}
	defer unlock()

	// Check every file before touching anything.
	originals := make([][]byte, len(changes))
	for i, c := range changes {
		cur, err := os.ReadFile(c.File)
		if errors.Is(err, fs.ErrNotExist) {
			return Batch{}, fmt.Errorf("%w: %s no longer exists", ErrChanged, c.File)
		}
		if err != nil {
			return Batch{}, fmt.Errorf("edit: read %s: %w", c.File, err)
		}
		if !bytes.Equal(cur, c.Before) {
			return Batch{}, fmt.Errorf("%w: %s", ErrChanged, c.File)
		}
		originals[i] = cur
	}

	prior, _, err := readJournal(stateDir)
	if err != nil {
		return Batch{}, err
	}
	taken := map[string]bool{}
	for _, b := range prior {
		taken[b.ID] = true
	}
	id, dir, err := newBatchDir(stateDir, now, taken)
	if err != nil {
		return Batch{}, fmt.Errorf("edit: create backup folder: %w", err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}

	batch := Batch{ID: id, Time: now}
	for i, c := range changes {
		backup := filepath.Join(absDir, fmt.Sprintf("%d-%s", i+1, filepath.Base(c.File)))
		if err := writeNew(backup, originals[i]); err != nil {
			os.RemoveAll(dir)
			return Batch{}, fmt.Errorf("edit: back up %s: %w", c.File, err)
		}
		batch.Files = append(batch.Files, BatchFile{
			File: c.File, Backup: backup, BeforeHash: hashHex(originals[i]), AfterHash: hashHex(c.After),
			GrantID: c.GrantID, Summary: c.Summary,
		})
	}

	// Journal the batch before the first write. If this process dies half way, undo
	// can still find the batch and the backups.
	if err := appendJournal(stateDir, journalApply{Type: "apply", Batch: batch}); err != nil {
		os.RemoveAll(dir)
		return Batch{}, fmt.Errorf("edit: write journal: %w", err)
	}
	fail := func(written int, cause error) (Batch, error) {
		if rerr := rollback(changes, originals, written); rerr != nil {
			// Keep the backups: they are the only good copy left.
			return Batch{}, fmt.Errorf("%w; restoring failed, originals are in %s: %v", cause, dir, rerr)
		}
		if aerr := appendJournal(stateDir, journalAbort{Type: "abort", ID: id}); aerr != nil {
			// The batch stays in the journal, so keep its backups too.
			return Batch{}, fmt.Errorf("%w; the batch is still in the journal and its backups are in %s: %v", cause, dir, aerr)
		}
		os.RemoveAll(dir)
		return Batch{}, cause
	}
	for i, c := range changes {
		// Check again right before the rename: an agent may have written the file
		// while the backups and the temp file were being written.
		err := writeAtomic(c.File, c.After, func() error {
			cur, err := os.ReadFile(c.File)
			if err != nil || !bytes.Equal(cur, c.Before) {
				return fmt.Errorf("%w: %s", ErrChanged, c.File)
			}
			return nil
		})
		if errors.Is(err, ErrChanged) {
			return fail(i, err)
		}
		if err != nil {
			return fail(i, fmt.Errorf("edit: write %s: %w", c.File, err))
		}
	}
	return batch, nil
}

// Undo restores the latest batch that is not undone yet. It refuses with ErrChanged
// when a file changed after grants wrote it, unless force is set. A forced undo first
// saves each such file to backups/<id>/before-undo-* and reports the path in
// BatchFile.Saved. A backup that does not match BeforeHash is never restored.
func Undo(stateDir string, now time.Time, force bool) (Batch, error) {
	if _, err := os.Stat(stateDir); errors.Is(err, fs.ErrNotExist) {
		return Batch{}, ErrNothingToUndo
	}
	unlock, err := fsx.Lock(filepath.Join(stateDir, "lock"))
	if err != nil {
		return Batch{}, err
	}
	defer unlock()

	batches, undone, err := readJournal(stateDir)
	if err != nil {
		return Batch{}, err
	}
	var batch *Batch
	for i := len(batches) - 1; i >= 0; i-- {
		if _, done := undone[batches[i].ID]; !done {
			batch = &batches[i]
			break
		}
	}
	if batch == nil {
		return Batch{}, ErrNothingToUndo
	}

	// Read everything first so a refusal writes nothing. A file that already holds its
	// backup was never written (Apply died before it) or is already restored; leave it.
	current := make([][]byte, len(batch.Files))
	existed := make([]bool, len(batch.Files))
	untouched := make([]bool, len(batch.Files))
	backups := make([][]byte, len(batch.Files))
	for i, f := range batch.Files {
		data, err := os.ReadFile(f.Backup)
		if errors.Is(err, fs.ErrNotExist) {
			// The state folder may have moved since the batch was written.
			alt := filepath.Join(stateDir, "backups", batch.ID, filepath.Base(f.Backup))
			data, err = os.ReadFile(alt)
		}
		if err != nil {
			return Batch{}, fmt.Errorf("edit: read backup of %s: %w", f.File, err)
		}
		if f.BeforeHash != "" && hashHex(data) != f.BeforeHash {
			return Batch{}, fmt.Errorf("edit: backup of %s does not match the original it was taken from (%s)", f.File, f.Backup)
		}
		backups[i] = data

		cur, err := os.ReadFile(f.File)
		switch {
		case err == nil:
			existed[i] = true
			current[i] = cur
			if bytes.Equal(cur, data) {
				untouched[i] = true
			} else if !force && hashHex(cur) != f.AfterHash {
				return Batch{}, fmt.Errorf("%w: %s was edited after grants changed it (use force to restore anyway)", ErrChanged, f.File)
			}
		case errors.Is(err, fs.ErrNotExist):
			if !force {
				return Batch{}, fmt.Errorf("%w: %s no longer exists", ErrChanged, f.File)
			}
		default:
			return Batch{}, fmt.Errorf("edit: read %s: %w", f.File, err)
		}
	}

	// A forced undo overwrites content grants did not write. Keep a copy of it.
	if force {
		dir := filepath.Join(stateDir, "backups", batch.ID)
		for i, f := range batch.Files {
			if !existed[i] || untouched[i] || hashHex(current[i]) == f.AfterHash {
				continue
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return Batch{}, fmt.Errorf("edit: create backup folder: %w", err)
			}
			saved, err := saveCopy(dir, fmt.Sprintf("before-undo-%d-%s-*", i+1, filepath.Base(f.File)), current[i])
			if err != nil {
				return Batch{}, fmt.Errorf("edit: keep a copy of %s: %w", f.File, err)
			}
			batch.Files[i].Saved = saved
		}
	}

	fail := func(written int, cause error) (Batch, error) {
		var errs []error
		for i := 0; i < written; i++ {
			var err error
			if existed[i] {
				err = WriteFileAtomic(batch.Files[i].File, current[i])
			} else {
				err = os.Remove(batch.Files[i].File)
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			cause = fmt.Errorf("%w; rolling back failed: %v", cause, errors.Join(errs...))
		}
		return Batch{}, cause
	}
	for i, f := range batch.Files {
		if untouched[i] {
			continue
		}
		var check func() error
		if !force {
			// Check again right before the rename, in case an agent wrote meanwhile.
			check = func() error {
				cur, err := os.ReadFile(f.File)
				if err != nil || hashHex(cur) != f.AfterHash {
					return fmt.Errorf("%w: %s was edited after grants changed it (use force to restore anyway)", ErrChanged, f.File)
				}
				return nil
			}
		}
		err := writeAtomic(f.File, backups[i], check)
		if errors.Is(err, ErrChanged) {
			return fail(i, err)
		}
		if err != nil {
			return fail(i, fmt.Errorf("edit: restore %s: %w", f.File, err))
		}
	}
	if err := appendJournal(stateDir, journalUndo{Type: "undo", ID: batch.ID, Time: now}); err != nil {
		return fail(len(batch.Files), fmt.Errorf("edit: write journal: %w", err))
	}
	batch.Undone = true
	return *batch, nil
}

// Batches returns journal batches, newest first. A missing journal gives an empty list.
func Batches(stateDir string) ([]Batch, error) {
	batches, undone, err := readJournal(stateDir)
	if err != nil {
		return nil, err
	}
	out := make([]Batch, 0, len(batches))
	for i := len(batches) - 1; i >= 0; i-- {
		b := batches[i]
		b.UndoneAt, b.Undone = undone[b.ID], false
		if _, ok := undone[b.ID]; ok {
			b.Undone = true
		}
		out = append(out, b)
	}
	return out, nil
}
