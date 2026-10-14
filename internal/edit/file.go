package edit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path through a temp file in the same folder, so a
// reader never sees a half-written file. If path is a symlink it writes the target and
// keeps the link. An existing file keeps its permission bits; a new file gets 0600.
func WriteFileAtomic(path string, data []byte) error {
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("edit: resolve %s: %w", path, err)
	} else if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("edit: %s is a symlink to a missing file", path)
	}

	mode := os.FileMode(0o600)
	if fi, err := os.Stat(target); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("edit: %s is not a regular file", target)
		}
		mode = fi.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("edit: stat %s: %w", target, err)
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".grants-*")
	if err != nil {
		return fmt.Errorf("edit: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(fmt.Errorf("edit: write %s: %w", tmpName, err))
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(fmt.Errorf("edit: chmod %s: %w", tmpName, err))
	}
	if err := tmp.Sync(); err != nil {
		return fail(fmt.Errorf("edit: sync %s: %w", tmpName, err))
	}
	if err := tmp.Close(); err != nil {
		return fail(fmt.Errorf("edit: close %s: %w", tmpName, err))
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fail(fmt.Errorf("edit: replace %s: %w", target, err))
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a folder entry to disk; it is best effort because some systems
// refuse to sync a folder.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
