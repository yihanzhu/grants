package claude

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"

	"github.com/yihanzhu/grants/internal/fsx"
)

type fileState int

const (
	stateOK      fileState = iota // read fine
	stateMissing                  // does not exist
	stateBlocked                  // exists, but cannot be read (permissions, macOS privacy)
)

func isMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// maxReadSize caps what readFile reads, so a huge file cannot use all memory.
// ~/.claude.json grows with every project and session, so it gets a higher cap.
const (
	maxReadSize       = 64 << 20
	maxClaudeJSONSize = 1 << 30
)

// readFile reads a whole regular file and says why it could not. A FIFO, a device
// or any other special file (also through a symlink) is never opened, so it cannot
// hang grants. It counts as blocked, like a file larger than maxReadSize.
func readFile(path string) ([]byte, fileState) {
	b, st, _ := readFileMax(path, maxReadSize)
	return b, st
}

// readFileMax is readFile with its own size cap. tooLarge is true when the file is
// over the cap, so the caller can say that instead of a generic "could not read".
func readFileMax(path string, limit int64) (b []byte, st fileState, tooLarge bool) {
	fi, err := os.Stat(path) // before Open: opening a FIFO blocks
	if err != nil {
		return nil, stateOf(err), false
	}
	if !fi.Mode().IsRegular() {
		return nil, stateBlocked, false
	}
	if fi.Size() > limit {
		return nil, stateBlocked, true
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, stateOf(err), false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, stateBlocked, false
	}
	b, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, stateBlocked, false
	}
	if int64(len(b)) > limit {
		return nil, stateBlocked, true
	}
	return b, stateOK, false
}

func stateOf(err error) fileState {
	if isMissing(err) {
		return stateMissing
	}
	return stateBlocked
}

// pathExists reports whether path exists. A permission error counts as existing,
// because the path is there but cannot be checked.
func pathExists(path string) bool { return fsx.Exists(path) }

// isDir reports whether path is a folder. blocked is true when it could not be checked.
func isDir(path string) (dir, blocked bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, !isMissing(err)
	}
	return fi.IsDir(), false
}
