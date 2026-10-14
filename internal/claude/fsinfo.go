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
const maxReadSize = 64 << 20

// readFile reads a whole regular file and says why it could not. A FIFO, a device
// or any other special file (also through a symlink) is never opened, so it cannot
// hang grants. It counts as blocked, like a file larger than maxReadSize.
func readFile(path string) ([]byte, fileState) {
	fi, err := os.Stat(path) // before Open: opening a FIFO blocks
	if err != nil {
		return nil, stateOf(err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxReadSize {
		return nil, stateBlocked
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, stateOf(err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, stateBlocked
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReadSize+1))
	if err != nil || len(b) > maxReadSize {
		return nil, stateBlocked
	}
	return b, stateOK
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
