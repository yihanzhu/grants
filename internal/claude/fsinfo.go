package claude

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// readFile reads a whole file and says why it could not.
func readFile(path string) ([]byte, fileState) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		return b, stateOK
	case isMissing(err):
		return nil, stateMissing
	}
	return nil, stateBlocked
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

// inside reports whether p is dir or lies below it.
func inside(p, dir string) bool {
	if p == "" || dir == "" {
		return false
	}
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if p == dir || dir == string(filepath.Separator) {
		return true
	}
	return strings.HasPrefix(p, dir+string(filepath.Separator))
}
