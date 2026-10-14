// Package fsx has small file-system helpers that tell apart "missing" from "blocked".
package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Exists reports whether path exists, without following a final symlink. A permission
// error counts as existing: we cannot tell, and a blocked path is not a missing one.
func Exists(path string) bool {
	_, err := os.Lstat(path)
	if err == nil {
		return true
	}
	return isDenied(err)
}

// Missing reports whether path certainly does not exist: Lstat says not-exist, or a
// parent is not a folder. A permission error is not "missing": the path may be there.
func Missing(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

func isDenied(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

// Within reports whether p is dir or inside it. Both are cleaned first; an empty
// path is never within anything.
func Within(p, dir string) bool {
	if p == "" || dir == "" {
		return false
	}
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}
