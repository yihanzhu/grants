// Package fsx has small file-system helpers that tell apart "missing" from "blocked".
package fsx

import (
	"errors"
	"io"
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

// Readable reports whether folder exists and can be listed.
func Readable(folder string) bool {
	_, err := listErr(folder)
	return err == nil
}

// Blocked reports whether folder exists but the OS denies access to it, for example
// macOS privacy controls (EPERM) or file modes (EACCES). A missing folder is not
// blocked, so callers can tell "gone" from "cannot look".
func Blocked(folder string) bool {
	_, err := listErr(folder)
	return err != nil && isDenied(err)
}

func listErr(folder string) (struct{}, error) {
	f, err := os.Open(folder)
	if err != nil {
		return struct{}{}, err
	}
	defer f.Close()
	if _, err := f.ReadDir(1); err != nil && !errors.Is(err, io.EOF) {
		return struct{}{}, err
	}
	return struct{}{}, nil
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
