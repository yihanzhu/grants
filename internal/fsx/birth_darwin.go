//go:build darwin

package fsx

import (
	"os"
	"syscall"
	"time"
)

// Birthtime returns when path was created. Only macOS records it; elsewhere it
// reports false.
func Birthtime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (st.Birthtimespec.Sec == 0 && st.Birthtimespec.Nsec == 0) {
		return time.Time{}, false
	}
	return time.Unix(int64(st.Birthtimespec.Sec), int64(st.Birthtimespec.Nsec)), true
}
