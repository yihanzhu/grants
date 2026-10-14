//go:build !darwin

package fsx

import "time"

// Birthtime returns when path was created. Only macOS records it; elsewhere it
// reports false.
func Birthtime(string) (time.Time, bool) { return time.Time{}, false }
