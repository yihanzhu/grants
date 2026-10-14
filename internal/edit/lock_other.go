//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package edit

// lockDir is a no-op where flock is not available.
func lockDir(string) (func(), error) { return func() {}, nil }
