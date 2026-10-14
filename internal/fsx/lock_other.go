//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package fsx

// Lock is a no-op where flock is not available.
func Lock(string) (func(), error) { return func() {}, nil }
