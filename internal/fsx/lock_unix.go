//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package fsx

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// Lock takes an exclusive lock on the file at path so two grants processes never
// write the same state at the same time. It waits up to ten seconds.
func Lock(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("fsx: open lock: %w", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			f.Close()
			return nil, fmt.Errorf("fsx: lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("fsx: another grants process holds the lock %s", path)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
