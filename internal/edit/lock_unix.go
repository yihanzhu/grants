//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package edit

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// lockDir takes an exclusive lock on path so two grants processes never edit and
// journal at the same time. It waits up to ten seconds.
func lockDir(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("edit: open lock: %w", err)
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
			return nil, fmt.Errorf("edit: lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("edit: another grants process holds the lock %s", path)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
