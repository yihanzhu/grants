//go:build unix

package claude

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadFileRefusesSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no FIFO here:", err)
	}
	link := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Fatal(err)
	}
	linkToFifo := filepath.Join(dir, "settings.json")
	if err := os.Symlink(fifo, linkToFifo); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, link, linkToFifo} {
		done := make(chan fileState, 1)
		go func() { _, st := readFile(p); done <- st }()
		select {
		case st := <-done:
			if st != stateBlocked {
				t.Errorf("%s: state = %v, want blocked", filepath.Base(p), st)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: readFile did not return", filepath.Base(p))
		}
	}
}
