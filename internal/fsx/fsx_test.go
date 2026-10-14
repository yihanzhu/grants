package fsx

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestExists(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "f")
	os.WriteFile(f, nil, 0o600)
	link := filepath.Join(d, "dangling")
	os.Symlink(filepath.Join(d, "nope"), link)
	for p, want := range map[string]bool{d: true, f: true, link: true, filepath.Join(d, "nope"): false} {
		if got := Exists(p); got != want {
			t.Errorf("Exists(%s) = %v", p, got)
		}
	}
}

func TestExistsAndReadableBlocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores modes")
	}
	d := t.TempDir()
	locked := filepath.Join(d, "locked")
	os.Mkdir(locked, 0o700)
	os.WriteFile(filepath.Join(locked, "f"), nil, 0o600)
	os.Chmod(locked, 0)
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	if Readable(locked) || !Blocked(locked) {
		t.Errorf("locked: readable=%v blocked=%v", Readable(locked), Blocked(locked))
	}
	// A path below a closed folder cannot be inspected, but it may exist.
	if !Exists(filepath.Join(locked, "f")) {
		t.Error("permission error must count as existing")
	}
}

func TestReadable(t *testing.T) {
	d := t.TempDir()
	if !Readable(d) || Blocked(d) {
		t.Error("empty folder should be readable")
	}
	missing := filepath.Join(d, "missing")
	if Readable(missing) || Blocked(missing) {
		t.Error("missing folder is neither readable nor blocked")
	}
	f := filepath.Join(d, "file")
	os.WriteFile(f, nil, 0o600)
	if Readable(f) {
		t.Error("a file is not a readable folder")
	}
}

func TestBirthtime(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	os.WriteFile(f, []byte("x"), 0o600)
	bt, ok := Birthtime(f)
	if runtime.GOOS != "darwin" {
		if ok {
			t.Fatal("expected false off darwin")
		}
		return
	}
	if !ok || time.Since(bt) > time.Minute || bt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("birthtime %v %v", bt, ok)
	}
	if _, ok := Birthtime(filepath.Join(filepath.Dir(f), "nope")); ok {
		t.Fatal("missing file has no birthtime")
	}
}
