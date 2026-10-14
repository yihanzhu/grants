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

func TestExistsCountsPermissionErrorAsExisting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores modes")
	}
	d := t.TempDir()
	locked := filepath.Join(d, "locked")
	os.Mkdir(locked, 0o700)
	os.WriteFile(filepath.Join(locked, "f"), nil, 0o600)
	os.Chmod(locked, 0)
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	// A path below a closed folder cannot be inspected, but it may exist.
	if !Exists(filepath.Join(locked, "f")) {
		t.Error("permission error must count as existing")
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

func TestMissing(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "f")
	os.WriteFile(f, nil, 0o600)
	for p, want := range map[string]bool{
		d: false, f: false,
		filepath.Join(d, "nope"):  true,
		filepath.Join(f, "child"): true, // a parent that is a file
	} {
		if got := Missing(p); got != want {
			t.Errorf("Missing(%s) = %v, want %v", p, got, want)
		}
	}
}

func TestMissingIsFalseForPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores modes")
	}
	locked := filepath.Join(t.TempDir(), "locked")
	os.Mkdir(locked, 0o700)
	os.WriteFile(filepath.Join(locked, "f"), nil, 0o600)
	os.Chmod(locked, 0)
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	if Missing(filepath.Join(locked, "f")) {
		t.Error("a path behind a blocked folder is not known to be missing")
	}
}
