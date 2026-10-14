package edit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()

	t.Run("new file is 0600", func(t *testing.T) {
		p := filepath.Join(dir, "new.json")
		if err := WriteFileAtomic(p, []byte("x")); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(p)
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v", fi.Mode().Perm())
		}
		if read(t, p) != "x" {
			t.Fatal("content")
		}
	})

	t.Run("mode kept", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("unix modes")
		}
		for _, mode := range []os.FileMode{0o644, 0o640, 0o600, 0o755} {
			p := filepath.Join(dir, "mode.txt")
			write(t, p, "old", mode)
			if err := WriteFileAtomic(p, []byte("new")); err != nil {
				t.Fatal(err)
			}
			fi, _ := os.Stat(p)
			if fi.Mode().Perm() != mode {
				t.Fatalf("mode = %v, want %v", fi.Mode().Perm(), mode)
			}
		}
	})

	t.Run("symlink target written, link kept", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks")
		}
		real := filepath.Join(dir, "real.txt")
		link := filepath.Join(dir, "link.txt")
		write(t, real, "old", 0o640)
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if err := WriteFileAtomic(link, []byte("new")); err != nil {
			t.Fatal(err)
		}
		if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
			t.Fatal("link was replaced by a file")
		}
		if read(t, real) != "new" || read(t, link) != "new" {
			t.Fatal("target not updated")
		}
		if fi, _ := os.Stat(real); fi.Mode().Perm() != 0o640 {
			t.Fatalf("mode = %v", fi.Mode().Perm())
		}
	})

	t.Run("symlink chain into another folder", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks")
		}
		other := t.TempDir()
		real := filepath.Join(other, "real.txt")
		write(t, real, "old", 0o600)
		mid := filepath.Join(dir, "mid.txt")
		link := filepath.Join(dir, "chain.txt")
		os.Symlink(real, mid)
		os.Symlink(mid, link)
		if err := WriteFileAtomic(link, []byte("new")); err != nil {
			t.Fatal(err)
		}
		if read(t, real) != "new" {
			t.Fatal("target not updated")
		}
	})

	t.Run("dangling symlink is refused", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks")
		}
		link := filepath.Join(dir, "dangling.txt")
		os.Symlink(filepath.Join(dir, "nowhere"), link)
		if err := WriteFileAtomic(link, []byte("x")); err == nil {
			t.Fatal("want error")
		}
	})

	t.Run("directory is refused and no temp file is left", func(t *testing.T) {
		d := filepath.Join(dir, "sub")
		os.Mkdir(d, 0o700)
		if err := WriteFileAtomic(d, []byte("x")); err == nil {
			t.Fatal("want error")
		}
	})

	t.Run("missing folder", func(t *testing.T) {
		if err := WriteFileAtomic(filepath.Join(dir, "no", "such", "f"), []byte("x")); err == nil {
			t.Fatal("want error")
		}
	})

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".grants-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// fixture creates two files and the changes that edit them.
func fixture(t *testing.T) (state string, files [2]string, changes []Change) {
	t.Helper()
	root := t.TempDir()
	state = filepath.Join(root, "state")
	files = [2]string{filepath.Join(root, "settings.json"), filepath.Join(root, "config.toml")}
	write(t, files[0], `{"a":["x","y"]}`, 0o644)
	write(t, files[1], "[a]\nk = \"1\"\n", 0o600)
	changes = []Change{
		{File: files[0], Before: []byte(`{"a":["x","y"]}`), After: []byte(`{"a":["y"]}`), GrantID: "g1", Summary: "remove x"},
		{File: files[1], Before: []byte("[a]\nk = \"1\"\n"), After: []byte("[a]\nk = \"2\"\n"), GrantID: "g2", Summary: "set k"},
	}
	return
}

func TestApplyAndUndo(t *testing.T) {
	state, files, changes := fixture(t)
	b, err := Apply(state, t0, changes)
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != "20260304T050607Z" || len(b.Files) != 2 || b.Undone {
		t.Fatalf("batch = %+v", b)
	}
	if read(t, files[0]) != `{"a":["y"]}` || read(t, files[1]) != "[a]\nk = \"2\"\n" {
		t.Fatal("files not changed")
	}
	if b.Files[0].AfterHash != hashHex([]byte(`{"a":["y"]}`)) || b.Files[0].GrantID != "g1" || b.Files[1].Summary != "set k" {
		t.Fatalf("batch files = %+v", b.Files)
	}
	for i, f := range b.Files {
		if filepath.Base(f.Backup) != []string{"1-settings.json", "2-config.toml"}[i] {
			t.Fatalf("backup name %q", f.Backup)
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(f.Backup); fi.Mode().Perm() != 0o600 {
				t.Fatalf("backup mode %v", fi.Mode().Perm())
			}
			if fi, _ := os.Stat(filepath.Dir(f.Backup)); fi.Mode().Perm() != 0o700 {
				t.Fatalf("backup dir mode %v", fi.Mode().Perm())
			}
		}
	}
	if read(t, b.Files[0].Backup) != `{"a":["x","y"]}` {
		t.Fatal("backup content")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(state, "journal.jsonl")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("journal mode %v", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(files[0]); fi.Mode().Perm() != 0o644 {
			t.Fatalf("edited file mode %v", fi.Mode().Perm())
		}
	}

	// The journal line has the documented shape.
	line := strings.TrimSpace(read(t, filepath.Join(state, "journal.jsonl")))
	var rec struct {
		Type  string
		Batch Batch
	}
	if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.Type != "apply" || rec.Batch.ID != b.ID {
		t.Fatalf("journal line %q (%v)", line, err)
	}

	list, err := Batches(state)
	if err != nil || len(list) != 1 || list[0].ID != b.ID || list[0].Undone || !list[0].Time.Equal(t0) {
		t.Fatalf("Batches = %+v, %v", list, err)
	}

	u, err := Undo(state, t0.Add(time.Hour), false)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Undone || u.ID != b.ID {
		t.Fatalf("undo batch = %+v", u)
	}
	if read(t, files[0]) != `{"a":["x","y"]}` || read(t, files[1]) != "[a]\nk = \"1\"\n" {
		t.Fatal("files not restored")
	}
	list, _ = Batches(state)
	if len(list) != 1 || !list[0].Undone {
		t.Fatalf("Batches after undo = %+v", list)
	}
	if _, err := Undo(state, t0, false); !errors.Is(err, ErrNothingToUndo) {
		t.Fatalf("second undo err = %v", err)
	}
}

func TestApplyChangedLeavesEverythingUntouched(t *testing.T) {
	state, files, changes := fixture(t)
	write(t, files[1], "[a]\nk = \"edited meanwhile\"\n", 0o600)
	_, err := Apply(state, t0, changes)
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
	if read(t, files[0]) != `{"a":["x","y"]}` || read(t, files[1]) != "[a]\nk = \"edited meanwhile\"\n" {
		t.Fatal("a file was touched")
	}
	if _, err := os.Stat(filepath.Join(state, "backups")); err == nil {
		entries, _ := os.ReadDir(filepath.Join(state, "backups"))
		if len(entries) != 0 {
			t.Fatal("backups written for a refused batch")
		}
	}
	if list, _ := Batches(state); len(list) != 0 {
		t.Fatalf("journal has %d batches", len(list))
	}
}

func TestApplyMissingFileIsChanged(t *testing.T) {
	state, files, changes := fixture(t)
	os.Remove(files[0])
	if _, err := Apply(state, t0, changes); !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyRejectsTwoChangesForOneFile(t *testing.T) {
	state, files, changes := fixture(t)
	changes = append(changes, Change{File: files[0], Before: changes[0].Before, After: []byte(`{}`)})
	if _, err := Apply(state, t0, changes); err == nil {
		t.Fatal("want error")
	}
	if read(t, files[0]) != `{"a":["x","y"]}` {
		t.Fatal("file touched")
	}
	if _, err := Apply(state, t0, nil); err == nil {
		t.Fatal("want error for no changes")
	}
}

func TestApplyRejectsTwoPathsToOneFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	state, files, changes := fixture(t)
	link := filepath.Join(filepath.Dir(files[0]), "link.json")
	os.Symlink(files[0], link)
	changes = append(changes, Change{File: link, Before: changes[0].Before, After: []byte(`{}`)})
	if _, err := Apply(state, t0, changes); err == nil {
		t.Fatal("want error")
	}
}

func TestApplyThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	state, files, changes := fixture(t)
	link := filepath.Join(filepath.Dir(files[0]), "link.json")
	os.Symlink(files[0], link)
	changes = changes[:1]
	changes[0].File = link
	if _, err := Apply(state, t0, changes); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link replaced")
	}
	if read(t, files[0]) != `{"a":["y"]}` {
		t.Fatal("target not changed")
	}
	if _, err := Undo(state, t0, false); err != nil {
		t.Fatal(err)
	}
	if read(t, files[0]) != `{"a":["x","y"]}` {
		t.Fatal("target not restored")
	}
}

func TestApplyFailureMidBatchRestoresWrittenFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("folder permissions")
	}
	if os.Getuid() == 0 {
		t.Skip("root ignores folder permissions")
	}
	root := t.TempDir()
	state := filepath.Join(root, "state")
	okDir := filepath.Join(root, "ok")
	roDir := filepath.Join(root, "ro")
	os.Mkdir(okDir, 0o700)
	os.Mkdir(roDir, 0o700)
	f1, f2 := filepath.Join(okDir, "a.json"), filepath.Join(roDir, "b.json")
	write(t, f1, "one", 0o600)
	write(t, f2, "two", 0o600)
	// A read-only folder lets us read the file but not create the temp file beside it.
	os.Chmod(roDir, 0o500)
	defer os.Chmod(roDir, 0o700)

	_, err := Apply(state, t0, []Change{
		{File: f1, Before: []byte("one"), After: []byte("ONE")},
		{File: f2, Before: []byte("two"), After: []byte("TWO")},
	})
	if err == nil {
		t.Fatal("want error")
	}
	if errors.Is(err, ErrChanged) {
		t.Fatalf("wrong error: %v", err)
	}
	if read(t, f1) != "one" || read(t, f2) != "two" {
		t.Fatalf("files not restored: %q %q", read(t, f1), read(t, f2))
	}
	if list, _ := Batches(state); len(list) != 0 {
		t.Fatal("failed batch was journaled")
	}
	if entries, _ := os.ReadDir(filepath.Join(state, "backups")); len(entries) != 0 {
		t.Fatal("backup folder of a failed batch was kept")
	}
}

func TestUndoRefusesChangedFilesAndForceWorks(t *testing.T) {
	state, files, changes := fixture(t)
	if _, err := Apply(state, t0, changes); err != nil {
		t.Fatal(err)
	}
	write(t, files[1], "[a]\nk = \"agent rewrote it\"\n", 0o600)

	_, err := Undo(state, t0, false)
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
	// Nothing was restored, not even the unchanged file.
	if read(t, files[0]) != `{"a":["y"]}` || read(t, files[1]) != "[a]\nk = \"agent rewrote it\"\n" {
		t.Fatal("refused undo wrote files")
	}
	if list, _ := Batches(state); list[0].Undone {
		t.Fatal("refused undo was journaled")
	}

	if _, err := Undo(state, t0, true); err != nil {
		t.Fatal(err)
	}
	if read(t, files[0]) != `{"a":["x","y"]}` || read(t, files[1]) != "[a]\nk = \"1\"\n" {
		t.Fatal("force did not restore")
	}
}

func TestUndoForceWhenFileDeleted(t *testing.T) {
	state, files, changes := fixture(t)
	Apply(state, t0, changes)
	os.Remove(files[0])
	if _, err := Undo(state, t0, false); !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Undo(state, t0, true); err != nil {
		t.Fatal(err)
	}
	if read(t, files[0]) != `{"a":["x","y"]}` {
		t.Fatal("not restored")
	}
}

func TestUndoNothing(t *testing.T) {
	root := t.TempDir()
	if _, err := Undo(filepath.Join(root, "missing"), t0, false); !errors.Is(err, ErrNothingToUndo) {
		t.Fatalf("missing state: %v", err)
	}
	if _, err := Undo(root, t0, false); !errors.Is(err, ErrNothingToUndo) {
		t.Fatalf("empty state: %v", err)
	}
}

func TestUndoTakesLatestNotUndoneBatch(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	f := filepath.Join(root, "f.txt")
	write(t, f, "v0", 0o600)
	step := func(from, to string, at time.Time) Batch {
		b, err := Apply(state, at, []Change{{File: f, Before: []byte(from), After: []byte(to)}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b1 := step("v0", "v1", t0)
	b2 := step("v1", "v2", t0.Add(time.Minute))

	list, _ := Batches(state)
	if len(list) != 2 || list[0].ID != b2.ID || list[1].ID != b1.ID {
		t.Fatalf("order: %+v", list)
	}
	if u, err := Undo(state, t0, false); err != nil || u.ID != b2.ID || read(t, f) != "v1" {
		t.Fatalf("first undo: %+v %v %q", u, err, read(t, f))
	}
	if u, err := Undo(state, t0, false); err != nil || u.ID != b1.ID || read(t, f) != "v0" {
		t.Fatalf("second undo: %+v %v %q", u, err, read(t, f))
	}
	if _, err := Undo(state, t0, false); !errors.Is(err, ErrNothingToUndo) {
		t.Fatalf("third undo: %v", err)
	}
	list, _ = Batches(state)
	if !list[0].Undone || !list[1].Undone {
		t.Fatalf("undone flags: %+v", list)
	}
	// A new apply after undos is the next undo target.
	b3 := step("v0", "v3", t0.Add(2*time.Minute))
	if u, err := Undo(state, t0, false); err != nil || u.ID != b3.ID {
		t.Fatalf("undo b3: %+v %v", u, err)
	}
}

func TestBatchIDsAreUnique(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	f := filepath.Join(root, "f.txt")
	write(t, f, "0", 0o600)
	var ids []string
	for i := 0; i < 3; i++ {
		b, err := Apply(state, t0, []Change{{File: f, Before: []byte(string(rune('0' + i))), After: []byte(string(rune('1' + i)))}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, b.ID)
	}
	want := []string{"20260304T050607Z", "20260304T050607Z-2", "20260304T050607Z-3"}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %v, want %v", ids, want)
		}
	}
	// An ID that only the journal knows (backups folder cleaned) is still taken.
	os.RemoveAll(filepath.Join(state, "backups"))
	b, err := Apply(state, t0, []Change{{File: f, Before: []byte("3"), After: []byte("4")}})
	if err != nil || b.ID != "20260304T050607Z-4" {
		t.Fatalf("id = %q, %v", b.ID, err)
	}
	// Times are formatted in UTC whatever the zone of now.
	zone := time.FixedZone("x", 5*3600)
	b, err = Apply(state, time.Date(2026, 3, 4, 10, 6, 7, 0, zone), []Change{{File: f, Before: []byte("4"), After: []byte("5")}})
	if err != nil || b.ID != "20260304T050607Z-5" {
		t.Fatalf("id = %q, %v", b.ID, err)
	}
}

func TestConcurrentApplyUsesTheLock(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	const n = 8
	var wg sync.WaitGroup
	ids := make(chan string, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		f := filepath.Join(root, "f"+string(rune('a'+i)))
		write(t, f, "old", 0o600)
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := Apply(state, t0, []Change{{File: f, Before: []byte("old"), After: []byte("new")}})
			if err != nil {
				errs <- err
				return
			}
			ids <- b.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate batch id %s", id)
		}
		seen[id] = true
	}
	list, err := Batches(state)
	if err != nil || len(list) != n {
		t.Fatalf("journal has %d batches (%v)", len(list), err)
	}
}

func TestJournalRoundTripAndDamage(t *testing.T) {
	state, files, changes := fixture(t)
	b, err := Apply(state, t0, changes)
	if err != nil {
		t.Fatal(err)
	}
	// Garbage, an unknown record, and a line cut short must not hide the real batch.
	jp := filepath.Join(state, "journal.jsonl")
	data := read(t, jp)
	data = "not json\n" + `{"type":"future","x":1}` + "\n" + data + `{"type":"apply","batch":{"id":"cut` // no newline
	write(t, jp, data, 0o600)
	list, err := Batches(state)
	if err != nil || len(list) != 1 {
		t.Fatalf("Batches = %+v, %v", list, err)
	}
	got := list[0]
	if got.ID != b.ID || len(got.Files) != 2 || got.Files[0] != b.Files[0] || got.Files[1] != b.Files[1] || !got.Time.Equal(b.Time) {
		t.Fatalf("round trip lost data:\n got %+v\nwant %+v", got, b)
	}
	if _, err := Undo(state, t0, false); err != nil {
		t.Fatal(err)
	}
	if read(t, files[0]) != `{"a":["x","y"]}` {
		t.Fatal("undo after damaged journal")
	}
	if list, _ := Batches(state); len(list) != 1 || !list[0].Undone {
		t.Fatalf("undo record lost behind a cut line: %+v", list)
	}
}

func TestBatchesMissingJournal(t *testing.T) {
	list, err := Batches(filepath.Join(t.TempDir(), "none"))
	if err != nil || len(list) != 0 {
		t.Fatalf("Batches = %v, %v", list, err)
	}
}

func TestUndoFindsMovedBackups(t *testing.T) {
	state, files, changes := fixture(t)
	b, _ := Apply(state, t0, changes)
	moved := state + "-moved"
	if err := os.Rename(state, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := Undo(moved, t0, false); err != nil {
		t.Fatal(err)
	}
	if read(t, files[0]) != `{"a":["x","y"]}` {
		t.Fatalf("not restored (batch %s)", b.ID)
	}
}

func TestApplyWithRealEditFunctions(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	js := filepath.Join(root, "settings.json")
	tm := filepath.Join(root, "config.toml")
	jdoc := "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(npm test:*)\",\n      \"Read\"\n    ]\n  }\n}\n"
	tdoc := "[projects.\"/work/app\"]\ntrust_level = \"trusted\"\n"
	write(t, js, jdoc, 0o600)
	write(t, tm, tdoc, 0o600)
	jnew, n, err := RemoveArrayString([]byte(jdoc), []string{"permissions", "allow"}, "Bash(npm test:*)")
	if err != nil || n != 1 {
		t.Fatal(err, n)
	}
	tnew, err := TOMLSetString([]byte(tdoc), []string{"projects", "/work/app"}, "trust_level", "untrusted")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(state, t0, []Change{
		{File: js, Before: []byte(jdoc), After: jnew},
		{File: tm, Before: []byte(tdoc), After: tnew},
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(read(t, js)), jnew) || !bytes.Equal([]byte(read(t, tm)), tnew) {
		t.Fatal("content")
	}
	if _, err := Undo(state, t0, false); err != nil {
		t.Fatal(err)
	}
	if read(t, js) != jdoc || read(t, tm) != tdoc {
		t.Fatal("undo")
	}
}
