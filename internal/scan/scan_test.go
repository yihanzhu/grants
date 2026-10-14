package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type facts struct {
	N     int
	Names []string
	Use   map[uint64]int32
}

// counter builds an extractor that counts calls.
func counter(calls *atomic.Int32) func(string) (facts, error) {
	return func(p string) (facts, error) {
		calls.Add(1)
		b, err := os.ReadFile(p)
		if err != nil {
			return facts{}, err
		}
		return facts{N: len(b), Names: []string{filepath.Base(p)}, Use: map[uint64]int32{7: 2}}, nil
	}
}

func write(t *testing.T, p, s string, mt time.Time) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) (dir string, files []string, mt time.Time) {
	t.Helper()
	dir = t.TempDir()
	mt = time.Unix(1_700_000_000, 123)
	for _, n := range []string{"a", "b", "c"} {
		p := filepath.Join(dir, n+".jsonl")
		write(t, p, "content of "+n, mt)
		files = append(files, p)
	}
	return dir, files, mt
}

func openCache(t *testing.T, dir string, version int) *Cache {
	t.Helper()
	c, err := Open(filepath.Join(dir, "state"), "t", version)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRunCachesAndReuses(t *testing.T) {
	dir, files, _ := setup(t)
	var calls atomic.Int32
	c := openCache(t, dir, 1)
	out, st := Run(c, files, Options{}, "s", counter(&calls))
	if st.Scanned != 3 || st.Cached != 0 || st.Failed != 0 || calls.Load() != 3 {
		t.Fatalf("cold: %+v calls=%d", st, calls.Load())
	}
	if st.Bytes != int64(len("content of a")*3) {
		t.Fatalf("bytes = %d", st.Bytes)
	}
	if out[files[0]].N != len("content of a") || out[files[0]].Use[7] != 2 {
		t.Fatalf("bad result %+v", out[files[0]])
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "state", "cache-t.gob"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file: %v %v", info, err)
	}
	if d, _ := os.Stat(filepath.Join(dir, "state")); d.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", d.Mode().Perm())
	}

	c2 := openCache(t, dir, 1)
	out2, st2 := Run(c2, files, Options{}, "s", counter(&calls))
	if st2.Cached != 3 || st2.Scanned != 0 || st2.Bytes != 0 || calls.Load() != 3 {
		t.Fatalf("warm: %+v calls=%d", st2, calls.Load())
	}
	if out2[files[2]].Names[0] != "c.jsonl" || out2[files[2]].Use[7] != 2 {
		t.Fatalf("bad cached result %+v", out2[files[2]])
	}
}

func TestRunInvalidation(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, p string, mt time.Time)
	}{
		{"size", func(t *testing.T, p string, mt time.Time) { write(t, p, "content of a plus", mt) }},
		{"mtime", func(t *testing.T, p string, mt time.Time) { write(t, p, "content of a", mt.Add(time.Second)) }},
		{"mtime ns", func(t *testing.T, p string, mt time.Time) { write(t, p, "content of a", mt.Add(time.Nanosecond)) }},
		{"head", func(t *testing.T, p string, mt time.Time) { write(t, p, "CONTENT of a", mt) }}, // same size, same mtime
		{"inode", func(t *testing.T, p string, mt time.Time) {
			// Replace the file by another one with the same bytes and mtime.
			tmp := p + ".new"
			write(t, tmp, "content of a", mt)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, p); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, files, mt := setup(t)
			var calls atomic.Int32
			c := openCache(t, dir, 1)
			Run(c, files, Options{}, "s", counter(&calls))
			tc.change(t, files[0], mt)
			if tc.name == "inode" && inodeOf(mustStat(t, files[0])) == 0 {
				t.Skip("no inode on this platform")
			}
			calls.Store(0)
			_, st := Run(c, files, Options{}, "s", counter(&calls))
			if st.Scanned != 1 || st.Cached != 2 || calls.Load() != 1 {
				t.Fatalf("%+v calls=%d", st, calls.Load())
			}
		})
	}
}

func mustStat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func TestRunVersionAndCorrupt(t *testing.T) {
	dir, files, _ := setup(t)
	var calls atomic.Int32
	c := openCache(t, dir, 1)
	Run(c, files, Options{}, "s", counter(&calls))
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	calls.Store(0)
	c2 := openCache(t, dir, 2) // version bump starts empty
	_, st := Run(c2, files, Options{}, "s", counter(&calls))
	if st.Cached != 0 || st.Scanned != 3 {
		t.Fatalf("version bump: %+v", st)
	}
	if err := c2.Save(); err != nil {
		t.Fatal(err)
	}

	cf := filepath.Join(dir, "state", "cache-t.gob")
	if err := os.WriteFile(cf, []byte("not a gob file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	c3 := openCache(t, dir, 2)
	_, st = Run(c3, files, Options{}, "s", counter(&calls))
	if st.Cached != 0 || st.Scanned != 3 {
		t.Fatalf("corrupt: %+v", st)
	}
	if err := c3.Save(); err != nil { // must replace the corrupt file
		t.Fatal(err)
	}
	c4 := openCache(t, dir, 2)
	if _, st = Run(c4, files, Options{}, "s", counter(&calls)); st.Cached != 3 {
		t.Fatalf("after repair: %+v", st)
	}
}

func TestRunCorruptEntryRescans(t *testing.T) {
	dir, files, _ := setup(t)
	var calls atomic.Int32
	c := openCache(t, dir, 1)
	Run(c, files, Options{}, "s", counter(&calls))
	c.mu.Lock()
	e := c.entries[files[1]]
	e.Data = []byte("garbage")
	c.entries[files[1]] = e
	c.mu.Unlock()
	_, st := Run(c, files, Options{}, "s", counter(&calls))
	if st.Cached != 2 || st.Scanned != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestRunPrunes(t *testing.T) {
	dir, files, _ := setup(t)
	var calls atomic.Int32
	c := openCache(t, dir, 1)
	Run(c, files, Options{}, "s", counter(&calls))
	Run(c, files[:1], Options{}, "s", counter(&calls))
	if len(c.entries) != 1 {
		t.Fatalf("entries = %d", len(c.entries))
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if n := len(openCache(t, dir, 1).entries); n != 1 {
		t.Fatalf("saved entries = %d", n)
	}
}

func TestRunFailures(t *testing.T) {
	dir, files, _ := setup(t)
	missing := filepath.Join(dir, "gone.jsonl")
	c := openCache(t, dir, 1)
	fail := func(p string) (facts, error) { return facts{}, fmt.Errorf("boom") }
	out, st := Run(c, append(files, missing), Options{}, "s", fail)
	if st.Failed != 4 || len(out) != 0 || len(st.Errors) == 0 || len(st.Errors) > 5 {
		t.Fatalf("%+v out=%v", st, out)
	}
	if len(c.entries) != 0 {
		t.Fatal("failed files must not be cached")
	}
}

func TestRunNilCacheAndNoCache(t *testing.T) {
	dir, files, _ := setup(t)
	var calls atomic.Int32
	_, st := Run(nil, files, Options{}, "s", counter(&calls))
	if st.Scanned != 3 || st.Bytes == 0 {
		t.Fatalf("%+v", st)
	}
	c := openCache(t, dir, 1)
	Run(c, files, Options{NoCache: true}, "s", counter(&calls))
	if len(c.entries) != 0 || c.dirty {
		t.Fatal("NoCache must not write the cache")
	}
	var nc *Cache
	if err := nc.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestSaveOnlyWhenChanged(t *testing.T) {
	dir, files, _ := setup(t)
	var calls atomic.Int32
	c := openCache(t, dir, 1)
	Run(c, files, Options{}, "s", counter(&calls))
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	cf := filepath.Join(dir, "state", "cache-t.gob")
	old := time.Unix(1_600_000_000, 0)
	os.Chtimes(cf, old, old)
	c2 := openCache(t, dir, 1)
	Run(c2, files, Options{}, "s", counter(&calls))
	if err := c2.Save(); err != nil {
		t.Fatal(err)
	}
	if !mustStat(t, cf).ModTime().Equal(old) {
		t.Fatal("unchanged cache was rewritten")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "state", "*.tmp")); len(m) != 0 {
		t.Fatalf("temp files left: %v", m)
	}
}

func TestProgress(t *testing.T) {
	dir := t.TempDir()
	var files []string
	for i := range 250 {
		p := filepath.Join(dir, fmt.Sprintf("f%03d", i))
		write(t, p, "x", time.Unix(1_700_000_000, 0))
		files = append(files, p)
	}
	var got [][2]int
	opt := Options{Workers: 4, Progress: func(stage string, done, total int) {
		if stage != "st" {
			t.Errorf("stage %q", stage)
		}
		got = append(got, [2]int{done, total})
	}}
	var calls atomic.Int32
	Run(nil, files, opt, "st", counter(&calls))
	want := [][2]int{{100, 250}, {200, 250}, {250, 250}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("progress = %v", got)
	}
	got = nil
	Run(nil, nil, opt, "st", counter(&calls))
	if len(got) != 1 || got[0] != [2]int{0, 0} {
		t.Fatalf("empty progress = %v", got)
	}
}

func TestRunConcurrent(t *testing.T) {
	dir := t.TempDir()
	var files []string
	for i := range 300 {
		p := filepath.Join(dir, fmt.Sprintf("f%03d", i))
		write(t, p, fmt.Sprint("data", i), time.Unix(1_700_000_000, int64(i)))
		files = append(files, p)
	}
	c := openCache(t, dir, 1)
	var calls atomic.Int32
	opt := Options{Workers: 16}
	out, st := Run(c, files, opt, "s", counter(&calls))
	if st.Scanned != 300 || len(out) != 300 {
		t.Fatalf("%+v", st)
	}
	// Two runs at once on the same cache, plus a save.
	done := make(chan Stats, 2)
	for range 2 {
		go func() { _, s := Run(c, files, opt, "s", counter(&calls)); done <- s }()
	}
	go c.Save()
	for range 2 {
		if s := <-done; s.Cached != 300 {
			t.Fatalf("%+v", s)
		}
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestWalk(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755)
	os.WriteFile(filepath.Join(dir, "a", "x.jsonl"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "a", "b", "y.jsonl"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "a", "z.txt"), nil, 0o644)
	files, skipped, err := Walk(dir, func(p string) bool { return filepath.Ext(p) == ".jsonl" })
	if err != nil || skipped != 0 || len(files) != 2 {
		t.Fatalf("%v %d %v", files, skipped, err)
	}
	files, _, err = Walk(filepath.Join(dir, "nope"), func(string) bool { return true })
	if err != nil || len(files) != 0 {
		t.Fatalf("missing root: %v %v", files, err)
	}
}
