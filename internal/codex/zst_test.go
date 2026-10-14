package codex

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/yihanzhu/grants/internal/scan"
)

// compressSessions turns every session file into a .jsonl.zst copy, as Codex does for
// older sessions. With keep, the plain file stays too.
func compressSessions(t *testing.T, codexHome string, keep bool) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(codexHome, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jsonl") {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		enc, _ := zstd.NewWriter(nil)
		if err := os.WriteFile(p+".zst", enc.EncodeAll(data, nil), 0o600); err != nil {
			return err
		}
		n++
		if !keep {
			return os.Remove(p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// sameReport compares two reports, ignoring the .zst suffix in evidence file names.
func sameReport(t *testing.T, a, b any) {
	t.Helper()
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if strings.ReplaceAll(string(jb), ".jsonl.zst", ".jsonl") != string(ja) {
		t.Errorf("reports differ:\n%s\n%s", ja, jb)
	}
}

func TestCollectReadsCompressedSessions(t *testing.T) {
	f := newFixture(t)
	plain := Collect(f.env, scan.Options{NoCache: true})
	if compressSessions(t, f.env.CodexHome, false) == 0 {
		t.Fatal("fixture has no session files")
	}
	sameReport(t, plain, Collect(f.env, scan.Options{NoCache: true}))
}

func TestCollectSkipsCompressedTwin(t *testing.T) {
	f := newFixture(t)
	plain := Collect(f.env, scan.Options{NoCache: true})
	compressSessions(t, f.env.CodexHome, true)
	sameReport(t, plain, Collect(f.env, scan.Options{NoCache: true}))
}

func TestWithoutCompressedTwins(t *testing.T) {
	got := withoutCompressedTwins([]string{"/s/a.jsonl", "/s/a.jsonl.zst", "/s/b.jsonl.zst", "/s/c.jsonl"})
	want := []string{"/s/a.jsonl", "/s/b.jsonl.zst", "/s/c.jsonl"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}
