package jsonl

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func lines(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	if err := EachFile(path, func(l []byte) error { out = append(out, string(l)); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEachFilePlainAndZstd(t *testing.T) {
	long := strings.Repeat("x", 3<<20) // longer than the read buffer
	data := "first\n\n" + long + "\nlast"
	dir := t.TempDir()
	plain := filepath.Join(dir, "a.jsonl")
	if err := os.WriteFile(plain, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	enc, _ := zstd.NewWriter(nil)
	packed := filepath.Join(dir, "a.jsonl.zst")
	if err := os.WriteFile(packed, enc.EncodeAll([]byte(data), nil), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []string{"first", long, "last"}
	if got := lines(t, plain); !reflect.DeepEqual(got, want) {
		t.Errorf("plain: %d lines", len(got))
	}
	if got := lines(t, packed); !reflect.DeepEqual(got, want) {
		t.Errorf("zstd: %d lines", len(got))
	}
}

func TestEachFileBadZstd(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.jsonl.zst")
	if err := os.WriteFile(p, []byte("not zstd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EachFile(p, func([]byte) error { return nil }); err == nil {
		t.Error("want an error for a file that is not zstd")
	}
}
