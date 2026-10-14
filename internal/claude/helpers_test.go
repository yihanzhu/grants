package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic fixtures. Paths and names are made up and live under t.TempDir().

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setMtime(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func js(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

type m = map[string]any

// Transcript record builders, shaped like real Claude Code records.

func toolUseLine(when, cwd, session, uuid, id, name string, input m) string {
	return js(m{
		"type": "assistant", "uuid": uuid, "timestamp": when, "cwd": cwd, "sessionId": session,
		"message": m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": id, "name": name, "input": input}}},
	})
}

func resultLine(when, cwd, session, uuid string, result any, extra m) string {
	rec := m{
		"type": "user", "uuid": uuid, "timestamp": when, "cwd": cwd, "sessionId": session,
		"message": m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "x", "content": "ok"}}},
	}
	if result != nil {
		rec["toolUseResult"] = result
	}
	for k, v := range extra {
		rec[k] = v
	}
	return js(rec)
}

func lines(ls ...string) string { return strings.Join(ls, "\n") + "\n" }
