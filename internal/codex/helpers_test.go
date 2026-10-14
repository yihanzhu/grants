package codex

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helpers that write rollout files with the record shapes Codex uses. All content is
// synthetic.

func at(day, hour, min int) time.Time {
	return time.Date(2026, 3, day, hour, min, 0, 0, time.UTC)
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

type rollout struct {
	lines []string
}

func (r *rollout) add(t time.Time, typ string, payload any) *rollout {
	p, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	// Real files put the timestamp first and the type before the payload.
	ts, _ := json.Marshal(stamp(t))
	ty, _ := json.Marshal(typ)
	line := fmt.Sprintf(`{"timestamp":%s,"ordinal":%d,"type":%s,"payload":%s}`, ts, len(r.lines), ty, p)
	r.lines = append(r.lines, line)
	return r
}

func (r *rollout) meta(t time.Time, cwd string, source any) *rollout {
	p := map[string]any{"id": "s", "cwd": cwd}
	if source != nil {
		p["source"] = source
	}
	return r.add(t, "session_meta", p)
}

// devSnapshot adds a developer message listing the approved prefixes the way Codex
// words it: the first entry follows the sentence, later entries are on their own lines.
func (r *rollout) devSnapshot(t time.Time, prefixes ...[]string) *rollout {
	var sb strings.Builder
	sb.WriteString("<permissions instructions>\n## Approved command prefixes\nThe following prefix rules have already been approved: ")
	for i, p := range prefixes {
		b, _ := json.Marshal(p)
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("- " + strings.ReplaceAll(string(b), ",", ", "))
	}
	sb.WriteString("\n The writable roots are `/work`.\n</permissions instructions>")
	return r.add(t, "response_item", map[string]any{
		"type": "message", "role": "developer",
		"content": []any{map[string]any{"type": "input_text", "text": sb.String()}, map[string]any{"type": "input_text", "text": "other"}},
	})
}

func (r *rollout) worldState(t time.Time, prefixes ...[]string) *rollout {
	if prefixes == nil {
		prefixes = [][]string{}
	}
	return r.add(t, "world_state", map[string]any{"full": true, "state": map[string]any{
		"model": "m", "permissions": map[string]any{"approved_command_prefixes": prefixes, "instructions": "x"},
	}})
}

func (r *rollout) call(t time.Time, name, callID string, args map[string]any) *rollout {
	b, _ := json.Marshal(args)
	return r.add(t, "response_item", map[string]any{"type": "function_call", "name": name, "call_id": callID, "arguments": string(b)})
}

func (r *rollout) callOutput(t time.Time, callID, output string) *rollout {
	return r.add(t, "response_item", map[string]any{"type": "function_call_output", "call_id": callID, "output": output})
}

func (r *rollout) cmdItem(t time.Time, id, status string, argv ...string) *rollout {
	return r.add(t, "event_msg", map[string]any{"type": "item_completed", "thread_id": "s", "item": map[string]any{
		"type": "CommandExecution", "id": id, "status": status, "command": argv, "cwd": "/work", "aggregated_output": "x",
	}})
}

func (r *rollout) noise(t time.Time) *rollout {
	return r.add(t, "event_msg", map[string]any{"type": "token_count", "info": nil})
}

func (r *rollout) bytes() []byte { return []byte(strings.Join(r.lines, "\n") + "\n") }

func (r *rollout) write(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, r.bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
