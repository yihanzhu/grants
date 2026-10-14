package codex

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yihanzhu/grants/internal/match"
)

func extract(t *testing.T, r *rollout) RolloutFacts {
	t.Helper()
	p := r.write(t, filepath.Join(t.TempDir(), "rollout-test.jsonl"))
	f, err := ExtractRollout(p)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func count(f RolloutFacts, k match.Key) int { return int(f.Usage[k].Count) }

func TestParsePrefixList(t *testing.T) {
	tests := []struct {
		name string
		text string
		want [][]string
	}{
		{"empty", "## Approved command prefixes\nThe following prefix rules have already been approved: \n The writable roots", nil},
		{"one", "## Approved command prefixes\nThe following prefix rules have already been approved: - [\"git\", \"add\"]\n The writable", [][]string{{"git", "add"}}},
		{"several", "## Approved command prefixes\nThe following prefix rules have already been approved: - [\"a\", \"b\"]\n- [\"c\"]\n- [\"d\", \"e\", \"f\"]\n\n</permissions>", [][]string{{"a", "b"}, {"c"}, {"d", "e", "f"}}},
		{"escapes", "## Approved command prefixes\nx: - [\"sh\", \"-c\", \"echo \\\"hi\\\"\\nls\"]\n", [][]string{{"sh", "-c", "echo \"hi\"\nls"}}},
		{"bad line skipped", "## Approved command prefixes\nx: - [\"a\"]\n- [not json\n- [\"b\"]\n", [][]string{{"a"}, {"b"}}},
		{"crlf", "## Approved command prefixes\r\nx: - [\"a\"]\r\n- [\"b\"]\r\n", [][]string{{"a"}, {"b"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePrefixList(tt.text)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSnapshots(t *testing.T) {
	git := []string{"git", "status"}
	npm := []string{"npm", "test"}
	r := &rollout{}
	r.meta(at(5, 10, 0), "/work/app", "vscode").
		devSnapshot(at(5, 10, 1), git).
		noise(at(5, 10, 2)).
		devSnapshot(at(5, 10, 3), git).      // identical: merged
		devSnapshot(at(5, 10, 4), npm, git). // changed
		devSnapshot(at(5, 10, 5), git, npm). // same set, other order: merged
		worldState(at(5, 10, 6), git).       // changed again
		worldState(at(5, 10, 7), git).       // merged
		noise(at(5, 11, 0))
	f := extract(t, r)
	if f.Cwd != "/work/app" || f.Source != "vscode" {
		t.Errorf("cwd=%q source=%q", f.Cwd, f.Source)
	}
	if !f.Start.Equal(at(5, 10, 0)) || !f.End.Equal(at(5, 11, 0)) {
		t.Errorf("start=%v end=%v", f.Start, f.End)
	}
	if len(f.Prefixes) != 3 {
		t.Fatalf("runs = %+v", f.Prefixes)
	}
	r0, r1, r2 := f.Prefixes[0], f.Prefixes[1], f.Prefixes[2]
	if !r0.From.Equal(at(5, 10, 1)) || !r0.To.Equal(at(5, 10, 3)) || !reflect.DeepEqual(r0.Prefixes, [][]string{git}) {
		t.Errorf("run 0 = %+v", r0)
	}
	if !r1.From.Equal(at(5, 10, 4)) || !r1.To.Equal(at(5, 10, 5)) || len(r1.Prefixes) != 2 {
		t.Errorf("run 1 = %+v", r1)
	}
	if !r2.From.Equal(at(5, 10, 6)) || !r2.To.Equal(at(5, 10, 7)) {
		t.Errorf("run 2 = %+v", r2)
	}
}

func TestExtractSubagentEmptySnapshotIgnored(t *testing.T) {
	sub := &rollout{}
	sub.meta(at(5, 10, 0), "/work/app", map[string]any{"subagent": map[string]any{"other": "guardian"}}).
		worldState(at(5, 10, 1)). // empty: says nothing
		worldState(at(5, 10, 2), []string{"git", "status"})
	f := extract(t, sub)
	if f.Source != "subagent" {
		t.Errorf("source = %q", f.Source)
	}
	if len(f.Prefixes) != 1 || len(f.Prefixes[0].Prefixes) != 1 {
		t.Errorf("runs = %+v", f.Prefixes)
	}

	main := &rollout{}
	main.meta(at(5, 10, 0), "/work/app", "cli").
		worldState(at(5, 10, 1), []string{"git", "status"}).
		worldState(at(5, 10, 2)) // the user's rules are all gone
	f = extract(t, main)
	if len(f.Prefixes) != 2 || len(f.Prefixes[1].Prefixes) != 0 {
		t.Errorf("an empty snapshot from a main session must count: %+v", f.Prefixes)
	}
}

func TestExtractWorldStateDeltaWithoutPrefixes(t *testing.T) {
	r := &rollout{}
	r.meta(at(5, 10, 0), "/work", "cli")
	r.add(at(5, 10, 1), "world_state", map[string]any{"full": false, "state": map[string]any{"permissions": map[string]any{"instructions": "x"}}})
	r.add(at(5, 10, 2), "world_state", map[string]any{"full": false, "state": map[string]any{"approved_command_prefixes_note": 1}})
	f := extract(t, r)
	if len(f.Prefixes) != 0 {
		t.Errorf("runs = %+v", f.Prefixes)
	}
}

func TestExtractEscalationsAndUsage(t *testing.T) {
	r := &rollout{}
	r.meta(at(5, 10, 0), "/work/app", "vscode")
	// 1: escalated with a prefix, ran
	r.call(at(5, 10, 1), "exec_command", "c1", map[string]any{
		"cmd": "curl -s https://example.com/a", "sandbox_permissions": "require_escalated",
		"prefix_rule": []string{"curl", "-s"}, "justification": "fetch the page with token=abc123secretvalue",
	})
	r.callOutput(at(5, 10, 2), "c1", "Chunk ID: 1\nOutput: ok")
	// 2: escalated, refused
	r.call(at(5, 10, 3), "exec_command", "c2", map[string]any{
		"cmd": "rm -rf build", "sandbox_permissions": "require_escalated", "prefix_rule": []string{"rm", "-rf"}, "justification": "clean",
	})
	r.callOutput(at(5, 10, 4), "c2", "exec_command failed: rejected by user")
	// 3: escalated without a proposed prefix, ran
	r.call(at(5, 10, 5), "exec_command", "c3", map[string]any{"cmd": "make deploy", "sandbox_permissions": "require_escalated"})
	r.callOutput(at(5, 10, 6), "c3", "Command: make deploy")
	// 4: plain command seen as a call and again as a completed item with the same id
	r.call(at(5, 10, 7), "exec_command", "c4", map[string]any{"cmd": "git status"})
	r.cmdItem(at(5, 10, 8), "c4", "completed", "/bin/zsh", "-lc", "git status")
	// 5: item only (code mode), failed status still counts
	r.cmdItem(at(5, 10, 9), "i5", "failed", "npm", "test")
	// 6: declined item does not count
	r.cmdItem(at(5, 10, 10), "i6", "declined", "git", "push")
	// 7: older shell function with an argv
	r.call(at(5, 10, 11), "shell", "c7", map[string]any{"command": []string{"bash", "-lc", "ls -la"}})
	// 8: escalated call that has an item but no output record
	r.call(at(5, 10, 12), "exec_command", "c8", map[string]any{"cmd": "go test ./...", "sandbox_permissions": "require_escalated", "prefix_rule": []string{"go", "test"}})
	r.cmdItem(at(5, 10, 13), "c8", "completed", "go", "test", "./...")
	// 9: local_shell_call
	r.add(at(5, 10, 14), "response_item", map[string]any{"type": "local_shell_call", "call_id": "l9", "action": map[string]any{"type": "exec", "command": []string{"cat", "x.txt"}}})
	r.noise(at(5, 10, 15))
	f := extract(t, r)

	if len(f.Escalations) != 3 {
		t.Fatalf("escalations = %+v", f.Escalations)
	}
	e := f.Escalations[0]
	if !reflect.DeepEqual(e.Prefix, []string{"curl", "-s"}) || !e.Ran || !e.T.Equal(at(5, 10, 1)) {
		t.Errorf("escalation 0 = %+v", e)
	}
	if !strings.HasPrefix(e.Justification, "fetch the page") || len([]rune(e.Justification)) > 160 {
		t.Errorf("justification = %q", e.Justification)
	}
	if f.Escalations[1].Ran {
		t.Error("a refused escalation must not be marked as run")
	}
	if !f.Escalations[2].Ran {
		t.Error("an escalation whose item completed must be marked as run")
	}

	checks := []struct {
		name string
		key  match.Key
		want int
	}{
		{"curl ran", match.PrefixKey([]string{"curl"}), 1},
		{"refused rm not counted", match.PrefixKey([]string{"rm"}), 0},
		{"make deploy", match.PrefixKey([]string{"make", "deploy"}), 1},
		{"git status once", match.PrefixKey([]string{"git", "status"}), 1},
		{"the call is counted, not the item with the same id", match.PrefixKey([]string{"zsh"}), 0},
		{"npm test from item", match.PrefixKey([]string{"npm", "test"}), 1},
		{"declined push not counted", match.PrefixKey([]string{"git", "push"}), 0},
		{"shell argv script", match.PrefixKey([]string{"ls"}), 1},
		{"go test", match.PrefixKey([]string{"go", "test"}), 1},
		{"local shell", match.PrefixKey([]string{"cat"}), 1},
	}
	for _, c := range checks {
		if got := count(f, c.key); got != c.want {
			t.Errorf("%s: count = %d, want %d", c.name, got, c.want)
		}
	}
	if u := f.Usage[match.PrefixKey([]string{"git", "status"})]; u.Last != at(5, 10, 7).Unix() {
		t.Errorf("last use = %d, want %d", u.Last, at(5, 10, 7).Unix())
	}
}

func TestExtractCountsEachKeyOncePerCommand(t *testing.T) {
	r := &rollout{}
	r.meta(at(5, 10, 0), "/work", "cli")
	// The wrapper and the script both yield a key for "git"; the command counts once.
	r.cmdItem(at(5, 10, 1), "a", "completed", "/bin/zsh", "-lc", "git status && git status")
	f := extract(t, r)
	if got := count(f, match.PrefixKey([]string{"git", "status"})); got != 1 {
		t.Errorf("count = %d, want 1", got)
	}
}

func TestExtractMalformedInput(t *testing.T) {
	r := &rollout{lines: []string{
		`{"timestamp":"2026-03-05T10:00:00.000Z","ordinal":0,"type":"session_meta","payload":{"cwd":`,
		`{"timestamp":"not a time","type":"world_state","payload":{"state":{"permissions":{"approved_command_prefixes":[["a"]]}}}}`,
		`{"timestamp":"2026-03-05T10:00:01.000Z","type":"world_state","payload":{"state":{"permissions":{"approved_command_prefixes":"nope"}}}}`,
		`{"timestamp":"2026-03-05T10:00:02.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"x","arguments":"{broken"}}`,
		`{"timestamp":"2026-03-05T10:00:03.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"y","arguments":"{\"cmd\":5,\"sandbox_permissions\":\"require_escalated\"}"}}`,
		`{"timestamp":"2026-03-05T10:00:04.000Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","command":"not an array"}}}`,
		`Approved command prefixes "type":"message"`,
		`"CommandExecution"`,
		`{"timestamp":"2026-03-05T10:00:05.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":null,"output":{"a":1}}}`,
		"\x00\xff\xfe",
	}}
	f := extract(t, r) // must not panic or fail
	if !f.Start.Equal(at(5, 10, 0)) {
		t.Errorf("start = %v", f.Start)
	}
}

func TestExtractMissingFile(t *testing.T) {
	if _, err := ExtractRollout(filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestExtractVeryLongLine(t *testing.T) {
	r := &rollout{}
	r.meta(at(5, 10, 0), "/work", "cli")
	r.add(at(5, 10, 1), "event_msg", map[string]any{"type": "item_completed", "item": map[string]any{
		"type": "CommandExecution", "id": "big", "status": "completed", "command": []string{"git", "log"},
		"aggregated_output": strings.Repeat("x", 3<<20),
	}})
	f := extract(t, r)
	if count(f, match.PrefixKey([]string{"git", "log"})) != 1 {
		t.Error("a multi-megabyte line must still be read")
	}
}

func TestExtractJustificationIsShort(t *testing.T) {
	r := &rollout{}
	r.meta(at(5, 10, 0), "/work", "cli")
	r.call(at(5, 10, 1), "exec_command", "c1", map[string]any{
		"cmd": "ls", "sandbox_permissions": "require_escalated", "prefix_rule": []string{"ls"},
		"justification": strings.Repeat("word ", 200),
	})
	f := extract(t, r)
	if len(f.Escalations) != 1 || len([]rune(f.Escalations[0].Justification)) > 160 {
		t.Errorf("escalations = %+v", f.Escalations)
	}
}

func TestExtractEmptyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rollout-empty.jsonl")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := ExtractRollout(p)
	if err != nil || !f.Start.IsZero() || len(f.Usage) != 0 {
		t.Errorf("facts=%+v err=%v", f, err)
	}
}
