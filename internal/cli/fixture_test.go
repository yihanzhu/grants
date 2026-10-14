package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/claude"
	"github.com/yihanzhu/grants/internal/codex"
	"github.com/yihanzhu/grants/internal/fsx"
)

// The synthetic home. Every path and string in it is made up. Its clock is 2026-10-13.
const testNow = "2026-10-13T12:00:00Z"

type home struct {
	root, home, state string
	app, gone, gone2  string // work folders; "gone" and "gone2" are never created
	claudeUser        string // ~/.claude/settings.json
	claudeProj        string // <app>/.claude/settings.json
	claudeJSON        string
	codexCfg          string
	codexRules        string
}

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, path, when string) {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, when)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, tm, tm); err != nil {
		t.Fatal(err)
	}
}

// born sets a file's birth and modification times. macOS lowers the birth time when
// the modification time is set earlier, so the birth date goes first. Other systems
// have no birth time and keep only the modification time.
func born(t *testing.T, path, birth, mtime string) {
	t.Helper()
	touch(t, path, birth)
	touch(t, path, mtime)
}

// hasBirth tells whether this system reports file birth times, which add a lower bound
// to the dates of grants in a file.
func hasBirth(path string) bool {
	_, ok := fsx.Birthtime(path)
	return ok
}

// window is the text grants shows for a grant dated by file times: a range when the
// file's birth time is known, else "before <date>".
func window(path, after, before string) string {
	if hasBirth(path) {
		return after + ".." + before
	}
	return "before " + before
}

func jline(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

type obj = map[string]any

// newHome builds a home with Claude Code and Codex data and points the process at it.
func newHome(t *testing.T) *home {
	t.Helper()
	local = time.UTC
	t.Cleanup(func() { local = time.Local })

	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	h := &home{root: root, home: filepath.Join(root, "home"), state: filepath.Join(root, "state")}
	h.app = filepath.Join(h.home, "work", "app")
	h.gone = filepath.Join(h.home, "work", "gone")
	h.gone2 = filepath.Join(h.home, "work", "gone2")
	if err := os.MkdirAll(h.app, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", h.home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GRANTS_STATE_DIR", h.state)
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("GRANTS_NOW", testNow)
	t.Setenv("NO_COLOR", "")
	t.Setenv("COLUMNS", "")
	t.Cleanup(claude.OverrideManaged())
	t.Cleanup(codex.OverrideManaged(filepath.Join(root, "no-managed-rules")))

	// Claude Code.
	h.claudeUser = filepath.Join(h.home, ".claude", "settings.json")
	put(t, h.claudeUser, "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(npm test:*)\",\n      \"Bash(git push:*)\",\n      \"Read(~/notes/**)\"\n    ]\n  }\n}\n")
	born(t, h.claudeUser, "2026-06-01T09:00:00Z", "2026-06-10T09:00:00Z")
	h.claudeProj = filepath.Join(h.app, ".claude", "settings.json")
	put(t, h.claudeProj, "{\"permissions\":{\"allow\":[\"Bash(make:*)\",\"Bash(curl -H 'Authorization: Bearer abcdefghij0123456789' https://example.com/x)\"]}}\n")
	born(t, h.claudeProj, "2026-08-20T09:00:00Z", "2026-09-01T09:00:00Z")
	h.claudeJSON = filepath.Join(h.home, ".claude.json")
	put(t, h.claudeJSON, "{\n  \"firstStartTime\": \"2026-05-01T00:00:00Z\",\n  \"projects\": {\n    "+
		jstr(h.app)+": {\n      \"hasTrustDialogAccepted\": true\n    },\n    "+
		jstr(h.gone)+": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n")
	touch(t, h.claudeJSON, "2026-10-12T09:00:00Z")

	sid := "11111111-aaaa"
	tool := func(when, id, name string, in obj) string {
		return jline(obj{"type": "assistant", "uuid": id, "timestamp": when, "cwd": h.app, "sessionId": sid,
			"message": obj{"role": "assistant", "content": []any{obj{"type": "tool_use", "id": id, "name": name, "input": in}}}})
	}
	put(t, filepath.Join(h.home, ".claude", "projects", "-work-app", sid+".jsonl"), strings.Join([]string{
		tool("2026-06-01T10:00:00Z", "t1", "Bash", obj{"command": "npm test"}),
		tool("2026-10-02T10:00:00Z", "t2", "Bash", obj{"command": "npm test"}),
		tool("2026-10-03T10:00:00Z", "t3", "Bash", obj{"command": "make build"}),
	}, "\n")+"\n")

	// Codex.
	cx := filepath.Join(h.home, ".codex")
	h.codexCfg = filepath.Join(cx, "config.toml")
	put(t, h.codexCfg, fmt.Sprintf("model = \"m\"\n\n[projects.%q]\ntrust_level = \"trusted\"\n\n[projects.%q]\ntrust_level = \"trusted\"\n\n[projects.\"/work/other\"]\ntrust_level = \"untrusted\"\n", h.app, h.gone2))
	born(t, h.codexCfg, "2026-08-01T09:00:00Z", "2026-09-20T09:00:00Z")
	h.codexRules = filepath.Join(cx, "rules", "default.rules")
	put(t, h.codexRules, "# rules\n"+
		"prefix_rule(pattern=[\"git\", \"push\"], decision=\"allow\")\n"+
		"prefix_rule(pattern=[\"npm\", \"test\"], decision=\"allow\")\n"+
		"prefix_rule(pattern=[\"curl\", \"-L\", \"https://example.com/a/b?x=1\"], decision=\"allow\")\n"+
		"prefix_rule(pattern=[\"/work/missing/tool.sh\"], decision=\"allow\")\n")
	born(t, h.codexRules, "2026-05-01T09:00:00Z", "2026-07-01T09:00:00Z")

	// Codex writes the timestamp first, then the type, then the payload.
	rec := func(when, typ string, payload obj) string {
		return fmt.Sprintf(`{"timestamp":%s,"type":%s,"payload":%s}`, jstr(when), jstr(typ), jline(payload))
	}
	prefixes := []any{[]string{"git", "push"}, []string{"npm", "test"}}
	args, _ := json.Marshal(obj{"cmd": "curl -L https://example.com/a/b?x=1", "sandbox_permissions": "require_escalated",
		"prefix_rule": []string{"curl", "-L", "https://example.com/a/b?x=1"}, "justification": "download the report"})
	put(t, filepath.Join(cx, "sessions", "2026", "06", "01", "rollout-a.jsonl"), strings.Join([]string{
		rec("2026-06-01T10:00:00.000Z", "session_meta", obj{"id": "s", "cwd": h.app, "source": "cli"}),
		rec("2026-06-01T10:00:01.000Z", "world_state", obj{"full": true, "state": obj{"permissions": obj{"approved_command_prefixes": prefixes}}}),
		rec("2026-06-01T10:05:00.000Z", "response_item", obj{"type": "function_call", "name": "exec_command", "call_id": "c1", "arguments": string(args)}),
		rec("2026-06-01T10:05:01.000Z", "response_item", obj{"type": "function_call_output", "call_id": "c1", "output": "Chunk ID: 1"}),
		rec("2026-10-05T10:00:00.000Z", "event_msg", obj{"type": "item_completed", "thread_id": "s", "item": obj{"type": "CommandExecution", "id": "u1", "status": "completed", "command": []string{"npm", "test"}, "cwd": h.app}}),
	}, "\n")+"\n")
	return h
}

func jstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// run calls cli.Main with the given stdin and returns the exit code and both outputs.
func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func overrideManaged(dir string) func() { return claude.OverrideManaged(dir) }
