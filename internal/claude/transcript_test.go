package claude

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/yihanzhu/grants/internal/match"
)

const (
	tHome    = "/home/u"
	tProj    = "/work/app"
	tSession = "11111111-aaaa"
)

func extractLines(t *testing.T, ls ...string) TranscriptFacts {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "projects")
	p := filepath.Join(root, "-work-app", tSession+".jsonl")
	writeFile(t, p, lines(ls...))
	f, err := extractTranscript(p, root, filepath.Join(dir, "file-history"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestExtractUsageAndBasics(t *testing.T) {
	f := extractLines(t,
		toolUseLine("2026-09-01T10:00:00Z", tProj, tSession, "u1", "t1", "Bash", m{"command": "npm test && git status"}),
		toolUseLine("2026-09-01T10:00:05Z", tProj, tSession, "u2", "t2", "Read", m{"file_path": "/work/app/src/a.go"}),
		toolUseLine("2026-09-01T10:00:09Z", tProj, tSession, "u3", "t3", "WebFetch", m{"url": "https://example.com/docs?q=1"}),
		toolUseLine("2026-09-01T10:00:11Z", tProj, tSession, "u4", "t4", "mcp__srv__do_thing", m{"x": 1}),
		toolUseLine("2026-09-01T10:00:12Z", tProj, tSession, "u4b", "t1", "Bash", m{"command": "npm test"}), // same id again: counted once
		"not json at all",
		`{"type":"tool_use"`, // cut off
	)
	if f.Cwd != tProj || f.SessionID != tSession {
		t.Errorf("cwd/session = %q %q", f.Cwd, f.SessionID)
	}
	if !f.Start.Equal(ts("2026-09-01T10:00:00Z")) || !f.End.Equal(ts("2026-09-01T10:00:12Z")) {
		t.Errorf("span = %v .. %v", f.Start, f.End)
	}
	cases := []struct {
		name string
		key  match.Key
		want int32
	}{
		{"bash tool", match.ToolKey("Bash"), 1},
		{"npm test prefix", match.PrefixKey([]string{"npm", "test"}), 1},
		{"git status prefix", match.PrefixKey([]string{"git", "status"}), 1},
		{"read dir", match.DirKey("read", "/work/app/src"), 1},
		{"read file", match.FileKey("read", "/work/app/src/a.go"), 1},
		{"edit namespace untouched", match.DirKey("edit", "/work/app/src"), 0},
		{"host", match.HostKey("example.com"), 1},
		{"mcp server", match.MCPServerKey("srv"), 1},
	}
	for _, c := range cases {
		if got := usageOf(f)[c.key].Count; got != c.want {
			t.Errorf("%s: count = %d, want %d", c.name, got, c.want)
		}
	}
	if got := usageOf(f)[match.ToolKey("Bash")].Last; got != ts("2026-09-01T10:00:00Z").Unix() {
		t.Errorf("last = %d", got)
	}
}

func TestExtractSettingsEdits(t *testing.T) {
	settings := tHome + "/.claude/settings.json"
	orig := `{"permissions":{"allow":["Bash(a:*)"]}}`
	f := extractLines(t,
		// Edit: before and after are rebuilt from oldString/newString.
		resultLine("2026-09-02T10:00:00Z", tProj, tSession, "e1", m{
			"filePath": settings, "originalFile": orig, "oldString": `"Bash(a:*)"`, "newString": `"Bash(a:*)","Bash(b:*)"`, "replaceAll": false,
		}, nil),
		// Write that creates the file: nothing was allowed before.
		resultLine("2026-09-03T10:00:00Z", tProj, tSession, "e2", m{
			"type": "create", "filePath": tProj + "/.claude/settings.local.json", "content": `{"permissions":{"allow":["Read(/x/**)"]}}`, "originalFile": nil,
		}, nil),
		// A failed edit stores an error string.
		resultLine("2026-09-04T10:00:00Z", tProj, tSession, "e3", "Error: String to replace not found", nil),
		// A Read of a settings file has the path under "file", not at the top.
		resultLine("2026-09-05T10:00:00Z", tProj, tSession, "e4", m{"type": "text", "file": m{"filePath": settings, "content": orig}}, nil),
		// Some other file.
		resultLine("2026-09-06T10:00:00Z", tProj, tSession, "e5", m{"filePath": "/work/app/main.go", "originalFile": "x", "oldString": "x", "newString": "y"}, nil),
		// Old string that is not in the file: only the before state is known.
		resultLine("2026-09-07T10:00:00Z", tProj, tSession, "e6", m{
			"filePath": settings, "originalFile": orig, "oldString": "missing", "newString": "z",
		}, nil),
	)
	type got struct {
		t     string
		file  string
		allow string
	}
	var have []got
	for _, s := range f.Snapshots {
		have = append(have, got{s.T.UTC().Format("2006-01-02T15:04:05.000Z"), s.File, strings.Join(s.Allow, ",")})
	}
	want := []got{
		{"2026-09-02T09:59:59.999Z", settings, "Bash(a:*)"},
		{"2026-09-02T10:00:00.000Z", settings, "Bash(a:*),Bash(b:*)"},
		{"2026-09-03T09:59:59.999Z", tProj + "/.claude/settings.local.json", ""},
		{"2026-09-03T10:00:00.000Z", tProj + "/.claude/settings.local.json", "Read(/x/**)"},
		{"2026-09-07T09:59:59.999Z", settings, "Bash(a:*)"},
	}
	if len(have) != len(want) {
		t.Fatalf("snapshots = %+v", have)
	}
	for i := range want {
		if have[i] != want[i] {
			t.Errorf("snapshot %d = %+v, want %+v", i, have[i], want[i])
		}
	}
}

func TestExtractMultiEdit(t *testing.T) {
	settings := tHome + "/.claude/settings.json"
	f := extractLines(t, resultLine("2026-09-02T10:00:00Z", tProj, tSession, "e1", m{
		"filePath": settings, "originalFile": `{"permissions":{"allow":["A","B"]}}`,
		"edits": []any{
			m{"oldString": `"A"`, "newString": `"A2"`},
			m{"oldString": `"B"`, "newString": `"B2"`},
		},
	}, nil))
	if len(f.Snapshots) != 2 || strings.Join(f.Snapshots[1].Allow, ",") != "A2,B2" {
		t.Errorf("snapshots = %+v", f.Snapshots)
	}
}

func TestExtractFileHistory(t *testing.T) {
	settings := tHome + "/.claude/settings.json"
	other := tProj + "/notes.md"
	snapshot := js(m{
		"type": "file-history-snapshot", "messageId": "m1", "isSnapshotUpdate": false,
		"snapshot": m{"messageId": "m1", "timestamp": "2026-09-08T10:00:00Z", "trackedFileBackups": m{
			settings: m{"backupFileName": "abcd@v1", "version": 1, "backupTime": "2026-09-08T09:00:00.500Z"},
			other:    m{"backupFileName": "ef01@v1", "version": 1, "backupTime": "2026-09-08T09:00:01Z"},
		}},
	})
	delta := js(m{
		"type": "file-history-delta", "messageId": "m2", "trackingPath": tProj + "/.claude/settings.local.json",
		"backup": m{"backupFileName": nil, "version": 1, "backupTime": "2026-09-09T09:00:00Z"}, "timestamp": "2026-09-09T09:00:05Z",
	})
	f := extractLines(t, snapshot, delta)
	if len(f.FileHistory) != 2 {
		t.Fatalf("refs = %+v", f.FileHistory)
	}
	byFile := map[string]FileHistoryRef{}
	for _, r := range f.FileHistory {
		byFile[r.File] = r
	}
	r := byFile[settings]
	if !strings.HasSuffix(r.Backup, filepath.Join("file-history", tSession, "abcd@v1")) || !r.T.Equal(ts("2026-09-08T09:00:00.5Z")) {
		t.Errorf("settings ref = %+v", r)
	}
	if r := byFile[tProj+"/.claude/settings.local.json"]; r.Backup != "" {
		t.Errorf("a file that did not exist has no backup, got %+v", r)
	}
}

func TestExtractDecisions(t *testing.T) {
	token := "ghp_" + strings.Repeat("a1B2", 9)
	perm := func(source, decision string) m {
		return m{"permissionDecision": m{"decision": decision, "source": source}, "sourceToolAssistantUUID": "a1"}
	}
	f := extractLines(t,
		toolUseLine("2026-09-10T10:00:00Z", tProj, tSession, "a1", "t1", "Bash", m{"command": "npm run build"}),
		resultLine("2026-09-10T10:00:30Z", tProj, tSession, "r1", nil, perm("user_permanent", "accept")),
		toolUseLine("2026-09-10T11:00:00Z", tProj, tSession, "a2", "t2", "Bash", m{"command": "curl -H 'Authorization: Bearer " + token + "' https://example.com/x"}),
		resultLine("2026-09-10T11:00:30Z", tProj, tSession, "r2", nil, m{
			"permissionDecision": m{"decision": "accept", "source": "user_permanent"}, "sourceToolAssistantUUID": "a2",
			"message": m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t2", "content": "ok"}}},
		}),
		// Not decisions we keep: one-time approval, rejection, answer with no known tool call.
		resultLine("2026-09-10T12:00:00Z", tProj, tSession, "r3", nil, perm("user_temporary", "accept")),
		resultLine("2026-09-10T12:00:01Z", tProj, tSession, "r4", nil, perm("user_permanent", "reject")),
		resultLine("2026-09-10T12:00:02Z", tProj, tSession, "r5", nil, m{
			"permissionDecision": m{"decision": "accept", "source": "user_permanent"}, "sourceToolAssistantUUID": "nope",
		}),
	)
	if len(f.Decisions) != 2 {
		t.Fatalf("decisions = %+v", f.Decisions)
	}
	d := f.Decisions[0]
	if d.Tool != "Bash" || d.Summary != "npm run build" || !d.T.Equal(ts("2026-09-10T10:00:30Z")) {
		t.Errorf("decision 0 = %+v", d)
	}
	wantKey := match.PrefixKey([]string{"npm", "run"})
	found := false
	for _, k := range d.Keys {
		found = found || k == wantKey
	}
	if !found {
		t.Error("decision keys miss the npm run prefix")
	}
	if strings.Contains(f.Decisions[1].Summary, token) {
		t.Errorf("summary keeps a credential: %q", f.Decisions[1].Summary)
	}
	if len(f.Decisions[1].Summary) > 120 {
		t.Errorf("summary too long: %d", len(f.Decisions[1].Summary))
	}
}

func TestExtractLongLinesAndGarbage(t *testing.T) {
	big := strings.Repeat("x", 3<<20)
	f := extractLines(t,
		toolUseLine("2026-09-01T10:00:00Z", tProj, tSession, "u1", "t1", "Write", m{"file_path": "/work/app/big.txt", "content": big}),
		"{}", "[]", `"str"`, "null",
		`{"type":"assistant","message":{"content":"text only, "type":"tool_use"}}`,
		toolUseLine("2026-09-01T10:00:10Z", tProj, tSession, "u2", "t2", "Bash", m{"command": 5}), // wrong type
	)
	if usageOf(f)[match.DirKey("edit", "/work/app")].Count != 1 {
		t.Error("the long line was skipped")
	}
	if usageOf(f)[match.ToolKey("Bash")].Count != 1 {
		t.Error("a tool call with a bad input type is still a call")
	}
}

func TestExtractMissingFile(t *testing.T) {
	if _, err := extractTranscript("/nonexistent/x.jsonl", "/nonexistent", "/nonexistent"); err == nil {
		t.Error("want an error for a missing file")
	}
}

func TestSessionFolder(t *testing.T) {
	root := "/h/.claude/projects"
	cases := map[string]string{
		root + "/-a-b/s1.jsonl":                   "s1",
		root + "/-a-b/s1/subagents/agent-x.jsonl": "s1",
		root + "/-a-b/s1/workflows/w.jsonl":       "s1",
		"/elsewhere/s2.jsonl":                     "s2",
	}
	for p, want := range cases {
		if got := sessionFolder(p, root); got != want {
			t.Errorf("sessionFolder(%s) = %q, want %q", p, got, want)
		}
	}
}

func TestHasSettingsPath(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`{"filePath":"/h/.claude/settings.json","x":1}`, true},
		{`{"file_path":"/h/.claude/settings.local.json"}`, true},
		{`{"text":"see /h/.claude/settings.json for details"}`, false},
		{`{"file":{"filePath":"/h/.claude/settings.json"}}`, true}, // prefilter only; decode drops it
		{`{"filePath":"/h/.claude/settings.jsonl"}`, false},
		{`{"filePath":"/h/.claude/settings-extra.json"}`, false},
		{`.claude/settings`, false},
		{``, false},
	}
	for _, c := range cases {
		if got := hasSettingsPath([]byte(c.line)); got != c.want {
			t.Errorf("hasSettingsPath(%s) = %v", c.line, got)
		}
	}
}

func TestLineTimeAndQuoted(t *testing.T) {
	line := []byte(`{"message":{"content":"\"timestamp\":\"2020-01-01T00:00:00Z\""},"timestamp":"2026-09-01T10:00:00.250Z","cwd":"/a \"b\"/c","sessionId":"s"}`)
	if got := lineTime(line); !got.Equal(ts("2026-09-01T10:00:00.25Z")) {
		t.Errorf("lineTime = %v", got)
	}
	if got := quotedAfterLast(line, keyCwd); got != `/a "b"/c` {
		t.Errorf("cwd = %q", got)
	}
	if !lineTime([]byte(`{"x":1}`)).IsZero() || quotedAfterLast([]byte(`{"cwd":"unterminated`), keyCwd) != "" {
		t.Error("missing values must come back empty")
	}
}

// usageOf counts every call of one transcript, copies included.
func usageOf(f TranscriptFacts) map[match.Key]Use {
	u := map[match.Key]Use{}
	countCalls(u, f.Calls, nil)
	return u
}
