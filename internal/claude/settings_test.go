package claude

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAllow(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []string
		bad  bool
	}{
		{"plain", `{"permissions":{"allow":["Bash(ls:*)","Read"]}}`, []string{"Bash(ls:*)", "Read"}, false},
		{"no permissions", `{"model":"x"}`, nil, false},
		{"no allow", `{"permissions":{"deny":["Bash(rm:*)"]}}`, nil, false},
		{"non-strings skipped", `{"permissions":{"allow":["A",1,null,{"x":1},"B"]}}`, []string{"A", "B"}, false},
		{"allow not an array", `{"permissions":{"allow":"A"}}`, nil, false},
		{"permissions not an object", `{"permissions":[1]}`, nil, true},
		{"not json", `{"permissions":`, nil, true},
		{"empty", ``, nil, true},
		{"escapes and unicode", `{"permissions":{"allow":["Bash(echo \"hi\":*)","Read(/tmp/café)"]}}`, []string{`Bash(echo "hi":*)`, "Read(/tmp/café)"}, false},
	}
	for _, c := range cases {
		got, err := parseAllow([]byte(c.doc))
		if (err != nil) != c.bad {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseClaudeJSONReadsOnlyWhatItNeeds(t *testing.T) {
	doc := `{
	  "firstStartTime": "2026-01-02T03:04:05.678Z",
	  "oauthAccount": {"emailAddress": "someone@example.com", "token": "sk-not-for-us"},
	  "projects": {
	    "/work/app": {"hasTrustDialogAccepted": true, "allowedTools": ["Bash(ls:*)", "Bash(ls:*)", 7], "lastCost": 1.5, "mcpServers": {"s": {"env": {"KEY": "v"}}}},
	    "/work/other/": {"hasTrustDialogAccepted": false},
	    "/work/odd": {"hasTrustDialogAccepted": "yes", "allowedTools": "nope"},
	    "": {"hasTrustDialogAccepted": true}
	  }
	}`
	cj, err := parseClaudeJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if cj.FirstStart.Year() != 2026 || cj.FirstStart.Month() != 1 {
		t.Errorf("firstStartTime = %v", cj.FirstStart)
	}
	want := map[string]projectInfo{
		"/work/app":   {Trusted: true, AllowedTools: []string{"Bash(ls:*)"}},
		"/work/other": {},
		"/work/odd":   {},
	}
	if !reflect.DeepEqual(cj.Projects, want) {
		t.Errorf("projects = %+v", cj.Projects)
	}
	if _, err := parseClaudeJSON([]byte(`{"projects":[`)); err == nil {
		t.Error("want an error for broken JSON")
	}
}

func TestArrayLines(t *testing.T) {
	doc := "{\n  \"hooks\": {\"allow\": [\"decoy\"]},\n  \"permissions\": {\n    \"deny\": [\"x\"],\n    \"allow\": [\n      \"A\",\n      \"B \\\"q\\\"\",\n      3,\n      \"A\"\n    ]\n  }\n}\n"
	got := arrayLines([]byte(doc), []string{"permissions", "allow"})
	want := map[string]int{"A": 6, `B "q"`: 7}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines = %v, want %v", got, want)
	}
	if arrayLines([]byte(doc), []string{"permissions", "nope"}) != nil {
		t.Error("missing path must give nil")
	}
	if arrayLines([]byte(doc), []string{"permissions", "deny", "x"}) != nil {
		t.Error("walking into an array must give nil")
	}
}

func TestValueLineKeysWithSlashesAndQuotes(t *testing.T) {
	doc := "{\n \"projects\": {\n  \"/a/b c\": {\"x\": [1, {\"y\": \"}\"}]},\n  \"/a/\\\"q\\\"\": {\n   \"hasTrustDialogAccepted\": true\n  }\n }\n}"
	if got := valueLine([]byte(doc), []string{"projects", `/a/"q"`, "hasTrustDialogAccepted"}); got != 5 {
		t.Errorf("line = %d", got)
	}
	if got := valueLine([]byte(doc), []string{"projects", "/a/b c"}); got != 3 {
		t.Errorf("line = %d", got)
	}
	if got := valueLine([]byte(doc), []string{"projects", "/missing"}); got != 0 {
		t.Errorf("line = %d", got)
	}
}

func TestJSONNavigatorSurvivesGarbage(t *testing.T) {
	docs := []string{
		``, `{`, `}`, `]`, `{"a"`, `{"a":`, `{"a":}`, `[1,2`, `{"a":[}`, `"unterminated`, `{"a":"\`,
		`{"permissions":{"allow":[}}`, `{"permissions":{"allow":["A" "B"]}}`, `{"permissions":{"allow":[,]}}`,
		strings.Repeat("[", 5000), strings.Repeat(`{"a":`, 5000), "\x00\xff\xfe",
	}
	for _, d := range docs {
		valueOffset([]byte(d), []string{"permissions", "allow"})
		arrayLines([]byte(d), []string{"permissions", "allow"})
		valueLine([]byte(d), []string{"a"})
	}
}
