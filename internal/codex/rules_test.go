package codex

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRulesShapes(t *testing.T) {
	src := "# header comment\n" +
		"prefix_rule(pattern=[\"git\", \"status\"], decision=\"allow\")\n" +
		"\n" +
		"prefix_rule(\n" +
		"    pattern = [\"npm\", [\"test\", \"run\"]],  # which\n" +
		"    decision = \"prompt\",\n" +
		"    justification = \"ask first\",\n" +
		"    match = [[\"npm\", \"test\"]],\n" +
		")\n" +
		"prefix_rule(pattern=['ls'])  # trailing comment\n" +
		"network_rule(host=\"example.com\", protocol=\"https\", decision=\"allow\")\n"
	rules := ParseRules([]byte(src))
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4: %+v", len(rules), rules)
	}
	r := rules[0]
	if r.Name != "prefix_rule" || r.Decision != "allow" || r.Line != 2 || !reflect.DeepEqual(r.Pattern, [][]string{{"git"}, {"status"}}) {
		t.Errorf("rule 0 = %+v", r)
	}
	if r.Raw != "prefix_rule(pattern=[\"git\", \"status\"], decision=\"allow\")\n" {
		t.Errorf("raw = %q", r.Raw)
	}
	r = rules[1]
	if r.Decision != "prompt" || r.Justification != "ask first" || r.Line != 4 {
		t.Errorf("rule 1 = %+v", r)
	}
	if !reflect.DeepEqual(r.Pattern, [][]string{{"npm"}, {"test", "run"}}) {
		t.Errorf("pattern = %v", r.Pattern)
	}
	if !strings.HasSuffix(r.Raw, ")\n") || !strings.HasPrefix(r.Raw, "prefix_rule(\n") {
		t.Errorf("raw = %q", r.Raw)
	}
	r = rules[2]
	if r.Decision != "allow" || !strings.HasSuffix(r.Raw, "# trailing comment\n") {
		t.Errorf("rule 2 = %+v", r)
	}
	if rules[3].Name != "network_rule" || rules[3].Decision != "allow" || rules[3].Err != "" {
		t.Errorf("rule 3 = %+v", rules[3])
	}
	for i := 1; i < len(rules); i++ {
		if rules[i].Start < rules[i-1].End {
			t.Errorf("rules %d and %d overlap", i-1, i)
		}
	}
}

func TestParseRulesStrings(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"escapes", `prefix_rule(pattern=["a\"b", "c\\d", "e\nf", "\x41\u00e9"])`, []string{`a"b`, `c\d`, "e\nf", "Aé"}},
		{"single", `prefix_rule(pattern=['it\'s', "x"])`, []string{"it's", "x"}},
		{"triple", "prefix_rule(pattern=[\"\"\"a\nb\"\"\", '''c'd'''])", []string{"a\nb", "c'd"}},
		{"raw", `prefix_rule(pattern=[r"a\d", "b"])`, []string{`a\d`, "b"}},
		{"continuation", "prefix_rule(pattern=[\"ab\\\ncd\"])", []string{"abcd"}},
		{"unicode", `prefix_rule(pattern=["日本語", "🙂"])`, []string{"日本語", "🙂"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := ParseRules([]byte(tt.src))
			if len(rules) != 1 || rules[0].Err != "" {
				t.Fatalf("rules = %+v", rules)
			}
			var got []string
			for _, alts := range rules[0].Pattern {
				got = append(got, alts[0])
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("tokens = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseRulesErrors(t *testing.T) {
	good := "prefix_rule(pattern=[\"ls\"])\n"
	tests := []struct {
		name string
		src  string
	}{
		{"unterminated string", "prefix_rule(pattern=[\"ls])\n"},
		{"unterminated call", "prefix_rule(pattern=[\"ls\"]\n"},
		{"missing pattern", "prefix_rule(decision=\"allow\")\n"},
		{"pattern not list", "prefix_rule(pattern=\"ls\")\n"},
		{"pattern number", "prefix_rule(pattern=[1, 2])\n"},
		{"concatenation", "prefix_rule(pattern=[\"a\" + \"b\"])\n"},
		{"positional", "prefix_rule([\"ls\"])\n"},
		{"assignment", "x = prefix_rule(pattern=[\"ls\"])\n"},
		{"function def", "def f():\n    pass\n"},
		{"bad escape", "prefix_rule(pattern=[\"a\\qb\"])\n"},
		{"empty alternatives", "prefix_rule(pattern=[[]])\n"},
		{"decision not string", "prefix_rule(pattern=[\"a\"], decision=1)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := ParseRules([]byte(tt.src + good))
			if len(rules) == 0 {
				t.Fatal("no statements")
			}
			bad := 0
			for _, r := range rules {
				if r.Err != "" {
					bad++
				}
			}
			if bad == 0 {
				t.Fatalf("no error reported: %+v", rules)
			}
			last := rules[len(rules)-1]
			if last.Err != "" || last.Raw != good {
				t.Errorf("the good rule after the bad one was lost: %+v", last)
			}
		})
	}
}

func TestParseRulesBadInputNeverPanics(t *testing.T) {
	inputs := []string{"", "(", ")", "\"", "'''", "prefix_rule(", "prefix_rule(pattern=[", "\x00\xff\xfe", "#", "prefix_rule(pattern=[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
		strings.Repeat("prefix_rule(", 1000)}
	for _, in := range inputs {
		rules := ParseRules([]byte(in))
		for _, r := range rules {
			if r.Start < 0 || r.End > len(in) || r.Start > r.End {
				t.Errorf("bad span in %q: %+v", in, r)
			}
		}
	}
}

func TestParseRulesCRLFAndSameLine(t *testing.T) {
	src := "prefix_rule(pattern=[\"a\"])\r\nprefix_rule(pattern=[\"b\"]); prefix_rule(pattern=[\"c\"])\r\n"
	rules := ParseRules([]byte(src))
	if len(rules) != 3 {
		t.Fatalf("got %d: %+v", len(rules), rules)
	}
	if rules[0].Raw != "prefix_rule(pattern=[\"a\"])\r\n" {
		t.Errorf("raw0 = %q", rules[0].Raw)
	}
	if rules[1].Raw != "prefix_rule(pattern=[\"b\"]); " {
		t.Errorf("raw1 = %q", rules[1].Raw)
	}
	if rules[2].Raw != "prefix_rule(pattern=[\"c\"])\r\n" {
		t.Errorf("raw2 = %q", rules[2].Raw)
	}
}

func TestRemoveRule(t *testing.T) {
	pat := [][]string{{"git"}, {"status"}}
	tests := []struct {
		name     string
		src      string
		decision string
		want     string
		n        int
	}{
		{
			name:     "single line",
			src:      "prefix_rule(pattern=[\"ls\"], decision=\"allow\")\nprefix_rule(pattern=[\"git\", \"status\"], decision=\"allow\")\nprefix_rule(pattern=[\"cat\"], decision=\"allow\")\n",
			decision: "allow",
			want:     "prefix_rule(pattern=[\"ls\"], decision=\"allow\")\nprefix_rule(pattern=[\"cat\"], decision=\"allow\")\n",
			n:        1,
		},
		{
			name:     "multi line with comments",
			src:      "# keep me\nprefix_rule(\n  pattern = [\"git\", \"status\"],  # why\n  decision = \"allow\",\n)  # tail\n# keep me too\nprefix_rule(pattern=[\"ls\"])\n",
			decision: "allow",
			want:     "# keep me\n# keep me too\nprefix_rule(pattern=[\"ls\"])\n",
			n:        1,
		},
		{
			name:     "duplicates removed",
			src:      "prefix_rule(pattern=[\"git\", \"status\"])\nprefix_rule(pattern=[\"x\"])\nprefix_rule(pattern=[\"git\", \"status\"], decision=\"allow\")\n",
			decision: "allow",
			want:     "prefix_rule(pattern=[\"x\"])\n",
			n:        2,
		},
		{
			name:     "other decision stays",
			src:      "prefix_rule(pattern=[\"git\", \"status\"], decision=\"prompt\")\nprefix_rule(pattern=[\"git\", \"status\"])\n",
			decision: "allow",
			want:     "prefix_rule(pattern=[\"git\", \"status\"], decision=\"prompt\")\n",
			n:        1,
		},
		{
			name:     "no newline at end",
			src:      "prefix_rule(pattern=[\"ls\"])\nprefix_rule(pattern=[\"git\", \"status\"])",
			decision: "allow",
			want:     "prefix_rule(pattern=[\"ls\"])\n",
			n:        1,
		},
		{
			name:     "no match",
			src:      "prefix_rule(pattern=[\"ls\"])\n",
			decision: "allow",
			want:     "prefix_rule(pattern=[\"ls\"])\n",
			n:        0,
		},
		{
			name:     "malformed neighbour kept",
			src:      "prefix_rule(pattern=[\"oops)\nprefix_rule(pattern=[\"git\", \"status\"])\nprefix_rule(pattern=[\"ls\"])\n",
			decision: "allow",
			want:     "prefix_rule(pattern=[\"oops)\nprefix_rule(pattern=[\"ls\"])\n",
			n:        1,
		},
		{
			name:     "malformed statement after",
			src:      "prefix_rule(pattern=[\"git\", \"status\"])\nprefix_rule(pattern=[\"oops)\n",
			decision: "allow",
			want:     "prefix_rule(pattern=[\"oops)\n",
			n:        1,
		},
		{
			name:     "same line neighbours",
			src:      "prefix_rule(pattern=[\"ls\"]); prefix_rule(pattern=[\"git\", \"status\"]); prefix_rule(pattern=[\"cat\"])\n",
			decision: "allow",
			want:     "prefix_rule(pattern=[\"ls\"]); prefix_rule(pattern=[\"cat\"])\n",
			n:        1,
		},
		{
			name:     "escaped tokens",
			src:      "prefix_rule(pattern=[\"git\", \"\\x73tatus\"])\n",
			decision: "allow",
			want:     "",
			n:        1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, n, err := RemoveRule([]byte(tt.src), pat, tt.decision)
			if err != nil {
				t.Fatal(err)
			}
			if n != tt.n || string(got) != tt.want {
				t.Errorf("got (%d) %q\nwant (%d) %q", n, got, tt.n, tt.want)
			}
		})
	}
}

func TestRemoveRuleAlternatives(t *testing.T) {
	src := "prefix_rule(pattern=[\"npm\", [\"run\", \"test\"]])\nprefix_rule(pattern=[\"npm\", \"run\"])\n"
	got, n, err := RemoveRule([]byte(src), [][]string{{"npm"}, {"run", "test"}}, "allow")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if string(got) != "prefix_rule(pattern=[\"npm\", \"run\"])\n" {
		t.Errorf("got %q", got)
	}
}

func TestPatternJSONAndDisplay(t *testing.T) {
	tests := []struct {
		p       [][]string
		json    string
		display string
	}{
		{[][]string{{"git"}, {"status"}}, `["git","status"]`, "git status"},
		{[][]string{{"npm"}, {"run", "test"}}, `["npm",["run","test"]]`, "npm run|test"},
		{[][]string{{"/bin/zsh"}, {"-lc"}, {"echo 'hi' && ls"}}, `["/bin/zsh","-lc","echo 'hi' && ls"]`, `/bin/zsh -lc "echo 'hi' && ls"`},
		{[][]string{{"a\"b"}}, `["a\"b"]`, `a"b`},
		{[][]string{{"say \"hi\" now"}}, `["say \"hi\" now"]`, `'say "hi" now'`},
		{[][]string{{"it's \"x\" y"}}, `["it's \"x\" y"]`, `'it'\''s "x" y'`},
		{[][]string{{"curl"}, {"-H"}, {"X: 1"}}, `["curl","-H","X: 1"]`, `curl -H "X: 1"`},
		{[][]string{{"it's"}}, `["it's"]`, "it's"},
		{[][]string{{""}}, `[""]`, `""`},
		{nil, `[]`, ""},
	}
	for _, tt := range tests {
		if got := PatternJSON(tt.p); got != tt.json {
			t.Errorf("PatternJSON(%v) = %s, want %s", tt.p, got, tt.json)
		}
		if got := PatternDisplay(tt.p); got != tt.display {
			t.Errorf("PatternDisplay(%v) = %s, want %s", tt.p, got, tt.display)
		}
	}
}

func TestExpand(t *testing.T) {
	got := expand([][]string{{"a", "b"}, {"c"}, {"d", "e"}})
	want := [][]string{{"a", "c", "d"}, {"a", "c", "e"}, {"b", "c", "d"}, {"b", "c", "e"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expand = %v", got)
	}
	big := [][]string{}
	for range 10 {
		big = append(big, []string{"1", "2", "3"})
	}
	if expand(big) != nil {
		t.Error("expected nil for a pattern with too many expansions")
	}
}
