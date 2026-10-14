package match

import (
	"reflect"
	"slices"
	"testing"
)

func TestCommands(t *testing.T) {
	cases := []struct {
		in   string
		want [][]string
	}{
		{`git status`, [][]string{{"git", "status"}}},
		{`cd repo && git push origin main`, [][]string{{"cd", "repo"}, {"git", "push", "origin", "main"}}},
		{`ls -la | grep foo; echo "a b"`, [][]string{{"ls", "-la"}, {"grep", "foo"}, {"echo", "a b"}}},
		{`FOO=1 BAR=2 npm test 2>&1 > out.txt`, [][]string{{"npm", "test"}}},
		{`timeout 30 nice -n 5 nohup make build`, [][]string{{"make", "build"}}},
		{`env -i PATH=/bin go test ./...`, [][]string{{"go", "test", "./..."}}},
		{`/bin/zsh -lc 'git add . && git commit -m "x y"'`, [][]string{
			{"/bin/zsh", "-lc", `git add . && git commit -m "x y"`},
			{"git", "add", "."},
			{"git", "commit", "-m", "x y"},
		}},
		{"cat <<EOF > f.txt\nrm -rf /\nEOF\necho done", [][]string{{"cat"}, {"echo", "done"}}},
		{"# a comment\ngit log # trailing", [][]string{{"git", "log"}}},
		{`echo it\'s`, [][]string{{"echo", "it's"}}},
		{`sort < in.txt > out.txt`, [][]string{{"sort"}}},
	}
	for _, c := range cases {
		if got := Commands(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Commands(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func has(keys []Key, k Key) bool { return slices.Contains(keys, k) }

func matches(rule, used []Key) bool {
	for _, k := range rule {
		if has(used, k) {
			return true
		}
	}
	return false
}

func TestClaudeBashRules(t *testing.T) {
	base := RuleBase{Home: "/home/u", Settings: "/home/u/.claude", Project: "/w/p"}
	cases := []struct {
		rule, cmd string
		want      bool
	}{
		{"Bash(git push:*)", "git push origin main", true},
		{"Bash(git push *)", "cd x && git push", true},
		{"Bash(git push:*)", "git pull", false},
		{"Bash(npm run build)", "npm run build", true},
		{"Bash(npm run build)", "npm run build --prod", false},
		{"Bash", "anything at all", true},
		{"Bash(*)", "anything", true},
		{"Bash(/opt/s/run.sh:*)", "/opt/s/run.sh --x", true},
	}
	for _, c := range cases {
		keys, ok := ClaudeRuleKeys(ParseClaudeRule(c.rule), base)
		if !ok {
			t.Fatalf("%s: not measurable", c.rule)
		}
		used := ClaudeToolKeys(ClaudeToolUse{Name: "Bash", Command: c.cmd})
		if got := matches(keys, used); got != c.want {
			t.Errorf("%s vs %q: got %v want %v", c.rule, c.cmd, got, c.want)
		}
	}
	if _, ok := ClaudeRuleKeys(ParseClaudeRule("Bash(git * main)"), base); ok {
		t.Error("middle wildcard should not be measurable")
	}
}

func TestClaudePathRules(t *testing.T) {
	base := RuleBase{Home: "/home/u", Settings: "/home/u/.claude", Project: "/w/p"}
	cases := []struct {
		rule string
		use  ClaudeToolUse
		want bool
	}{
		{"Read(~/notes/**)", ClaudeToolUse{Name: "Read", FilePath: "/home/u/notes/a/b.md"}, true},
		{"Read(~/notes/**)", ClaudeToolUse{Name: "Edit", FilePath: "/home/u/notes/b.md"}, false},
		{"Edit(~/notes/inbox/**)", ClaudeToolUse{Name: "Write", FilePath: "/home/u/notes/inbox/x.md"}, true},
		{"Edit(//etc/hosts)", ClaudeToolUse{Name: "Edit", FilePath: "/etc/hosts"}, true},
		{"Read(src/**)", ClaudeToolUse{Name: "Grep", FilePath: "/w/p/src/x.go"}, true},
		{"WebFetch(domain:example.com)", ClaudeToolUse{Name: "WebFetch", URL: "https://EXAMPLE.com/a"}, true},
		{"mcp__gh", ClaudeToolUse{Name: "mcp__gh__create_issue"}, true},
		{"mcp__gh__*", ClaudeToolUse{Name: "mcp__gh__create_issue"}, true},
		{"mcp__gh__list", ClaudeToolUse{Name: "mcp__gh__create_issue"}, false},
	}
	for _, c := range cases {
		keys, ok := ClaudeRuleKeys(ParseClaudeRule(c.rule), base)
		if !ok {
			t.Fatalf("%s: not measurable", c.rule)
		}
		if got := matches(keys, ClaudeToolKeys(c.use)); got != c.want {
			t.Errorf("%s vs %+v: got %v want %v", c.rule, c.use, got, c.want)
		}
	}
}

func TestCodexPatterns(t *testing.T) {
	cases := []struct {
		pattern [][]string
		argv    []string
		want    bool
	}{
		{[][]string{{"git"}, {"push"}}, []string{"git", "push", "origin"}, true},
		{[][]string{{"git"}, {"push"}}, []string{"/bin/zsh", "-lc", "git push"}, true},
		{[][]string{{"git"}, {"push"}}, []string{"/usr/bin/git", "push"}, true},
		{[][]string{{"/bin/zsh"}, {"-lc"}, {"make x"}}, []string{"/bin/zsh", "-lc", "make x"}, true},
		{[][]string{{"npm", "pnpm"}, {"test"}}, []string{"pnpm", "test"}, true},
		{[][]string{{"git"}, {"push"}}, []string{"git", "pull"}, false},
	}
	for _, c := range cases {
		if got := matches(CodexPatternKeys(c.pattern), ArgvKeys(c.argv)); got != c.want {
			t.Errorf("%q vs %q: got %v want %v", c.pattern, c.argv, got, c.want)
		}
	}
}
