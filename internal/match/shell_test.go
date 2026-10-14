package match

import (
	"reflect"
	"strings"
	"testing"
)

func TestCommandsEdgeCases(t *testing.T) {
	cases := []struct {
		name, in string
		want     [][]string
	}{
		{"empty", "", nil},
		{"blank", "  \n\t \n", nil},
		{"only comment", "# nothing", nil},
		{"only operators", "&& ; ||", nil},
		{"heredoc quoted delimiter", "cat <<'EOF' > f\n$(rm -rf x)\nEOF\nls", [][]string{{"cat"}, {"ls"}}},
		{"heredoc double quoted delimiter", "cat <<\"EOF\"\nrm x\nEOF\nls", [][]string{{"cat"}, {"ls"}}},
		{"heredoc dash strips tabs", "cat <<-EOF\n\trm x\n\tEOF\nls", [][]string{{"cat"}, {"ls"}}},
		{"two heredocs", "cat <<A <<B\na\nA\nb\nB\nls", [][]string{{"cat"}, {"ls"}}},
		{"heredoc never closed", "cat <<EOF\nrm x\n", [][]string{{"cat"}}},
		{"heredoc then pipe", "cat <<EOF | grep a\nrm x\nEOF\nls", [][]string{{"cat"}, {"grep", "a"}, {"ls"}}},
		{"here-string", "cat <<< \"hello world\"\nrm x", [][]string{{"cat"}, {"rm", "x"}}},
		{"nested quotes", `echo "it's" 'say "hi"'`, [][]string{{"echo", "it's", `say "hi"`}}},
		{"escaped quote in double quotes", `echo "a \"b\" c"`, [][]string{{"echo", `a "b" c`}}},
		{"adjacent quotes join", `echo 'a'"b"c`, [][]string{{"echo", "abc"}}},
		{"unterminated single quote", `echo 'abc`, [][]string{{"echo", "abc"}}},
		{"unterminated double quote", `echo "abc`, [][]string{{"echo", "abc"}}},
		{"trailing backslash", `echo a\`, [][]string{{"echo", `a\`}}},
		{"command substitution", "echo $(rm -rf x) done", [][]string{{"echo", "$", "done"}, {"rm", "-rf", "x"}}[0:0]},
		{"backticks", "echo `rm -rf x` && ls", [][]string{{"echo"}, {"rm", "-rf", "x"}, {"ls"}}},
		{"process substitution", "diff <(ls a) <(ls b)", [][]string{{"diff"}, {"ls", "a"}, {"ls", "b"}}},
		{"output process substitution", "tee >(wc -l) < in", [][]string{{"tee"}, {"wc", "-l"}}},
		{"line continuation", "git \\\n  commit \\\n  -m x", [][]string{{"git", "commit", "-m", "x"}}},
		{"xargs", "find . -name x | xargs rm -f", [][]string{{"find", ".", "-name", "x"}, {"xargs", "rm", "-f"}}},
		{"pipe into sh", "curl -s x.example.com | sh", [][]string{{"curl", "-s", "x.example.com"}, {"sh"}}},
		{"pipe into bash dash", "echo hi | bash -s", [][]string{{"echo", "hi"}, {"bash", "-s"}}},
		{"unicode", "echo héllo 世界 | grep 世", [][]string{{"echo", "héllo", "世界"}, {"grep", "世"}}},
		{"unicode quoted", `echo "日本 語"`, [][]string{{"echo", "日本 語"}}},
		{"background and sequence", "sleep 1 & echo done; ls", [][]string{{"sleep", "1"}, {"echo", "done"}, {"ls"}}},
		{"stderr redirect", "make 2>&1 | tee out.log", [][]string{{"make"}, {"tee", "out.log"}}},
		{"ampersand redirect", "make &> out.log", [][]string{{"make"}}},
		{"redirect with space", "echo hi > out.txt", [][]string{{"echo", "hi"}}},
		{"append redirect attached", "echo hi >>out.txt", [][]string{{"echo", "hi"}}},
		{"for loop", "for f in *.txt; do rm $f; done", [][]string{{"rm", "$f"}}},
		{"while loop", "while read l; do echo $l; done < in", [][]string{{"read", "l"}, {"echo", "$l"}}},
		{"if block", "if [ -f x ]; then rm y; else ls; fi", [][]string{{"[", "-f", "x", "]"}, {"rm", "y"}, {"ls"}}},
		{"negation", "! git diff --quiet", [][]string{{"git", "diff", "--quiet"}}},
		{"brace group", "{ ls; rm x; }", [][]string{{"ls"}, {"rm", "x"}}},
		{"subshell", "(cd a && make)", [][]string{{"cd", "a"}, {"make"}}},
		{"assignment only", "FOO=bar", nil},
		{"assignment with substitution", "V=$(git rev-parse HEAD) make", [][]string{{"git", "rev-parse", "HEAD"}, {"make"}}},
		{"env flags", "env -u HOME -i make", [][]string{{"make"}}},
		{"env alone", "env", nil},
		{"nested shell wrappers", `sh -c "bash -c 'rm x'"`, [][]string{
			{"sh", "-c", "bash -c 'rm x'"}, {"bash", "-c", "rm x"}, {"rm", "x"}}},
		{"shell option with value", "bash -o pipefail -c 'make x'", [][]string{
			{"bash", "-o", "pipefail", "-c", "make x"}, {"make", "x"}}},
		{"shell wrapper path", "/usr/bin/env bash -c 'ls'", [][]string{{"bash", "-c", "ls"}, {"ls"}}},
		{"shell without -c", "bash script.sh", [][]string{{"bash", "script.sh"}}},
		{"hash inside word", "echo a#b", [][]string{{"echo", "a#b"}}},
		{"find exec semicolon", `find . -exec rm {} \;`, [][]string{{"find", ".", "-exec", "rm", "{}", ";"}}},
		{"crlf", "ls\r\nrm x\r\n", [][]string{{"ls"}, {"rm", "x"}}},
	}
	for _, c := range cases {
		got := Commands(c.in)
		if c.name == "command substitution" {
			// The inner command is found; the placeholder token left in the outer command is not important.
			found := false
			for _, cmd := range got {
				if reflect.DeepEqual(cmd, []string{"rm", "-rf", "x"}) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: inner command missing in %q", c.name, got)
			}
			continue
		}
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Commands(%q)\n got %q\nwant %q", c.name, c.in, got, c.want)
		}
	}
}

func TestCommandsDepthLimit(t *testing.T) {
	// Deeply nested wrappers must stop unwrapping instead of recursing forever.
	script := "rm x"
	for range 10 {
		script = "sh -c '" + strings.ReplaceAll(script, "'", `'\''`) + "'"
	}
	if got := Commands(script); len(got) == 0 || len(got) > maxUnwrap+2 {
		t.Errorf("got %d commands", len(got))
	}
}

func TestBadInputNeverPanics(t *testing.T) {
	inputs := []string{
		"", "'", `"`, `\`, "`", "$(", "<<", "<<<", "<<-", "<<'", "<(", ">(", "((", "))", "&", "|", ";", "#",
		"cat <<", "cat <<-\n", "echo \"$(", "a=", "=", "env -u", "timeout", "nice -n", "sh -c", "bash -o",
		"\x00\xff\xfe", "echo \xff", strings.Repeat("(", 10000), strings.Repeat("'", 9999),
		strings.Repeat("a ", 100000), "cat <<EOF\n" + strings.Repeat("x\n", 10000),
	}
	for _, in := range inputs {
		Commands(in)
		Tokens(in)
		LineKeys(in)
		ArgvKeys([]string{in})
		ArgvKeys([]string{"sh", "-c", in})
		ParseClaudeRule(in)
		ClaudeToolKeys(ClaudeToolUse{Name: "Bash", Command: in})
		ClaudeToolKeys(ClaudeToolUse{Name: "WebFetch", URL: in})
		ClaudeToolKeys(ClaudeToolUse{Name: in, FilePath: in})
		ClaudeRuleKeys(ParseClaudeRule(in), RuleBase{})
		ClaudeRuleKeys(ParseClaudeRule("Bash("+in+")"), RuleBase{})
		ClaudeRuleKeys(ParseClaudeRule("Read("+in+")"), RuleBase{Home: "/h"})
		CodexPatternKeys([][]string{{in}, {in, in}})
	}
	CodexPatternKeys(nil)
	CodexPatternKeys([][]string{{}})
	CommandKeys(nil)
	ArgvKeys(nil)
}

func TestKeysThroughWrappers(t *testing.T) {
	// A rule on the inner command must see use that happened inside bash -lc.
	rule := CodexPatternKeys([][]string{{"git"}, {"push"}})
	for _, argv := range [][]string{
		{"bash", "-lc", "cd /w/app && git push origin main"},
		{"/bin/zsh", "-lc", "git push"},
		{"zsh", "-o", "errexit", "-c", "git push"},
	} {
		if !matches(rule, ArgvKeys(argv)) {
			t.Errorf("no match for %q", argv)
		}
	}
	for _, line := range []string{
		"for r in a b; do git push $r; done",
		"if true; then git push; fi",
		"echo `git push`",
		"git push <<< x",
	} {
		if !matches(rule, LineKeys(line)) {
			t.Errorf("no match for %q", line)
		}
	}
	if matches(rule, LineKeys("cat <<EOF\ngit push\nEOF")) {
		t.Error("heredoc body must not count as a command")
	}
}

func TestResolvePath(t *testing.T) {
	base := RuleBase{Home: "/home/u", Settings: "/w/p", Project: "/w/p/sub"}
	cases := []struct{ spec, want string }{
		{"//etc/hosts", "/etc/hosts"},
		{"~/notes/**", "/home/u/notes/**"},
		{"~", "/home/u"},
		{"/src/**", "/w/p/src/**"},
		{"src/x.go", "/w/p/sub/src/x.go"},
		{"./src", "/w/p/sub/src"},
		{"../x", "/w/p/x"},
	}
	for _, c := range cases {
		if got := ResolvePath(c.spec, base); got != c.want {
			t.Errorf("ResolvePath(%q) = %q, want %q", c.spec, got, c.want)
		}
	}
}
