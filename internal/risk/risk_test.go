package risk

import (
	"slices"
	"testing"

	"github.com/yihanzhu/grants/internal/model"
)

var testEnv = model.Env{Home: "/home/u", ClaudeDir: "/home/u/.claude", CodexHome: "/home/u/.codex"}

func always(string) bool { return true }

func existsOnly(paths ...string) func(string) bool {
	return func(p string) bool { return slices.Contains(paths, p) }
}

func claudeRule(rule, project string, scope model.Scope) *model.Grant {
	return &model.Grant{Agent: model.ClaudeCode, Kind: model.KindRule, Value: rule, Scope: scope, Project: project}
}

func codexRule(pattern ...[]string) *model.Grant {
	return &model.Grant{Agent: model.Codex, Kind: model.KindRule, Tool: "exec", Pattern: pattern, Scope: model.ScopeUser}
}

func TestClaudeBashLevels(t *testing.T) {
	cases := []struct {
		rule string
		want model.Level
	}{
		{"Bash", model.RiskHigh},
		{"Bash(*)", model.RiskHigh},
		{"Bash()", model.RiskHigh},
		{"Bash(bash -c:*)", model.RiskHigh},
		{"Bash(bash -lc 'make test')", model.RiskHigh},
		{"Bash(python -c:*)", model.RiskHigh},
		{"Bash(python3 -c 'print(1)')", model.RiskHigh},
		{"Bash(node -e:*)", model.RiskHigh},
		{"Bash(ruby -e:*)", model.RiskHigh},
		{"Bash(perl -e:*)", model.RiskHigh},
		{"Bash(osascript:*)", model.RiskHigh},
		{"Bash(eval:*)", model.RiskHigh},
		{"Bash(exec:*)", model.RiskHigh},
		{"Bash(env)", model.RiskHigh},
		{"Bash(xargs:*)", model.RiskHigh},
		{"Bash(sudo:*)", model.RiskHigh},
		{"Bash(doas:*)", model.RiskHigh},
		{"Bash(su:*)", model.RiskHigh},
		{"Bash(rm:*)", model.RiskHigh},
		{"Bash(rm -rf node_modules)", model.RiskHigh},
		{"Bash(git push:*)", model.RiskHigh},
		{"Bash(git reset --hard:*)", model.RiskHigh},
		{"Bash(git clean:*)", model.RiskHigh},
		{"Bash(curl:*)", model.RiskHigh},
		{"Bash(curl https://example.com/x:*)", model.RiskHigh},
		{"Bash(wget example.com)", model.RiskHigh},
		{"Bash(ssh:*)", model.RiskHigh},
		{"Bash(scp a.txt host:/tmp)", model.RiskHigh},
		{"Bash(rsync -a src/ u@host:dst/)", model.RiskHigh},
		{"Bash(docker run:*)", model.RiskHigh},
		{"Bash(kubectl:*)", model.RiskHigh},
		{"Bash(terraform apply:*)", model.RiskHigh},
		{"Bash(gh pr create:*)", model.RiskHigh},
		{"Bash(gh api:*)", model.RiskHigh},
		{"Bash(npm publish:*)", model.RiskHigh},
		{"Bash(pnpm publish)", model.RiskHigh},
		{"Bash(yarn publish)", model.RiskHigh},
		{"Bash(chmod -R 777 .)", model.RiskHigh},
		{"Bash(chown -R u .)", model.RiskHigh},
		{"Bash(dd:*)", model.RiskHigh},
		{"Bash(mkfs.ext4:*)", model.RiskHigh},
		{"Bash(kill:*)", model.RiskHigh},
		{"Bash(pkill:*)", model.RiskHigh},
		{"Bash(launchctl:*)", model.RiskHigh},
		{"Bash(crontab:*)", model.RiskHigh},
		{"Bash(security:*)", model.RiskHigh},
		{"Bash(find . -delete)", model.RiskHigh},
		{"Bash(find . -name x -exec rm {} ;)", model.RiskHigh},
		{"Bash(git:*)", model.RiskHigh},
		{"Bash(npm:*)", model.RiskHigh},
		{"Bash(npx:*)", model.RiskHigh},
		{"Bash(pnpm:*)", model.RiskHigh},
		{"Bash(yarn:*)", model.RiskHigh},
		{"Bash(uv:*)", model.RiskHigh},
		{"Bash(uvx:*)", model.RiskHigh},
		{"Bash(pip:*)", model.RiskHigh},
		{"Bash(brew:*)", model.RiskHigh},
		{"Bash(cargo:*)", model.RiskHigh},
		{"Bash(go:*)", model.RiskHigh},
		{"Bash(make:*)", model.RiskHigh},
		{"Bash(python:*)", model.RiskHigh},
		{"Bash(node:*)", model.RiskHigh},
		{"Bash(sh:*)", model.RiskHigh},
		{"Bash(/bin/rm -rf x)", model.RiskHigh},
		{"Bash(cd x && rm -rf y)", model.RiskHigh},
		{"Bash(echo hi | bash)", model.RiskHigh},

		{"Bash(npm run build)", model.RiskMedium},
		{"Bash(npm test:*)", model.RiskMedium},
		{"Bash(npx prettier:*)", model.RiskMedium},
		{"Bash(pnpm install:*)", model.RiskMedium},
		{"Bash(yarn build)", model.RiskMedium},
		{"Bash(make test:*)", model.RiskMedium},
		{"Bash(cargo run:*)", model.RiskMedium},
		{"Bash(go run:*)", model.RiskMedium},
		{"Bash(uv run:*)", model.RiskMedium},
		{"Bash(pip install:*)", model.RiskMedium},
		{"Bash(brew install:*)", model.RiskMedium},
		{"Bash(xcodebuild:*)", model.RiskMedium},
		{"Bash(git commit:*)", model.RiskMedium},
		{"Bash(git merge:*)", model.RiskMedium},
		{"Bash(git rebase:*)", model.RiskMedium},
		{"Bash(git checkout:*)", model.RiskMedium},
		{"Bash(git switch:*)", model.RiskMedium},
		{"Bash(git stash:*)", model.RiskMedium},
		{"Bash(git tag:*)", model.RiskMedium},
		{"Bash(git add:*)", model.RiskMedium},
		{"Bash(git -C /w/app commit:*)", model.RiskMedium},
		{"Bash(mv:*)", model.RiskMedium},
		{"Bash(cp -r a b)", model.RiskMedium},
		{"Bash(open:*)", model.RiskMedium},
		{"Bash(mkdir:*)", model.RiskMedium},
		{"Bash(touch:*)", model.RiskMedium},
		{"Bash(frobnicate:*)", model.RiskMedium},
		{"Bash(python script.py)", model.RiskMedium},
		{"Bash(bash run.sh)", model.RiskMedium},
		{"Bash(ls *)", model.RiskLow}, // " *" is the prefix form, not a wildcard in the middle
		{"Bash(git * main)", model.RiskMedium},
		{"Bash(ls*)", model.RiskMedium},
		{"Bash(gh pr view:*)", model.RiskMedium},
		{"Bash(scp a b)", model.RiskMedium},

		{"Bash(ls:*)", model.RiskLow},
		{"Bash(cat README.md)", model.RiskLow},
		{"Bash(head:*)", model.RiskLow},
		{"Bash(tail:*)", model.RiskLow},
		{"Bash(wc:*)", model.RiskLow},
		{"Bash(grep:*)", model.RiskLow},
		{"Bash(rg:*)", model.RiskLow},
		{"Bash(find . -name x)", model.RiskLow},
		{"Bash(git status)", model.RiskLow},
		{"Bash(git log:*)", model.RiskLow},
		{"Bash(git diff:*)", model.RiskLow},
		{"Bash(git show:*)", model.RiskLow},
		{"Bash(git branch:*)", model.RiskLow},
		{"Bash(git rev-parse:*)", model.RiskLow},
		{"Bash(pwd)", model.RiskLow},
		{"Bash(which:*)", model.RiskLow},
		{"Bash(echo:*)", model.RiskLow},
		{"Bash(jq:*)", model.RiskLow},
		{"Bash(stat:*)", model.RiskLow},
		{"Bash(date)", model.RiskLow},
		{"Bash(file:*)", model.RiskLow},
		{"Bash(go test:*)", model.RiskLow},
		{"Bash(go build ./...)", model.RiskLow},
		{"Bash(go vet:*)", model.RiskLow},
		{"Bash(swift test:*)", model.RiskLow},
		{"Bash(swift build:*)", model.RiskLow},
		{"Bash(cargo test:*)", model.RiskLow},
		{"Bash(curl localhost:3000/health)", model.RiskLow},
		{"Bash(curl -s http://127.0.0.1:8080/x:*)", model.RiskLow},
		{"Bash(wget http://localhost/x)", model.RiskLow},
		{"Bash(curl http://[::1]:80/)", model.RiskLow},
		{"Bash(env FOO=1 ls)", model.RiskLow},
		{"Bash(FOO=1 ls:*)", model.RiskLow},
		{"Bash(timeout 5 ls:*)", model.RiskLow},
	}
	for _, c := range cases {
		g := claudeRule(c.rule, "/work/app", model.ScopeProject)
		Assess(g, testEnv, always)
		if g.Risk.Level != c.want {
			t.Errorf("%s: got %s %v, want %s", c.rule, g.Risk.Level, g.Risk.Reasons, c.want)
		}
		if len(g.Risk.Reasons) == 0 {
			t.Errorf("%s: no reasons", c.rule)
		}
	}
}

func TestClaudeNonBashLevels(t *testing.T) {
	cases := []struct {
		rule    string
		project string
		scope   model.Scope
		want    model.Level
	}{
		{"Edit", "/work/app", model.ScopeProject, model.RiskHigh},
		{"Write", "/work/app", model.ScopeProject, model.RiskHigh},
		{"MultiEdit(*)", "/work/app", model.ScopeProject, model.RiskHigh},
		{"NotebookEdit", "", model.ScopeUser, model.RiskHigh},
		{"WebFetch", "", model.ScopeUser, model.RiskHigh},
		{"WebFetch(domain:*)", "", model.ScopeUser, model.RiskHigh},
		{"WebFetch(domain:example.com)", "", model.ScopeUser, model.RiskLow},
		{"WebSearch", "", model.ScopeUser, model.RiskLow},
		{"Read", "", model.ScopeUser, model.RiskMedium},
		{"mcp__files", "", model.ScopeUser, model.RiskMedium},
		{"mcp__files__*", "", model.ScopeUser, model.RiskMedium},
		{"mcp__files__delete_file", "", model.ScopeUser, model.RiskMedium},
		{"mcp__files__createIssue", "", model.ScopeUser, model.RiskMedium},
		{"mcp__files__send-message", "", model.ScopeUser, model.RiskMedium},
		{"mcp__files__list_files", "", model.ScopeUser, model.RiskLow},
		{"mcp__files__get_issue", "", model.ScopeUser, model.RiskLow},
		{"mcp__files__truncated_view", "", model.ScopeUser, model.RiskLow},
		{"SomethingNew", "", model.ScopeUser, model.RiskMedium},
		{"Task(helper)", "", model.ScopeUser, model.RiskMedium},

		// paths
		{"Read(src/**)", "/work/app", model.ScopeProject, model.RiskLow},
		{"Edit(src/**)", "/work/app", model.ScopeProject, model.RiskLow},
		{"Edit(/src/**)", "/work/app", model.ScopeProject, model.RiskLow},
		{"Edit(//work/app/docs/**)", "/work/app", model.ScopeProject, model.RiskLow},
		{"Edit(~/notes/**)", "/work/app", model.ScopeProject, model.RiskMedium},
		{"Edit(//tmp/**)", "", model.ScopeUser, model.RiskMedium},
		{"Edit(../other/**)", "/work/app", model.ScopeProject, model.RiskMedium},
		{"Read(~/notes/inbox/**)", "/work/app", model.ScopeProject, model.RiskLow},
		{"Read(//etc/hosts)", "", model.ScopeUser, model.RiskLow},
		{"Read(~/code/**)", "", model.ScopeUser, model.RiskMedium},
		{"Read(~/**)", "", model.ScopeUser, model.RiskHigh},
		{"Read(~)", "", model.ScopeUser, model.RiskHigh},
		{"Edit(~/**)", "", model.ScopeUser, model.RiskHigh},
		{"Edit(//**)", "", model.ScopeUser, model.RiskHigh},
		{"Read(//)", "", model.ScopeUser, model.RiskHigh},
		{"Read(**)", "/work/app", model.ScopeProject, model.RiskHigh},
		{"Edit(**)", "/work/app", model.ScopeProject, model.RiskHigh},
		{"Read(~/.ssh/**)", "", model.ScopeUser, model.RiskHigh},
		{"Read(~/.ssh/id_rsa)", "/work/app", model.ScopeProject, model.RiskHigh},
		{"Read(~/.aws/credentials)", "", model.ScopeUser, model.RiskHigh},
		{"Read(~/.gnupg/**)", "", model.ScopeUser, model.RiskHigh},
		{"Read(~/.config/**)", "", model.ScopeUser, model.RiskHigh},
		{"Edit(~/.config/app/x.toml)", "", model.ScopeUser, model.RiskHigh},
		{"Read(~/.netrc)", "", model.ScopeUser, model.RiskHigh},
		{"Read(.env)", "/work/app", model.ScopeProject, model.RiskHigh},
		{"Read(.env.local)", "/work/app", model.ScopeProject, model.RiskHigh},
		{"Edit(**/.env)", "/work/app", model.ScopeProject, model.RiskHigh},
		{"Read(.env.example)", "/work/app", model.ScopeProject, model.RiskLow},
		{"Read(~/Library/Keychains/**)", "", model.ScopeUser, model.RiskHigh},
		{"Read(//Library/Keychains/login.keychain-db)", "", model.ScopeUser, model.RiskHigh},
	}
	for _, c := range cases {
		g := claudeRule(c.rule, c.project, c.scope)
		Assess(g, testEnv, always)
		if g.Risk.Level != c.want {
			t.Errorf("%s: got %s %v, want %s", c.rule, g.Risk.Level, g.Risk.Reasons, c.want)
		}
	}
}

func TestCodexLevels(t *testing.T) {
	cases := []struct {
		name    string
		pattern [][]string
		want    model.Level
	}{
		{"git alone", [][]string{{"git"}}, model.RiskHigh},
		{"git push", [][]string{{"git"}, {"push"}}, model.RiskHigh},
		{"git status", [][]string{{"git"}, {"status"}}, model.RiskLow},
		{"npm test", [][]string{{"npm"}, {"test"}}, model.RiskMedium},
		{"alternatives take the highest", [][]string{{"git"}, {"status", "push"}}, model.RiskHigh},
		{"alternative programs", [][]string{{"npm", "pnpm"}, {"test"}}, model.RiskMedium},
		{"shell wrapper", [][]string{{"/bin/zsh"}, {"-lc"}, {"make x"}}, model.RiskHigh},
		{"bash -c", [][]string{{"bash"}, {"-c"}, {"ls"}}, model.RiskHigh},
		{"rm", [][]string{{"rm"}, {"-rf"}, {"build"}}, model.RiskHigh},
		{"rm by path", [][]string{{"/bin/rm"}}, model.RiskHigh},
		{"curl remote", [][]string{{"curl"}, {"https://example.com/x"}}, model.RiskHigh},
		{"curl local", [][]string{{"curl"}, {"http://localhost:3000/x"}}, model.RiskLow},
		{"ls", [][]string{{"ls"}}, model.RiskLow},
		{"go test", [][]string{{"go"}, {"test"}, {"./..."}}, model.RiskLow},
		{"env alone", [][]string{{"env"}}, model.RiskHigh},
		{"unknown", [][]string{{"frobnicate"}, {"x"}}, model.RiskMedium},
		{"spaces in tokens", [][]string{{"git"}, {"commit"}, {"-m"}, {"two words"}}, model.RiskMedium},
		{"quote in token", [][]string{{"echo"}, {"it's"}}, model.RiskLow},
		{"python -c", [][]string{{"python3"}, {"-c"}, {"print(1)"}}, model.RiskHigh},
	}
	for _, c := range cases {
		g := codexRule(c.pattern...)
		Assess(g, testEnv, always)
		if g.Risk.Level != c.want {
			t.Errorf("%s: got %s %v, want %s", c.name, g.Risk.Level, g.Risk.Reasons, c.want)
		}
	}
}

func TestCodexPatternFromValue(t *testing.T) {
	g := &model.Grant{Agent: model.Codex, Kind: model.KindRule, Value: "git push", Scope: model.ScopeUser}
	Assess(g, testEnv, always)
	if g.Risk.Level != model.RiskHigh {
		t.Errorf("no Pattern: got %s", g.Risk.Level)
	}
}

func TestTrustLevels(t *testing.T) {
	cases := []struct {
		name   string
		agent  model.Agent
		folder string
		exists []string
		want   model.Level
	}{
		{"root", model.ClaudeCode, "/", nil, model.RiskHigh},
		{"home", model.ClaudeCode, "/home/u", nil, model.RiskHigh},
		{"home with slash", model.Codex, "/home/u/", nil, model.RiskHigh},
		{"parent of home", model.ClaudeCode, "/home", nil, model.RiskHigh},
		{"documents", model.ClaudeCode, "/home/u/Documents", nil, model.RiskHigh},
		{"desktop", model.Codex, "/home/u/Desktop", nil, model.RiskHigh},
		{"downloads", model.Codex, "/home/u/Downloads", nil, model.RiskHigh},
		{"library", model.ClaudeCode, "/home/u/Library", nil, model.RiskHigh},
		{"mobile documents", model.ClaudeCode, "/home/u/Library/Mobile Documents", nil, model.RiskHigh},
		{"project", model.ClaudeCode, "/work/app", nil, model.RiskLow},
		{"subfolder of documents", model.Codex, "/home/u/Documents/app", nil, model.RiskLow},
		{"claude settings", model.ClaudeCode, "/work/app", []string{"/work/app/.claude/settings.json"}, model.RiskMedium},
		{"mcp json", model.ClaudeCode, "/work/app", []string{"/work/app/.mcp.json"}, model.RiskMedium},
		{"codex config", model.Codex, "/work/app", []string{"/work/app/.codex/config.toml"}, model.RiskMedium},
		{"codex rules", model.Codex, "/work/app", []string{"/work/app/.codex/rules"}, model.RiskMedium},
		{"codex hooks", model.Codex, "/work/app", []string{"/work/app/.codex/hooks.json"}, model.RiskMedium},
		{"claude config does not count for codex", model.Codex, "/work/app", []string{"/work/app/.claude/settings.json"}, model.RiskLow},
	}
	for _, c := range cases {
		g := &model.Grant{Agent: c.agent, Kind: model.KindTrust, Value: c.folder, Scope: model.ScopeUser}
		Assess(g, testEnv, existsOnly(append(c.exists, c.folder)...))
		if g.Risk.Level != c.want {
			t.Errorf("%s: got %s %v, want %s", c.name, g.Risk.Level, g.Risk.Reasons, c.want)
		}
	}
}

func TestFlags(t *testing.T) {
	type tc struct {
		name   string
		g      *model.Grant
		exists func(string) bool
		want   []model.Flag
	}
	cases := []tc{
		{"missing trust folder", &model.Grant{Agent: model.Codex, Kind: model.KindTrust, Value: "/work/gone"},
			existsOnly(), []model.Flag{model.FlagDeadPath}},
		{"existing trust folder", &model.Grant{Agent: model.Codex, Kind: model.KindTrust, Value: "/work/app"},
			existsOnly("/work/app"), nil},
		{"missing program", claudeRule("Bash(/opt/tools/run.sh:*)", "/work/app", model.ScopeProject),
			existsOnly(), []model.Flag{model.FlagDeadPath}},
		{"missing home program", claudeRule("Bash(~/bin/run.sh:*)", "/work/app", model.ScopeProject),
			existsOnly(), []model.Flag{model.FlagDeadPath}},
		{"existing program", claudeRule("Bash(/opt/tools/run.sh:*)", "/work/app", model.ScopeProject),
			existsOnly("/opt/tools/run.sh"), nil},
		{"program on PATH is not checked", claudeRule("Bash(git status)", "/work/app", model.ScopeProject),
			existsOnly(), nil},
		{"missing read folder", claudeRule("Read(~/old/**)", "", model.ScopeUser),
			existsOnly("/home/u"), []model.Flag{model.FlagDeadPath}},
		{"existing read folder", claudeRule("Read(~/old/**)", "", model.ScopeUser),
			existsOnly("/home/u/old"), nil},
		{"missing edit folder", claudeRule("Edit(//srv/data/**)", "", model.ScopeUser),
			existsOnly(), []model.Flag{model.FlagDeadPath}},
		{"edit of a new file in an existing folder", claudeRule("Write(out/new.txt)", "/work/app", model.ScopeProject),
			existsOnly("/work/app/out"), nil},
		{"codex missing program", codexRule([]string{"/opt/x/tool"}, []string{"run"}),
			existsOnly(), []model.Flag{model.FlagDeadPath}},
		{"one-off url path", claudeRule("Bash(curl https://example.com/a/b)", "/work/app", model.ScopeProject),
			always, []model.Flag{model.FlagOneOff}},
		{"one-off url query", claudeRule("Bash(curl 'https://example.com/?q=1')", "/work/app", model.ScopeProject),
			always, []model.Flag{model.FlagOneOff}},
		{"host-only url is not one-off", claudeRule("Bash(curl https://example.com:*)", "/work/app", model.ScopeProject),
			always, nil},
		{"one-off script", claudeRule("Bash(sh -c 'echo hi')", "/work/app", model.ScopeProject),
			always, []model.Flag{model.FlagOneOff}},
		{"one-off many tokens", claudeRule("Bash(a b c d e f g)", "/work/app", model.ScopeProject),
			always, []model.Flag{model.FlagOneOff}},
		{"six tokens are fine", claudeRule("Bash(a b c d e f)", "/work/app", model.ScopeProject),
			always, nil},
		{"one-off long token", claudeRule("Bash(echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)", "/work/app", model.ScopeProject),
			always, []model.Flag{model.FlagOneOff}},
		{"long path in a Read rule is fine", claudeRule("Read(~/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/**)", "", model.ScopeUser),
			always, nil},
		{"codex one-off script", codexRule([]string{"bash"}, []string{"-lc"}, []string{"make test && make lint"}),
			always, []model.Flag{model.FlagOneOff}},
		{"codex many tokens", codexRule([]string{"a"}, []string{"b"}, []string{"c"}, []string{"d"}, []string{"e"}, []string{"f"}, []string{"g"}),
			always, []model.Flag{model.FlagOneOff}},
		{"codex short prefix", codexRule([]string{"npm"}, []string{"test"}),
			always, nil},
		{"secret", claudeRule("Bash(curl -H 'Authorization: Bearer abcdef123456' localhost)", "/work/app", model.ScopeProject),
			always, []model.Flag{model.FlagSecret}},
		{"secret in codex rule", codexRule([]string{"deploy"}, []string{"--token=abcdef123456"}),
			always, []model.Flag{model.FlagSecret}},
		{"env var reference is not a secret", claudeRule("Bash(deploy --token=$TOKEN)", "/work/app", model.ScopeProject),
			always, nil},
	}
	for _, c := range cases {
		Assess(c.g, testEnv, c.exists)
		if !slices.Equal(c.g.Flags, c.want) {
			t.Errorf("%s: flags %v, want %v", c.name, c.g.Flags, c.want)
		}
	}
}

func TestSecretRaisesLevel(t *testing.T) {
	g := claudeRule("Bash(echo ghp_0123456789abcdefghijABCDEF:*)", "/work/app", model.ScopeProject)
	Assess(g, testEnv, always)
	if g.Risk.Level != model.RiskHigh || !slices.Contains(g.Risk.Reasons, "contains a credential") {
		t.Errorf("got %+v", g.Risk)
	}
}

func TestKeepsExistingFlagsAndNoDuplicates(t *testing.T) {
	g := claudeRule("Bash(curl https://example.com/a)", "/work/app", model.ScopeProject)
	g.Flags = []model.Flag{model.FlagUnused, model.FlagCommitted, model.FlagOneOff}
	Assess(g, testEnv, always)
	Assess(g, testEnv, always)
	want := []model.Flag{model.FlagUnused, model.FlagCommitted, model.FlagOneOff}
	if !slices.Equal(g.Flags, want) {
		t.Errorf("flags %v, want %v", g.Flags, want)
	}
}

func TestStatusesAndNilExists(t *testing.T) {
	for _, st := range []model.Status{model.StatusActive, model.StatusGone, model.StatusUnknown} {
		for _, g := range []*model.Grant{
			claudeRule("Bash(git push:*)", "/work/app", model.ScopeProject),
			codexRule([]string{"git"}, []string{"push"}),
			{Agent: model.Codex, Kind: model.KindTrust, Value: "/work/app"},
			{},
		} {
			g.Status = st
			Assess(g, model.Env{}, nil)
			if g.Risk.Level == "" {
				t.Errorf("%s: no level for %+v", st, g)
			}
		}
	}
}

func TestEmptyGrantIsLow(t *testing.T) {
	g := &model.Grant{}
	Assess(g, testEnv, always)
	if g.Risk.Level == "" {
		t.Error("no level")
	}
}

func TestReasonsAreOnlyTopLevel(t *testing.T) {
	g := claudeRule("Bash(ls && rm -rf x)", "/work/app", model.ScopeProject)
	Assess(g, testEnv, always)
	if g.Risk.Level != model.RiskHigh || len(g.Risk.Reasons) != 1 {
		t.Errorf("got %+v", g.Risk)
	}
}

func TestOddInputsNeverPanic(t *testing.T) {
	odd := []string{"", "(", ")", "Bash(", "Bash()", "Bash(()", "Read(", "Read()", "Edit(//)", "Read(~~)", "mcp__", "mcp____", "mcp__a____b",
		"Bash(\x00)", "Bash(' ')", "WebFetch(domain:)", "Read(**/**)", "Bash(*:*)", "Bash(:*)", "Bash( *)"}
	for _, v := range odd {
		for _, scope := range []model.Scope{model.ScopeUser, model.ScopeProject, model.ScopeLocal, model.ScopeLegacy, model.ScopeManaged, ""} {
			Assess(claudeRule(v, "", scope), testEnv, always)
			Assess(claudeRule(v, "/work/app", scope), model.Env{}, nil)
		}
		Assess(&model.Grant{Agent: model.Codex, Kind: model.KindRule, Value: v, Pattern: [][]string{{v}, {}, {v, v}}}, testEnv, always)
		Assess(&model.Grant{Agent: model.Codex, Kind: model.KindTrust, Value: v}, testEnv, always)
		Redact(v)
	}
	// A pattern with many alternatives stays bounded.
	big := make([][]string, 12)
	for i := range big {
		big[i] = []string{"a", "b", "c", "d"}
	}
	Assess(codexRule(big...), testEnv, always)
}

func TestAssessBroadTrust(t *testing.T) {
	trust := func(agent model.Agent) *model.Grant {
		g := &model.Grant{Agent: agent, Kind: model.KindTrust, Value: "/work", Scope: model.ScopeUser}
		Assess(g, testEnv, existsOnly("/work"))
		return g
	}
	cx := trust(model.Codex)
	AssessBroadTrust(cx, 3)
	if cx.Risk.Level != model.RiskHigh || len(cx.Risk.Reasons) != 1 || cx.Risk.Reasons[0] != "every project inside inherits trust (3 projects)" {
		t.Errorf("codex: %+v", cx.Risk)
	}
	cl := trust(model.ClaudeCode)
	AssessBroadTrust(cl, 5)
	if cl.Risk.Level != model.RiskMedium || len(cl.Risk.Reasons) != 1 || cl.Risk.Reasons[0] != "folders inside it share this trust (5 projects)" {
		t.Errorf("claude: %+v", cl.Risk)
	}

	// Fewer than three projects change nothing.
	few := trust(model.Codex)
	AssessBroadTrust(few, 2)
	if few.Risk.Level != model.RiskLow || few.Risk.Reasons[0] != "limited to one folder" {
		t.Errorf("two projects: %+v", few.Risk)
	}
	// A higher level stays, and the new reason joins only when it matches that level.
	home := &model.Grant{Agent: model.ClaudeCode, Kind: model.KindTrust, Value: "/home/u", Scope: model.ScopeUser}
	Assess(home, testEnv, always)
	AssessBroadTrust(home, 4)
	if home.Risk.Level != model.RiskHigh || len(home.Risk.Reasons) != 1 {
		t.Errorf("home: %+v", home.Risk)
	}
	// Rules are not trusted folders.
	rule := claudeRule("Bash(ls:*)", "", model.ScopeUser)
	Assess(rule, testEnv, always)
	before := rule.Risk
	AssessBroadTrust(rule, 9)
	if rule.Risk.Level != before.Level || len(rule.Risk.Reasons) != len(before.Reasons) {
		t.Errorf("rule changed: %+v", rule.Risk)
	}
}
