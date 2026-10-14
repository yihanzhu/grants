package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/claude"
	"github.com/yihanzhu/grants/internal/codex"
	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
	"github.com/yihanzhu/grants/internal/store"
)

// Fixtures are synthetic and live under t.TempDir().

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func env() model.Env {
	return model.Env{Home: "/home/u", Now: now, UnusedAfter: 90 * 24 * time.Hour}
}

func TestEnvFromOS(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GRANTS_STATE_DIR", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("GRANTS_NOW", "")

	t.Run("defaults", func(t *testing.T) {
		e, err := EnvFromOS(0)
		if err != nil {
			t.Fatal(err)
		}
		if e.Home != home || e.ClaudeDir != filepath.Join(home, ".claude") || e.ClaudeJSON != filepath.Join(home, ".claude.json") ||
			e.CodexHome != filepath.Join(home, ".codex") || e.StateDir != filepath.Join(home, ".local", "state", "grants") {
			t.Errorf("env = %+v", e)
		}
		if e.UnusedAfter != 90*24*time.Hour || time.Since(e.Now) > time.Minute {
			t.Errorf("unused=%v now=%v", e.UnusedAfter, e.Now)
		}
	})
	t.Run("overrides", func(t *testing.T) {
		cfg := filepath.Join(home, "cfg")
		if err := os.MkdirAll(cfg, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg, ".claude.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CLAUDE_CONFIG_DIR", cfg)
		t.Setenv("CODEX_HOME", filepath.Join(home, "cx"))
		t.Setenv("GRANTS_STATE_DIR", filepath.Join(home, "st"))
		t.Setenv("GRANTS_NOW", "2026-10-13T12:00:00Z")
		e, err := EnvFromOS(30 * 24 * time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if e.ClaudeDir != cfg || e.ClaudeJSON != filepath.Join(cfg, ".claude.json") || e.CodexHome != filepath.Join(home, "cx") ||
			e.StateDir != filepath.Join(home, "st") || !e.Now.Equal(now) || e.UnusedAfter != 30*24*time.Hour {
			t.Errorf("env = %+v", e)
		}
	})
	t.Run("config dir without its own .claude.json keeps the home one", func(t *testing.T) {
		t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "empty"))
		e, _ := EnvFromOS(0)
		if e.ClaudeJSON != filepath.Join(home, ".claude.json") {
			t.Errorf("ClaudeJSON = %s", e.ClaudeJSON)
		}
	})
	t.Run("XDG state home", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", filepath.Join(home, "xdg"))
		e, _ := EnvFromOS(0)
		if e.StateDir != filepath.Join(home, "xdg", "grants") {
			t.Errorf("StateDir = %s", e.StateDir)
		}
	})
	t.Run("bad GRANTS_NOW", func(t *testing.T) {
		t.Setenv("GRANTS_NOW", "yesterday")
		if _, err := EnvFromOS(0); err == nil {
			t.Error("want an error")
		}
	})
}

// codexHome writes a Codex home with the given rules and trusted folders. Nothing in
// it records sessions, so every grant is dated by its files and by grants' own history.
func codexHome(t *testing.T, rules, trusted []string) model.Env {
	t.Helper()
	restore := claude.OverrideManaged()
	t.Cleanup(restore)
	t.Cleanup(codex.OverrideManaged(filepath.Join(t.TempDir(), "no-managed")))
	root := t.TempDir()
	env := model.Env{
		Home: filepath.Join(root, "home"), ClaudeDir: filepath.Join(root, "home", ".claude"), ClaudeJSON: filepath.Join(root, "home", ".claude.json"),
		CodexHome: filepath.Join(root, "home", ".codex"), StateDir: filepath.Join(root, "state"), Now: now, UnusedAfter: 90 * 24 * time.Hour,
	}
	setCodex(t, env, rules, trusted)
	return env
}

func setCodex(t *testing.T, env model.Env, rules, trusted []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(env.CodexHome, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	var r, c strings.Builder
	for _, p := range rules {
		r.WriteString(`prefix_rule(pattern=["` + p + `"], decision="allow")` + "\n")
	}
	for _, p := range trusted {
		c.WriteString("[projects.\"" + p + "\"]\ntrust_level = \"trusted\"\n\n")
	}
	if err := os.WriteFile(filepath.Join(env.CodexHome, "rules", "default.rules"), []byte(r.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.CodexHome, "config.toml"), []byte(c.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byValue(t *testing.T, gs []model.Grant, value string) model.Grant {
	t.Helper()
	for _, g := range gs {
		if g.Value == value {
			return g
		}
	}
	t.Fatalf("no grant %q in %d grants", value, len(gs))
	return model.Grant{}
}

func TestRunNothingInstalled(t *testing.T) {
	root := t.TempDir()
	env := model.Env{Home: root, ClaudeDir: filepath.Join(root, ".claude"), ClaudeJSON: filepath.Join(root, ".claude.json"), CodexHome: filepath.Join(root, ".codex"), StateDir: filepath.Join(root, "state"), Now: now, UnusedAfter: time.Hour}
	res, err := Run(env, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Reports) != 2 || res.Reports[0].Agent != model.ClaudeCode || res.Reports[1].Agent != model.Codex {
		t.Fatalf("reports = %+v", res.Reports)
	}
	if res.Reports[0].Found || res.Reports[1].Found || len(res.Grants) != 0 || len(res.Notes) != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestRunTracksGrantsAcrossRuns(t *testing.T) {
	trusted := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(trusted, 0o755); err != nil {
		t.Fatal(err)
	}
	env := codexHome(t, []string{"alpha", "beta"}, []string{trusted})

	// Run 1: both rules are new, so they are dated "before now".
	env.Now = day("2026-10-01")
	res, err := Run(env, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a := byValue(t, res.Grants, "alpha")
	if a.Status != model.StatusActive || a.ID == "" || a.ID != model.MakeID(a.Key) {
		t.Errorf("alpha = %+v", a)
	}
	if a.Granted.Before.IsZero() {
		t.Errorf("alpha has no date: %+v", a.Granted)
	}

	// Run 2 a week later: beta is gone from the rules file.
	setCodex(t, env, []string{"alpha"}, []string{trusted})
	env.Now = day("2026-10-08")
	res, err = Run(env, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	beta := byValue(t, res.Grants, "beta")
	if beta.Status != model.StatusGone || beta.Agent != model.Codex || beta.Kind != model.KindRule || beta.Revocable {
		t.Errorf("beta = %+v", beta)
	}
	if !beta.LastSeen.Equal(day("2026-10-01")) {
		t.Errorf("beta last seen = %v, want 2026-10-01", beta.LastSeen)
	}
	if !beta.Removed.After.Equal(day("2026-10-01")) || !beta.Removed.Before.Equal(day("2026-10-08")) {
		t.Errorf("beta removed = %+v, want between the runs", beta.Removed)
	}
	if beta.Risk.Level == "" || beta.HasFlag(model.FlagDeadPath) {
		t.Errorf("beta risk/flags = %+v %v", beta.Risk, beta.Flags)
	}
	if got := byValue(t, res.Grants, "alpha"); got.Status != model.StatusActive {
		t.Errorf("alpha = %+v", got)
	}
	// Active grants sort before the gone one.
	if res.Grants[len(res.Grants)-1].Value != "beta" {
		t.Errorf("last grant = %q, want beta", res.Grants[len(res.Grants)-1].Value)
	}

	// Run 3: the folder is deleted, so its trust grant is flagged dead-path.
	if err := os.RemoveAll(trusted); err != nil {
		t.Fatal(err)
	}
	env.Now = day("2026-10-09")
	res, _ = Run(env, scan.Options{})
	tg := byValue(t, res.Grants, trusted)
	if !tg.HasFlag(model.FlagDeadPath) {
		t.Errorf("trust flags = %v, want dead-path", tg.Flags)
	}

	// An agent that is not found never produces gone grants from the store.
	if err := os.RemoveAll(env.CodexHome); err != nil {
		t.Fatal(err)
	}
	env.Now = day("2026-10-10")
	res, _ = Run(env, scan.Options{})
	if len(res.Grants) != 0 {
		t.Errorf("grants = %d, want none when the agent folder is missing", len(res.Grants))
	}
}

func TestRunStateFolderProblems(t *testing.T) {
	env := codexHome(t, []string{"alpha"}, nil)
	// A state folder that cannot be created: its parent is a file.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.StateDir = filepath.Join(blocker, "state")
	res, err := Run(env, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Grants) != 1 || len(res.Notes) == 0 || res.Notes[0].Level != "warn" {
		t.Errorf("grants=%d notes=%+v", len(res.Grants), res.Notes)
	}
}

func active(key, value string) model.Grant {
	return model.Grant{Key: key, Agent: model.Codex, Kind: model.KindRule, Value: value, Tool: "exec", Status: model.StatusActive, Revocable: true}
}

func TestUnusedFlag(t *testing.T) {
	cutoff := now.Add(-90 * 24 * time.Hour)
	old := model.Window{Before: cutoff.Add(-24 * time.Hour)}
	recent := model.Window{Before: now.Add(-10 * 24 * time.Hour)}
	covers := cutoff.Add(-24 * time.Hour) // history reaches back past the window
	tests := []struct {
		name string
		mod  func(g *model.Grant)
		want bool
	}{
		{"never used, old, history covers the window", func(g *model.Grant) {
			g.Granted, g.Usage = old, model.Usage{Known: true, Since: covers}
		}, true},
		{"used inside the window", func(g *model.Grant) {
			g.Granted, g.Usage = old, model.Usage{Known: true, Count: 3, Last: now.Add(-5 * 24 * time.Hour), Since: covers}
		}, false},
		{"last used before the window", func(g *model.Grant) {
			g.Granted, g.Usage = old, model.Usage{Known: true, Count: 3, Last: cutoff.Add(-time.Hour), Since: covers}
		}, true},
		{"history too short", func(g *model.Grant) {
			g.Granted, g.Usage = old, model.Usage{Known: true, Since: now.Add(-30 * 24 * time.Hour)}
		}, false},
		{"history start unknown", func(g *model.Grant) {
			g.Granted, g.Usage = old, model.Usage{Known: true}
		}, false},
		{"use cannot be measured", func(g *model.Grant) {
			g.Granted, g.Usage = old, model.Usage{Since: covers}
		}, false},
		{"granted inside the window", func(g *model.Grant) {
			g.Granted, g.Usage = recent, model.Usage{Known: true, Since: covers}
		}, false},
		{"granted date unknown counts as old", func(g *model.Grant) {
			g.Usage = model.Usage{Known: true, Since: covers}
		}, true},
		{"gone grants are not flagged", func(g *model.Grant) {
			g.Status, g.Granted, g.Usage = model.StatusGone, old, model.Usage{Known: true, Since: covers}
		}, false},
		{"a flag set already is kept once", func(g *model.Grant) {
			g.Granted, g.Usage, g.Flags = old, model.Usage{Known: true, Since: covers}, []model.Flag{model.FlagUnused}
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := active("k", "alpha")
			tt.mod(&g)
			out := merge(env(), []model.Report{{Agent: model.Codex, Found: true, Grants: []model.Grant{g}}}, &store.Observations{Grants: map[string]*store.Seen{}})
			n := 0
			for _, f := range out[0].Flags {
				if f == model.FlagUnused {
					n++
				}
			}
			if want := map[bool]int{true: 1, false: 0}[tt.want]; n != want {
				t.Errorf("unused flags = %d, want %d", n, want)
			}
		})
	}

	t.Run("a first-seen date does not make an undated grant look new", func(t *testing.T) {
		g := active("k", "alpha")
		g.Usage = model.Usage{Known: true, Since: covers}
		out := merge(env(), []model.Report{{Agent: model.Codex, Found: true, Grants: []model.Grant{g}}}, &store.Observations{Grants: map[string]*store.Seen{}})
		if !out[0].HasFlag(model.FlagUnused) || out[0].Granted.Source != firstSeen || !out[0].Granted.Before.Equal(now) {
			t.Errorf("grant = %+v", out[0])
		}
	})
}

func TestMergeObservations(t *testing.T) {
	obs := &store.Observations{Grants: map[string]*store.Seen{}}
	dated := active("dated", "dated")
	dated.Granted = model.Window{Before: day("2026-05-01"), Source: "rules file last changed"}
	undated := active("undated", "undated")

	run := func(at time.Time, grants ...model.Grant) []model.Grant {
		e := env()
		e.Now = at
		return merge(e, []model.Report{{Agent: model.Codex, Found: true, Grants: grants}}, obs)
	}

	out := run(day("2026-10-01"), dated, undated)
	if g := byValue(t, out, "dated"); !g.Granted.Before.Equal(day("2026-05-01")) || g.Granted.Source != "rules file last changed" {
		t.Errorf("an adapter date must win: %+v", g.Granted)
	}
	if g := byValue(t, out, "undated"); !g.Granted.Before.Equal(day("2026-10-01")) || !g.Granted.After.IsZero() || g.Granted.Source != firstSeen {
		t.Errorf("first run: %+v", g.Granted)
	}

	// A new grant on the second run was absent on the first.
	later := active("later", "later")
	out = run(day("2026-10-05"), dated, undated, later)
	if g := byValue(t, out, "later"); !g.Granted.After.Equal(day("2026-10-01")) || !g.Granted.Before.Equal(day("2026-10-05")) {
		t.Errorf("second run new grant: %+v", g.Granted)
	}
	if g := byValue(t, out, "undated"); !g.Granted.Before.Equal(day("2026-10-01")) {
		t.Errorf("an old grant keeps its first sighting: %+v", g.Granted)
	}

	// A grant the adapter reports as gone gains the store's view of it.
	goneG := active("undated", "undated")
	goneG.Status, goneG.Revocable = model.StatusGone, false
	out = run(day("2026-10-09"), dated, goneG, later)
	g := byValue(t, out, "undated")
	if g.Status != model.StatusGone || !g.LastSeen.Equal(day("2026-10-05")) || !g.Removed.Before.Equal(day("2026-10-09")) {
		t.Errorf("adapter-gone grant = %+v", g)
	}
	if len(out) != 3 {
		t.Errorf("grants = %d, want 3 (no duplicate for the gone key)", len(out))
	}
}

func TestMergeGoneFromStore(t *testing.T) {
	obs := &store.Observations{
		Runs: []time.Time{day("2026-09-01"), day("2026-09-10")},
		Grants: map[string]*store.Seen{
			"claude-code|rule|f|Bash(git push:*)": {Agent: model.ClaudeCode, Kind: model.KindRule, Value: "Bash(git push:*)", First: day("2026-09-01"), Last: day("2026-09-01")},
			"claude-code|trust|/work/x":           {Agent: model.ClaudeCode, Kind: model.KindTrust, Value: "/work/x", First: day("2026-09-01"), Last: day("2026-09-01")},
			"codex|rule|[[\"ls\"]]":               {Agent: model.Codex, Kind: model.KindRule, Value: "ls", First: day("2026-09-01"), Last: day("2026-09-01")},
			"codex|rule|[[\"zzz\"]]":              {Agent: model.Codex, Kind: model.KindRule, Value: "zzz", First: day("2026-09-01"), Last: day("2026-09-10")}, // still seen on the last run
		},
	}
	e := env()
	e.Now = day("2026-09-10")
	reports := []model.Report{
		{Agent: model.ClaudeCode, Found: true},
		{Agent: model.Codex, Found: false}, // Codex folder missing: its grants are not declared gone
	}
	out := merge(e, reports, obs)
	if len(out) != 2 {
		t.Fatalf("grants = %d, want the 2 Claude Code ones", len(out))
	}
	rule := byValue(t, out, "Bash(git push:*)")
	if rule.Status != model.StatusGone || rule.Tool != "Bash" || rule.Scope != model.ScopeUser || rule.Revocable || rule.RevokeNote == "" {
		t.Errorf("rule = %+v", rule)
	}
	if rule.Risk.Level != model.RiskHigh {
		t.Errorf("a gone rule is still rated: %+v", rule.Risk)
	}
	if !rule.Removed.After.Equal(day("2026-09-01")) || !rule.Removed.Before.Equal(day("2026-09-10")) || len(rule.Evidence) == 0 {
		t.Errorf("rule removal = %+v evidence=%d", rule.Removed, len(rule.Evidence))
	}
	trust := byValue(t, out, "/work/x")
	if trust.Kind != model.KindTrust || trust.HasFlag(model.FlagDeadPath) {
		t.Errorf("trust = %+v", trust)
	}
}

func TestAssignIDsCollisions(t *testing.T) {
	// A fake hash makes collisions easy: keys a, b, c share their first 7 digits.
	hash := func(k string) string {
		switch k {
		case "a":
			return "1111111aaaa"
		case "b":
			return "1111111bbbb"
		case "c":
			return "1111111aaab" // collides with a for 10 digits
		case "d":
			return "2222222dddd"
		}
		return k
	}
	gs := []model.Grant{{Key: "a"}, {Key: "b"}, {Key: "c"}, {Key: "d"}}
	assignIDs(gs, hash)
	// a and c share their first 10 digits, so they need 11; b needs 8; d stays at 7.
	want := []string{"1111111aaaa", "1111111b", "1111111aaab", "2222222"}
	seen := map[string]bool{}
	for i, g := range gs {
		if g.ID != want[i] {
			t.Errorf("id of %s = %q, want %q", g.Key, g.ID, want[i])
		}
		if seen[g.ID] {
			t.Errorf("id %q is not unique", g.ID)
		}
		seen[g.ID] = true
	}

	// Identical keys cannot be told apart; the loop must still end.
	gs = []model.Grant{{Key: "same"}, {Key: "same"}}
	assignIDs(gs, hexOf)
	if gs[0].ID != gs[1].ID || len(gs[0].ID) != 64 {
		t.Errorf("ids = %q %q", gs[0].ID, gs[1].ID)
	}
}

func TestHexOfMatchesMakeID(t *testing.T) {
	for _, k := range []string{"", "codex|rule|[[\"ls\"]]", "claude-code|trust|/work/x"} {
		if got := hexOf(k)[:idLen]; got != model.MakeID(k) {
			t.Errorf("hexOf(%q)[:7] = %q, MakeID = %q", k, got, model.MakeID(k))
		}
	}
}

func TestSortGrants(t *testing.T) {
	mk := func(value string, st model.Status, lvl model.Level, agent model.Agent, kind model.Kind) model.Grant {
		return model.Grant{Key: value, Value: value, Status: st, Agent: agent, Kind: kind, Risk: model.Risk{Level: lvl}}
	}
	gs := []model.Grant{
		mk("gone-high", model.StatusGone, model.RiskHigh, model.Codex, model.KindRule),
		mk("low-codex", model.StatusActive, model.RiskLow, model.Codex, model.KindRule),
		mk("unknown", model.StatusUnknown, model.RiskHigh, model.Codex, model.KindRule),
		mk("high-b", model.StatusActive, model.RiskHigh, model.Codex, model.KindRule),
		mk("high-a", model.StatusActive, model.RiskHigh, model.Codex, model.KindRule),
		mk("high-claude", model.StatusActive, model.RiskHigh, model.ClaudeCode, model.KindTrust),
		mk("med", model.StatusActive, model.RiskMedium, model.ClaudeCode, model.KindRule),
		mk("low-claude-rule", model.StatusActive, model.RiskLow, model.ClaudeCode, model.KindRule),
		mk("low-claude-trust", model.StatusActive, model.RiskLow, model.ClaudeCode, model.KindTrust),
	}
	sortGrants(gs)
	var got []string
	for _, g := range gs {
		got = append(got, g.Value)
	}
	want := "high-claude high-a high-b med low-claude-rule low-claude-trust low-codex unknown gone-high"
	if strings.Join(got, " ") != want {
		t.Errorf("order =\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
}

func TestDeadPathOnlyForActive(t *testing.T) {
	g := model.Grant{Key: "codex|trust|/nowhere/x", Agent: model.Codex, Kind: model.KindTrust, Value: "/nowhere/x/y", Scope: model.ScopeUser, Status: model.StatusGone}
	out := merge(env(), []model.Report{{Agent: model.Codex, Found: true, Grants: []model.Grant{g}}}, &store.Observations{Grants: map[string]*store.Seen{}})
	if out[0].HasFlag(model.FlagDeadPath) {
		t.Errorf("flags = %v", out[0].Flags)
	}
	g.Status = model.StatusActive
	out = merge(env(), []model.Report{{Agent: model.Codex, Found: true, Grants: []model.Grant{g}}}, &store.Observations{Grants: map[string]*store.Seen{}})
	if !out[0].HasFlag(model.FlagDeadPath) {
		t.Errorf("flags = %v, want dead-path for an active grant with a missing folder", out[0].Flags)
	}
}

func TestStoreHoldsNoCredential(t *testing.T) {
	secret := "Bash(curl -H 'Authorization: Bearer abcdefghij0123456789' https://example.com/x)"
	g := active("claude-code|rule|/f/settings.json|"+secret, secret)
	g.Agent, g.Tool = model.ClaudeCode, "Bash"
	obs := &store.Observations{Grants: map[string]*store.Seen{}}
	out := merge(env(), []model.Report{{Agent: model.ClaudeCode, Found: true, Grants: []model.Grant{g}}}, obs)

	dir := t.TempDir()
	if err := obs.Save(dir); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "seen.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), "abcdefghij0123456789") {
		t.Errorf("seen.json holds the credential:\n%s", saved)
	}
	if strings.Contains(out[0].Key, "abcdefghij0123456789") {
		t.Errorf("key holds the credential: %s", out[0].Key)
	}
	// The rule text itself stays whole: revoke needs it to find the rule.
	if out[0].Value != secret {
		t.Errorf("value = %q", out[0].Value)
	}
	if !out[0].HasFlag(model.FlagSecret) {
		t.Errorf("flags = %v", out[0].Flags)
	}
}

func TestUnreadPrefixesAreNotReportedGone(t *testing.T) {
	obs := &store.Observations{
		Runs: []time.Time{day("2026-09-01"), day("2026-09-10")},
		Grants: map[string]*store.Seen{
			"claude-code|trust|/work/x":       {Agent: model.ClaudeCode, Kind: model.KindTrust, Value: "/work/x", First: day("2026-09-01"), Last: day("2026-09-01")},
			"claude-code|rule|f|Bash(ls:*)":   {Agent: model.ClaudeCode, Kind: model.KindRule, Value: "Bash(ls:*)", First: day("2026-09-01"), Last: day("2026-09-01")},
			"claude-code|rule|g.json#Bash(a)": {Agent: model.ClaudeCode, Kind: model.KindRule, Value: "Bash(a)", First: day("2026-09-01"), Last: day("2026-09-01")},
		},
	}
	e := env()
	e.Now = day("2026-09-10")
	reports := []model.Report{{
		Agent: model.ClaudeCode, Found: true,
		Unread: []string{"claude-code|trust|", "claude-code|rule|g.json#"},
	}}
	out := merge(e, reports, obs)
	// Only the rule from a file that was read counts as removed.
	if len(out) != 1 || out[0].Value != "Bash(ls:*)" || out[0].Status != model.StatusGone {
		t.Fatalf("grants = %+v, want only the rule from the readable file as gone", out)
	}
}

func TestCollectRecoversAdapterPanic(t *testing.T) {
	old := adapters
	t.Cleanup(func() { adapters = old })
	adapters = []struct {
		agent model.Agent
		name  string
		run   func(model.Env, scan.Options) model.Report
	}{{model.ClaudeCode, "Claude Code", func(model.Env, scan.Options) model.Report { panic("boom") }}}

	reports := collect(env(), scan.Options{})
	if len(reports) != 1 || len(reports[0].Notes) != 1 || reports[0].Notes[0].Level != "warn" {
		t.Fatalf("reports = %+v", reports)
	}
	obs := &store.Observations{
		Runs: []time.Time{day("2026-09-01")},
		Grants: map[string]*store.Seen{
			"claude-code|trust|/work/x": {Agent: model.ClaudeCode, Kind: model.KindTrust, Value: "/work/x", First: day("2026-09-01"), Last: day("2026-09-01")},
		},
	}
	e := env()
	e.Now = day("2026-09-10")
	if out := merge(e, reports, obs); len(out) != 0 {
		t.Errorf("a crashed adapter made %d grants appear removed: %+v", len(out), out)
	}
}

func TestAssignIDsKeepsCredentialOnlyDifferencesApart(t *testing.T) {
	// Redaction gives both rules the same key; their raw values differ.
	gs := []model.Grant{
		{Key: "claude-code|rule|f|Bash(curl -H x:[redacted])", Value: "Bash(curl -H x:tokenone)"},
		{Key: "claude-code|rule|f|Bash(curl -H x:[redacted])", Value: "Bash(curl -H x:tokentwo)"},
		{Key: "other", Value: "v"},
	}
	assignIDs(gs, hexOf)
	if gs[0].ID == gs[1].ID {
		t.Errorf("ids are equal: %q", gs[0].ID)
	}
	if gs[2].ID != model.MakeID("other") {
		t.Errorf("an unrelated grant changed its id: %q", gs[2].ID)
	}
}

func TestRunTakesTheHistoryLock(t *testing.T) {
	env := codexHome(t, []string{"alpha"}, nil)
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := fsx.Lock(filepath.Join(env.StateDir, "seen.lock"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		Run(env, scan.Options{})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Run did not wait for the history lock")
	case <-time.After(300 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not finish after the lock was released")
	}
}
