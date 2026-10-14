package claude

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/scan"
)

func TestReadListsOnlyFilesThatWereParsed(t *testing.T) {
	env := bareEnv(t)
	proj := filepath.Join(env.Home, "work", "app")
	user := filepath.Join(env.ClaudeDir, "settings.json")
	local := filepath.Join(env.ClaudeDir, "settings.local.json") // not valid JSON
	projSettings := filepath.Join(proj, ".claude", "settings.json")
	projLocal := filepath.Join(proj, ".claude", "settings.local.json") // missing
	writeFile(t, user, `{"permissions":{"allow":["Bash(ls:*)"]}}`)
	writeFile(t, local, `{"permissions":`)
	writeFile(t, projSettings, `{}`)
	writeFile(t, env.ClaudeJSON, `{"projects":{"`+proj+`":{"hasTrustDialogAccepted":true}}}`)

	rep := Collect(env, scan.Options{NoCache: true})
	for _, want := range []string{user, projSettings, env.ClaudeJSON} {
		if !slices.Contains(rep.Read, want) {
			t.Errorf("Read = %v, want %s", rep.Read, want)
		}
	}
	for _, not := range []string{local, projLocal} {
		if slices.Contains(rep.Read, not) {
			t.Errorf("Read = %v lists %s, which was not parsed", rep.Read, not)
		}
	}
}

func TestReadSkipsUnreadableFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	env := bareEnv(t)
	user := filepath.Join(env.ClaudeDir, "settings.json")
	writeFile(t, user, `{"permissions":{"allow":["Bash(ls:*)"]}}`)
	if err := os.Chmod(user, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(user, 0o600) })
	rep := Collect(env, scan.Options{NoCache: true})
	if slices.Contains(rep.Read, user) {
		t.Errorf("Read = %v lists an unreadable file", rep.Read)
	}
}

func TestOversizedFilesSayTooLarge(t *testing.T) {
	env := bareEnv(t)
	user := filepath.Join(env.ClaudeDir, "settings.json")
	writeFile(t, user, "")
	// Sparse files: no disk is used and nothing is read, because the size check comes first.
	if err := os.Truncate(user, maxReadSize+1); err != nil {
		t.Fatal(err)
	}
	writeFile(t, env.ClaudeJSON, "")
	if err := os.Truncate(env.ClaudeJSON, maxClaudeJSONSize+1); err != nil {
		t.Fatal(err)
	}
	rep := Collect(env, scan.Options{NoCache: true})
	var text string
	for _, n := range rep.Notes {
		text += n.Text + "\n"
	}
	for _, p := range []string{user, env.ClaudeJSON} {
		if !strings.Contains(text, p+" is too large to read") {
			t.Errorf("notes = %q, want a too-large note for %s", text, p)
		}
	}
	if len(rep.Read) != 0 {
		t.Errorf("Read = %v", rep.Read)
	}

	// A ~/.claude.json above the old 64 MiB cap but below the new one is read.
	writeFile(t, env.ClaudeJSON, `{"projects":{}}`)
	if err := os.Truncate(env.ClaudeJSON, maxReadSize+1); err == nil {
		// The padding is NUL bytes, so the JSON no longer parses; the note must say so, not "too large".
		rep = Collect(env, scan.Options{NoCache: true})
		for _, n := range rep.Notes {
			if strings.Contains(n.Text, env.ClaudeJSON+" is too large") {
				t.Errorf("a %d byte ~/.claude.json is under the cap: %q", maxReadSize+1, n.Text)
			}
		}
	}
}

func TestSpecificityRanksFolderRules(t *testing.T) {
	base := match.RuleBase{Home: "/home/u", Settings: "/home/u/.claude", Project: "/work/app"}
	rank := func(rule string) int { return specificity(rule, base) }

	// "Read(**)" is the whole project and "Read(//**)" the whole disk.
	if got, want := rank("Read(**)"), rank("Read(//work/app/**)"); got == 0 || got != want {
		t.Errorf("Read(**) = %d, want the rank of the project folder %d", got, want)
	}
	for _, narrower := range []string{"Read(//home/**)", "Read(~/**)", "Read(//work/app/src/**)", "Read(src/**)", "Read(//home/u/notes.txt)"} {
		if !(rank("Read(//**)") < rank(narrower)) {
			t.Errorf("Read(//**) = %d must be broader than %s = %d", rank("Read(//**)"), narrower, rank(narrower))
		}
	}
	if !(rank("Read(**)") < rank("Read(src/**)") && rank("Read(src/**)") < rank("Read(src/a.go)")) {
		t.Errorf("project %d, src %d, file %d: want narrower to rank higher", rank("Read(**)"), rank("Read(src/**)"), rank("Read(src/a.go)"))
	}
	for rule, want := range map[string]int{
		"Read(//**)": 1, "Read(~/**)": len("/home/u"), "Read(/**)": len("/home/u/.claude"),
		"Read": 0, "Read(*)": 0, "Edit(//tmp/x/**)": len("/tmp/x"), "Bash(npm test:*)": 2,
	} {
		if got := rank(rule); got != want {
			t.Errorf("specificity(%q) = %d, want %d", rule, got, want)
		}
	}
	if got := rank("Read(notes.txt)"); got != exactRank {
		t.Errorf("a path without wildcard = %d, want exactRank", got)
	}
}
