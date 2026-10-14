package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONLeavesOutUnknownTimes(t *testing.T) {
	day := time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
	g := Grant{ID: "abc1234", Agent: Codex, Kind: KindRule, Value: "git push", Status: StatusActive}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "0001-01-01") {
		t.Errorf("unknown times written: %s", b)
	}
	for _, key := range []string{`"last_seen"`, `"removed"`, `"after"`, `"before"`, `"last"`, `"since"`} {
		if strings.Contains(string(b), key) {
			t.Errorf("%s should be left out: %s", key, b)
		}
	}

	g.Granted = Window{Before: day, Approx: true, Source: "first session"}
	g.Usage = Usage{Known: true, Count: 2, Last: day, Since: day}
	g.LastSeen = day
	g.Removed = Window{After: day, Before: day.Add(time.Hour)}
	b, err = json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var back Grant
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Granted.Before.Equal(day) || !back.Granted.Approx || back.Usage.Count != 2 || !back.Usage.Last.Equal(day) ||
		!back.LastSeen.Equal(day) || !back.Removed.After.Equal(day) || back.ID != "abc1234" || back.Value != "git push" {
		t.Errorf("round trip lost data: %+v\n%s", back, b)
	}
}

func TestMakeID(t *testing.T) {
	if got := MakeID("x"); len(got) != 7 || got != MakeID("x") || got == MakeID("y") {
		t.Errorf("MakeID = %q", got)
	}
}
