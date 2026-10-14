package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/timeline"
)

func g(key, val string) model.Grant {
	return model.Grant{Key: key, Agent: model.Codex, Kind: model.KindRule, Value: val, Project: "/work/app"}
}

var t0 = time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)

func TestDefaultStateDir(t *testing.T) {
	t.Setenv("GRANTS_STATE_DIR", "")
	t.Setenv("XDG_STATE_HOME", "")
	if got := DefaultStateDir("/home/u"); got != "/home/u/.local/state/grants" {
		t.Fatal(got)
	}
	t.Setenv("XDG_STATE_HOME", "/xdg")
	if got := DefaultStateDir("/home/u"); got != "/xdg/grants" {
		t.Fatal(got)
	}
	t.Setenv("GRANTS_STATE_DIR", "/custom")
	if got := DefaultStateDir("/home/u"); got != "/custom" {
		t.Fatal(got)
	}
}

func TestLoadMissingAndCorrupt(t *testing.T) {
	d := t.TempDir()
	o, err := Load(filepath.Join(d, "none"))
	if err != nil || o == nil || len(o.Grants) != 0 || len(o.Runs) != 0 {
		t.Fatalf("%v %v", o, err)
	}
	os.WriteFile(filepath.Join(d, "seen.json"), []byte("{nope"), 0o600)
	o, err = Load(d)
	if err == nil || o == nil || o.Grants == nil {
		t.Fatalf("corrupt file must error with usable empty value: %v %v", o, err)
	}
	os.WriteFile(filepath.Join(d, "seen.json"), []byte("{}"), 0o600)
	if o, err = Load(d); err != nil || o.Grants == nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	d := filepath.Join(t.TempDir(), "state")
	o, _ := Load(d)
	o.Record(t0, []model.Grant{g("k1", "npm test"), g("k2", "ls")})
	if err := o.Save(d); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(d, "seen.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	o2, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	s := o2.Grants["k1"]
	if s == nil || s.Value != "npm test" || s.Agent != model.Codex || s.Kind != model.KindRule || s.Project != "/work/app" || !s.First.Equal(t0) || !s.Last.Equal(t0) {
		t.Fatalf("%+v", s)
	}
	if len(o2.Runs) != 1 || !o2.Runs[0].Equal(t0) {
		t.Fatalf("%v", o2.Runs)
	}
	if m, _ := filepath.Glob(filepath.Join(d, "*.tmp")); len(m) != 0 {
		t.Fatal("temp files left", m)
	}
}

func TestRecordKeepsFirstAndCapsRuns(t *testing.T) {
	o := &Observations{}
	for i := range 520 {
		o.Record(t0.Add(time.Duration(i)*time.Hour), []model.Grant{g("k", "v")})
	}
	if len(o.Runs) != 500 {
		t.Fatalf("runs = %d", len(o.Runs))
	}
	if !o.Runs[0].Equal(t0.Add(20 * time.Hour)) {
		t.Fatalf("kept the wrong runs: %v", o.Runs[0])
	}
	s := o.Grants["k"]
	if !s.First.Equal(t0) || !s.Last.Equal(t0.Add(519*time.Hour)) {
		t.Fatalf("%+v", s)
	}
}

func TestObsAndTimeline(t *testing.T) {
	o := &Observations{}
	o.Record(t0, []model.Grant{g("a", "A"), g("b", "B")})
	o.Record(t0.Add(24*time.Hour), []model.Grant{g("a", "A"), g("b", "B")})
	o.Record(t0.Add(48*time.Hour), []model.Grant{g("a", "A")}) // b vanished here
	o.Record(t0.Add(72*time.Hour), []model.Grant{g("a", "A")})

	if o.Obs("nope") != nil {
		t.Fatal("unknown key must give nil")
	}
	obs := o.Obs("b")
	if len(obs) != 3 || !obs[0].Present || !obs[0].T.Equal(t0) || !obs[1].Present || !obs[1].T.Equal(t0.Add(24*time.Hour)) ||
		obs[2].Present || !obs[2].T.Equal(t0.Add(48*time.Hour)) || obs[0].Source != "seen by grants" {
		t.Fatalf("%+v", obs)
	}
	res := timeline.Date(obs)
	if !res.LastSeen.Equal(t0.Add(24*time.Hour)) || res.RemovedAt.Before.IsZero() {
		t.Fatalf("%+v", res)
	}
	// Still active: no absence after the last sighting.
	if obs := o.Obs("a"); len(obs) != 2 || !obs[1].Present || !obs[1].T.Equal(t0.Add(72*time.Hour)) {
		t.Fatalf("%+v", obs)
	}
	// Seen only once: a single present observation, plus absence at the next run.
	o.Record(t0.Add(96*time.Hour), []model.Grant{g("c", "C")})
	obs = o.Obs("c")
	if len(obs) != 1 || !obs[0].Present {
		t.Fatalf("%+v", obs)
	}
	obs = o.Obs("a")
	if len(obs) != 3 || obs[2].Present || !obs[2].T.Equal(t0.Add(96*time.Hour)) {
		t.Fatalf("%+v", obs)
	}
}
