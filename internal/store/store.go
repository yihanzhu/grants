// Package store keeps what grants itself saw on each run. It dates grants that the
// agents' own history cannot date, and shows grants that disappeared between runs.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/timeline"
)

// maxRuns is how many run times are kept.
const maxRuns = 500

const fileName = "seen.json"

// Source labels observations made by grants itself.
const Source = "seen by grants"

// DefaultStateDir returns $GRANTS_STATE_DIR, else $XDG_STATE_HOME/grants, else
// <home>/.local/state/grants.
func DefaultStateDir(home string) string {
	if d := os.Getenv("GRANTS_STATE_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "grants")
	}
	return filepath.Join(home, ".local", "state", "grants")
}

// Seen is one grant as grants saw it.
type Seen struct {
	Agent   model.Agent `json:"agent"`
	Kind    model.Kind  `json:"kind"`
	Value   string      `json:"value"`
	Project string      `json:"project,omitempty"`
	First   time.Time   `json:"first"`
	Last    time.Time   `json:"last"`
}

// Observations is the saved record of every run.
type Observations struct {
	Runs   []time.Time      `json:"runs"`
	Grants map[string]*Seen `json:"grants"` // by model.Grant.Key
}

// Load reads seen.json from stateDir. A missing file gives empty observations.
func Load(stateDir string) (*Observations, error) {
	o := &Observations{Grants: map[string]*Seen{}}
	data, err := os.ReadFile(filepath.Join(stateDir, fileName))
	if errors.Is(err, fs.ErrNotExist) {
		return o, nil
	}
	if err != nil {
		return o, fmt.Errorf("store: read %s: %w", fileName, err)
	}
	if err := json.Unmarshal(data, o); err != nil {
		return &Observations{Grants: map[string]*Seen{}}, fmt.Errorf("store: parse %s: %w", fileName, err)
	}
	if o.Grants == nil {
		o.Grants = map[string]*Seen{}
	}
	return o, nil
}

// Save writes seen.json atomically with mode 0600, creating stateDir (0700).
func (o *Observations) Save(stateDir string) error {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("store: create state folder: %w", err)
	}
	tmp, err := os.CreateTemp(stateDir, fileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("store: write %s: %w", fileName, err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write %s: %w", fileName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write %s: %w", fileName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: write %s: %w", fileName, err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(stateDir, fileName)); err != nil {
		return fmt.Errorf("store: write %s: %w", fileName, err)
	}
	return nil
}

// Record notes that active grants were present at now, and logs the run. Only the
// last 500 runs are kept.
func (o *Observations) Record(now time.Time, active []model.Grant) {
	if o.Grants == nil {
		o.Grants = map[string]*Seen{}
	}
	for _, g := range active {
		s := o.Grants[g.Key]
		if s == nil {
			s = &Seen{First: now}
			o.Grants[g.Key] = s
		}
		s.Agent, s.Kind, s.Value, s.Project = g.Agent, g.Kind, g.Value, g.Project
		if now.Before(s.First) {
			s.First = now
		}
		if now.After(s.Last) {
			s.Last = now
		}
	}
	o.Runs = append(o.Runs, now)
	if n := len(o.Runs); n > maxRuns {
		o.Runs = append([]time.Time(nil), o.Runs[n-maxRuns:]...)
	}
}

// Obs turns what grants saw into timeline observations: present at the first and the
// last sighting, absent at the first later run that did not see it. An unknown key
// gives nil.
func (o *Observations) Obs(key string) []timeline.Obs {
	s := o.Grants[key]
	if s == nil {
		return nil
	}
	obs := []timeline.Obs{{T: s.First, Present: true, Source: Source}}
	if s.Last.After(s.First) {
		obs = append(obs, timeline.Obs{T: s.Last, Present: true, Source: Source})
	}
	// Runs are appended in time order, but a clock change could break that.
	var next time.Time
	for _, r := range o.Runs {
		if r.After(s.Last) && (next.IsZero() || r.Before(next)) {
			next = r
		}
	}
	if !next.IsZero() {
		obs = append(obs, timeline.Obs{T: next, Present: false, Source: Source})
	}
	return obs
}

// Missing returns grants seen on an earlier run that are not in active, sorted by
// agent, kind and value.
func (o *Observations) Missing(active map[string]bool) []*Seen {
	var out []*Seen
	for k, s := range o.Grants {
		if !active[k] {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Value < b.Value
	})
	return out
}
