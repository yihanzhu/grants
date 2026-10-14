// Package timeline dates a grant from point-in-time observations of whether it was
// present: config snapshots, backups, session records and the live config file.
package timeline

import (
	"sort"
	"time"

	"github.com/yihanzhu/grants/internal/model"
)

// Obs is one observation of a grant at a moment.
type Obs struct {
	T       time.Time
	Present bool
	Approx  bool   // T is an estimate (e.g. the first session in a folder)
	Source  string // plain words for display, e.g. "Codex session snapshot"
	Detail  string // optional, short and redacted
	File    string // optional, file the observation came from
}

// Result is what the observations say about one grant.
type Result struct {
	Granted   model.Window
	LastSeen  time.Time    // latest observation where it was present
	RemovedAt model.Window // set when the latest observation says absent after it was present
	Evidence  []model.Evidence
}

// Date computes the grant window and removal from observations. It ignores
// observations with a zero time. The grant was created after the latest absence that
// precedes its first presence, and at or before that first presence.
func Date(obs []Obs) Result {
	var list []Obs
	for _, o := range obs {
		if !o.T.IsZero() {
			list = append(list, o)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].T.Before(list[j].T) })

	var r Result
	first := -1
	for i, o := range list {
		if o.Present {
			first = i
			break
		}
	}
	if first < 0 {
		return r
	}
	p := list[first]
	r.Granted = model.Window{Before: p.T, Approx: p.Approx, Source: p.Source}
	for i := first - 1; i >= 0; i-- {
		if !list[i].Present {
			r.Granted.After = list[i].T
			break
		}
	}
	last := first
	for i := first; i < len(list); i++ {
		if list[i].Present {
			last = i
		}
	}
	r.LastSeen = list[last].T
	if last+1 < len(list) {
		gone := list[last+1]
		r.RemovedAt = model.Window{After: list[last].T, Before: gone.T, Approx: gone.Approx, Source: gone.Source}
	}

	// Keep evidence short: transitions plus the first and last observation.
	for i, o := range list {
		changed := i == 0 || list[i-1].Present != o.Present
		if changed || i == len(list)-1 || i == first {
			what := "absent"
			if o.Present {
				what = "present"
			}
			src := o.File
			r.Evidence = append(r.Evidence, model.Evidence{Time: o.T, What: what, Detail: joinDetail(o.Source, o.Detail), Source: src})
		}
	}
	return r
}

func joinDetail(source, detail string) string {
	if detail == "" {
		return source
	}
	if source == "" {
		return detail
	}
	return source + ": " + detail
}
