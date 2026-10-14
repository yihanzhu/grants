package claude

import (
	"path/filepath"
	"sort"
	"time"

	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/timeline"
)

// dateGrant turns observations into a grant window. For a grant that is active now, only
// the latest stretch of presence counts: when it was seen absent after an earlier
// presence, it was removed and added again.
func dateGrant(obs []timeline.Obs, active bool) timeline.Result {
	if active {
		obs = currentStretch(obs)
	}
	r := timeline.Date(obs)
	if active && r.Granted.Before.IsZero() {
		// Seen absent and never seen present after that: only a lower bound is known.
		if a, ok := lastAbsent(obs); ok {
			r.Granted = modelWindow(a)
			r.Evidence = append(r.Evidence, evidenceOf(a, "absent"))
		}
	}
	return r
}

// currentStretch drops every observation before the latest absence.
func currentStretch(obs []timeline.Obs) []timeline.Obs {
	list := sortedObs(obs)
	for i := len(list) - 1; i >= 0; i-- {
		if !list[i].Present {
			return list[i:]
		}
	}
	return list
}

func lastAbsent(obs []timeline.Obs) (timeline.Obs, bool) {
	list := sortedObs(obs)
	for i := len(list) - 1; i >= 0; i-- {
		if !list[i].Present {
			return list[i], true
		}
	}
	return timeline.Obs{}, false
}

func sortedObs(obs []timeline.Obs) []timeline.Obs {
	list := make([]timeline.Obs, 0, len(obs))
	for _, o := range obs {
		if !o.T.IsZero() {
			list = append(list, o)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].T.Before(list[j].T) })
	return list
}

// earliestSession returns the earliest time any session shows a folder in use. A
// session in a subfolder that is trusted on its own does not count: it shows that
// subfolder in use, and trust in dir does not follow from it.
func earliestSession(sessions []session, dir string, trusted map[string]bool) (time.Time, bool) {
	var first time.Time
	for _, s := range sessions {
		if s.T.IsZero() || !fsx.Within(s.Dir, dir) || trustedBetween(s.Dir, dir, trusted) {
			continue
		}
		if first.IsZero() || s.T.Before(first) {
			first = s.T
		}
	}
	return first, !first.IsZero()
}

// trustedBetween reports whether a trusted folder lies below dir and above or at p.
func trustedBetween(p, dir string, trusted map[string]bool) bool {
	dir = filepath.Clean(dir)
	for q := filepath.Clean(p); q != dir; q = filepath.Dir(q) {
		if trusted[q] {
			return true
		}
		if q == filepath.Dir(q) {
			break
		}
	}
	return false
}

func modelWindow(o timeline.Obs) model.Window {
	return model.Window{After: o.T, Source: "last seen absent: " + o.Source}
}

func evidenceOf(o timeline.Obs, what string) model.Evidence {
	d := o.Source
	if o.Detail != "" {
		d += ": " + o.Detail
	}
	return model.Evidence{Time: o.T, What: what, Detail: d, Source: o.File}
}
