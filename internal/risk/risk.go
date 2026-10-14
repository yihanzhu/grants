// Package risk rates how much a grant lets an agent do and flags grants that look stale.
package risk

import "github.com/yihanzhu/grants/internal/model"

// Assess sets g.Risk and adds the flags it can decide from the grant alone:
// FlagSecret, FlagOneOff and FlagDeadPath. exists reports whether a path exists.
//
// TODO(risk agent): implement.
func Assess(g *model.Grant, env model.Env, exists func(path string) bool) {
	g.Risk = model.Risk{Level: model.RiskLow}
}

// Redact masks credential-like substrings (bearer tokens, api keys, passwords).
//
// TODO(risk agent): implement.
func Redact(s string) string { return s }
