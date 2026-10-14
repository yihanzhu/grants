package cli

import "github.com/yihanzhu/grants/internal/model"

// style adds ANSI colors when on. Pad text before styling it: escape codes have no width.
type style struct{ on bool }

func (s style) wrap(code, t string) string {
	if !s.on || t == "" {
		return t
	}
	return "\x1b[" + code + "m" + t + "\x1b[0m"
}

func (s style) bold(t string) string   { return s.wrap("1", t) }
func (s style) dim(t string) string    { return s.wrap("2", t) }
func (s style) red(t string) string    { return s.wrap("31", t) }
func (s style) yellow(t string) string { return s.wrap("33", t) }
func (s style) green(t string) string  { return s.wrap("32", t) }

// level colors a risk word.
func (s style) level(l model.Level, t string) string {
	switch l {
	case model.RiskHigh:
		return s.red(t)
	case model.RiskMedium:
		return s.yellow(t)
	}
	return t
}
