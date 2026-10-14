package match

import (
	"strings"
	"testing"
	"time"
)

// Substitutions must not make Commands quadratic: an unclosed "$(" or a deep nest is
// the input a hostile transcript could hold.
func TestCommandsStaysFastOnHostileSubstitutions(t *testing.T) {
	const n = 32 * 1024 // 64 KB of "$("
	inputs := map[string]string{
		"unclosed":         strings.Repeat("$(", n),
		"unclosed in word": "echo " + strings.Repeat("$(a ", n),
		"nested closed":    strings.Repeat("$(", n) + strings.Repeat(")", n),
		"nested with text": strings.Repeat("$(echo ", n/2) + strings.Repeat(")", n/2),
		"many closed":      strings.Repeat("$(a)", n),
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			Commands(in)
			if d := time.Since(start); d > 500*time.Millisecond {
				t.Errorf("Commands took %v on %d bytes", d, len(in))
			}
		})
	}
}

func TestCommandsListsSubstitutionsOnlyToALimitedDepth(t *testing.T) {
	flat := func(in string) string {
		var parts []string
		for _, c := range Commands(in) {
			parts = append(parts, strings.Join(c, " "))
		}
		return strings.Join(parts, " | ")
	}
	// Three levels are listed, the fourth stays inside its word.
	got := flat("echo $(a $(b $(c $(d))))")
	for _, want := range []string{"a $(b", "b $(c", "c $(d)"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not list %q", got, want)
		}
	}
	if strings.Contains(got, " | d") || strings.HasSuffix(got, "| d") {
		t.Errorf("%q lists the fourth level", got)
	}
	// An unclosed substitution is one word, not a list of guesses.
	if got := flat("echo $(rm -rf x"); got != "echo $(rm -rf x" {
		t.Errorf("unclosed = %q", got)
	}
}
