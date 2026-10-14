package cli

import (
	"io"
	"os"
	"strconv"
)

// isTerminal reports whether w is a terminal.
func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	return ok && fdIsTerminal(f.Fd())
}

// termWidth returns the width of the terminal behind w, else $COLUMNS, else 120.
func termWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if n := fdWidth(f.Fd()); n > 0 {
			return n
		}
	}
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		return n
	}
	return 120
}
