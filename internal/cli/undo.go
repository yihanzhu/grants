package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/edit"
)

func (a *app) cmdUndo(args []string) int {
	var (
		g     globals
		force bool
	)
	fs := flag.NewFlagSet("undo", flag.ContinueOnError)
	g.register(fs)
	fs.BoolVar(&force, "force", false, "")
	rest, code, done := a.parse("undo", usages["undo"], fs, &g, args)
	if done {
		return code
	}
	if len(rest) > 0 {
		fmt.Fprintf(a.stderr, "grants undo: unexpected argument %q\n", rest[0])
		return exitUsage
	}
	env, err := core.EnvFromOS(0)
	if err != nil {
		return a.fail("%v", err)
	}
	batch, err := edit.Undo(env.StateDir, env.Now, force)
	switch {
	case errors.Is(err, edit.ErrNothingToUndo):
		return a.fail("nothing to undo. grants has not changed any file, or the last change is already undone.")
	case errors.Is(err, edit.ErrChanged):
		return a.fail("%s\nNothing was restored. Run grants undo --force to overwrite the changes anyway.", trimSentinel(err, edit.ErrChanged))
	case err != nil:
		return a.fail("%v", err)
	}

	fmt.Fprintf(a.stdout, "Restored %s from the revoke of %s:\n", plural(len(batch.Files), "file", "files"), fmtDateTime(batch.Time))
	for _, f := range batch.Files {
		fmt.Fprintf(a.stdout, "  %s\n", tilde(f.File, env.Home))
		for _, s := range strings.Split(f.Summary, "\n") {
			if s != "" {
				fmt.Fprintf(a.stdout, "    %s\n", a.st.dim("undone: "+tildeText(s, env.Home)))
			}
		}
	}
	return exitOK
}
