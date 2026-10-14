// Command grants lists and revokes the permissions you gave AI coding agents.
package main

import (
	"os"
	"runtime/debug"

	"github.com/yihanzhu/grants/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	cli.Version = version
	// go install builds without ldflags; the module version is in the build info.
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			cli.Version = bi.Main.Version
		}
	}
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
