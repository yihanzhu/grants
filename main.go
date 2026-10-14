// Command grants lists and revokes the permissions you gave AI coding agents.
package main

import (
	"os"

	"github.com/yihanzhu/grants/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
