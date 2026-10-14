package risk

import (
	"net/url"
	"path"
	"strings"

	"github.com/yihanzhu/grants/internal/model"
)

// verdict is the highest level seen so far and the reasons at that level.
type verdict struct {
	level   model.Level
	reasons []string
	set     bool
}

// add raises the level when lvl is higher, and keeps one reason list for the top level.
func (v *verdict) add(lvl model.Level, reason string) {
	switch {
	case !v.set || lvl.Rank() > v.level.Rank():
		v.level, v.reasons, v.set = lvl, []string{reason}, true
	case lvl == v.level && !contains(v.reasons, reason):
		v.reasons = append(v.reasons, reason)
	}
}

func (v *verdict) result() model.Risk {
	if !v.set {
		return model.Risk{Level: model.RiskLow}
	}
	return model.Risk{Level: v.level, Reasons: v.reasons}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var (
	shellNames = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "fish": true}
	// inlineFlags maps an interpreter to the flags that run code given on the command line.
	inlineFlags = map[string][]string{
		"python": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "ruby": {"-e"},
		"perl": {"-e", "-E"}, "php": {"-r"}, "deno": {"eval"}, "bun": {"-e", "--eval"},
	}
	// bare programs have many subcommands; a rule that names only the program allows all of them.
	bareHigh = map[string]bool{"git": true, "npm": true, "npx": true, "pnpm": true, "yarn": true,
		"uv": true, "uvx": true, "pip": true, "pip3": true, "brew": true, "cargo": true, "go": true,
		"make": true, "python": true, "python3": true, "node": true, "terraform": true}
	alwaysHigh = map[string]string{
		"sudo": "runs commands as administrator", "doas": "runs commands as administrator",
		"su": "switches user", "rm": "deletes files", "shred": "deletes files",
		"osascript": "runs scripts that control other apps", "eval": "runs text as code",
		"exec": "replaces the shell with any program", "xargs": "runs other commands on input",
		"ssh": "opens a remote shell", "docker": "controls containers", "podman": "controls containers",
		"kubectl": "controls a cluster", "dd": "writes raw disk data", "kill": "stops processes",
		"pkill": "stops processes", "killall": "stops processes", "launchctl": "controls system services",
		"systemctl": "controls system services", "crontab": "changes scheduled jobs",
		"security": "reads or changes keychains", "diskutil": "changes disks",
		"shutdown": "shuts down the machine", "reboot": "restarts the machine",
	}
	readOnly = map[string]bool{"ls": true, "cat": true, "head": true, "tail": true, "wc": true,
		"grep": true, "rg": true, "pwd": true, "which": true, "echo": true, "jq": true, "stat": true,
		"date": true, "file": true, "cd": true, "true": true, "false": true, ":": true, "[": true,
		"[[": true, "test": true, "read": true, "printf": true, "sort": true, "uniq": true,
		"tree": true, "du": true, "df": true, "whoami": true, "uname": true, "basename": true,
		"dirname": true, "realpath": true, "readlink": true, "id": true, "diff": true, "sleep": true,
		"less": true, "more": true, "hostname": true, "exit": true, "return": true, "wait": true,
	}
	changesState = map[string]bool{"mv": true, "open": true, "mkdir": true, "touch": true,
		"xcodebuild": true, "source": true, ".": true, "export": true, "unset": true,
	}
)

// classifyCommands returns the highest level over the simple commands of one rule.
func classifyCommands(cmds [][]string, v *verdict) {
	for _, c := range cmds {
		lvl, why := classify(c)
		v.add(lvl, why)
	}
}

// classify rates one simple command (tokens, program first).
func classify(cmd []string) (model.Level, string) {
	if len(cmd) == 0 {
		return model.RiskLow, "empty command"
	}
	prog := cmd[0]
	if strings.Contains(prog, "/") {
		prog = path.Base(prog)
	}
	prog = strings.ToLower(prog)
	args := cmd[1:]

	if why, ok := alwaysHigh[prog]; ok {
		return model.RiskHigh, why
	}
	switch {
	case shellNames[prog]:
		return classifyShell(args)
	case strings.HasPrefix(prog, "python"):
		return classifyInterpreter("python", args)
	case prog == "node" || prog == "ruby" || prog == "perl" || prog == "php" || prog == "deno" || prog == "bun":
		return classifyInterpreter(prog, args)
	}
	switch prog {
	case "git":
		return classifyGit(args)
	case "npm", "pnpm", "yarn":
		return classifyNode(prog, args)
	case "npx", "uvx":
		if len(args) == 0 {
			return model.RiskHigh, "any subcommand of " + prog
		}
		return model.RiskMedium, "runs a downloaded package"
	case "uv", "pip", "pip3", "brew", "make":
		if len(args) == 0 {
			return model.RiskHigh, "any subcommand of " + prog
		}
		return model.RiskMedium, "runs project scripts or changes installed software"
	case "cargo":
		return classifyTool(prog, args, "test")
	case "go":
		return classifyTool(prog, args, "test", "build", "vet")
	case "swift":
		return classifyTool(prog, args, "test", "build")
	case "terraform":
		if len(args) == 0 || args[0] == "apply" || args[0] == "destroy" {
			return model.RiskHigh, "changes cloud infrastructure"
		}
		return model.RiskMedium, "runs terraform"
	case "curl", "wget":
		return classifyDownload(prog, args)
	case "scp", "rsync":
		return classifyCopy(prog, args)
	case "gh":
		return classifyGH(args)
	case "chmod", "chown", "chgrp":
		if hasFlag(args, "R", "recursive") {
			return model.RiskHigh, "changes permissions of a whole folder tree"
		}
		return model.RiskMedium, "changes permissions"
	case "find":
		for _, a := range args {
			switch a {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete":
				return model.RiskHigh, "find that runs commands or deletes files"
			}
		}
		return model.RiskLow, "read-only command"
	case "cp":
		return model.RiskMedium, "copies files"
	}
	if strings.HasPrefix(prog, "mkfs") {
		return model.RiskHigh, "formats a disk"
	}
	if readOnly[prog] {
		return model.RiskLow, "read-only command"
	}
	if changesState[prog] {
		return model.RiskMedium, "changes files or state"
	}
	return model.RiskMedium, "unrecognized command"
}

func classifyShell(args []string) (model.Level, string) {
	if len(args) == 0 {
		return model.RiskHigh, "any shell script"
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "c") {
			return model.RiskHigh, "runs inline code through a shell"
		}
	}
	return model.RiskMedium, "runs a script"
}

func classifyInterpreter(name string, args []string) (model.Level, string) {
	if len(args) == 0 {
		return model.RiskHigh, "any " + name + " code"
	}
	for _, a := range args {
		for _, f := range inlineFlags[name] {
			if a == f {
				return model.RiskHigh, "runs inline " + name + " code"
			}
		}
		if !strings.HasPrefix(a, "-") {
			break // from here on the arguments belong to the script
		}
	}
	return model.RiskMedium, "runs a " + name + " script"
}

// firstWord returns the first argument that is not an option, skipping the options
// git and similar tools put before the subcommand (-C dir, -c key=value).
func firstWord(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, args[i+1:]
	}
	return "", nil
}

func classifyGit(args []string) (model.Level, string) {
	sub, rest := firstWord(args)
	switch sub {
	case "":
		return model.RiskHigh, "any git subcommand"
	case "push":
		return model.RiskHigh, "pushes code to a remote"
	case "clean":
		return model.RiskHigh, "deletes untracked files"
	case "reset":
		if hasFlag(rest, "", "hard") {
			return model.RiskHigh, "discards local changes"
		}
		return model.RiskMedium, "changes git state"
	case "commit", "merge", "rebase", "checkout", "switch", "stash", "tag", "add":
		return model.RiskMedium, "changes git state"
	case "status", "log", "diff", "show", "branch", "rev-parse":
		return model.RiskLow, "read-only command"
	}
	return model.RiskMedium, "unrecognized command"
}

func classifyNode(prog string, args []string) (model.Level, string) {
	sub, _ := firstWord(args)
	switch sub {
	case "":
		return model.RiskHigh, "any " + prog + " subcommand"
	case "publish":
		return model.RiskHigh, "publishes a package"
	}
	return model.RiskMedium, "runs project scripts or installs packages"
}

// classifyTool handles build tools with a few read-only or test subcommands.
func classifyTool(prog string, args []string, low ...string) (model.Level, string) {
	sub, _ := firstWord(args)
	if sub == "" {
		return model.RiskHigh, "any " + prog + " subcommand"
	}
	for _, l := range low {
		if sub == l {
			return model.RiskLow, "builds or tests without changing anything else"
		}
	}
	return model.RiskMedium, "runs project code or changes state"
}

// hasFlag reports whether args hold a short flag containing letter (-R, -rf) or the long flag.
func hasFlag(args []string, short, long string) bool {
	for _, a := range args {
		if a == "--"+long || a == "--"+long+"=true" {
			return true
		}
		if short != "" && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, short) {
			return true
		}
	}
	return false
}

func classifyDownload(prog string, args []string) (model.Level, string) {
	hosts := hostsIn(args)
	if len(hosts) == 0 {
		return model.RiskHigh, prog + " to any address can send data out"
	}
	for _, h := range hosts {
		if h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return model.RiskHigh, prog + " to a remote address can send data out"
		}
	}
	return model.RiskLow, prog + " to this machine only"
}

// hostsIn finds the hosts of the URLs in args. Arguments with a scheme win; without
// one, every non-option argument counts, which errs toward remote.
func hostsIn(args []string) []string {
	var withScheme, plain []string
	for _, a := range args {
		switch {
		case strings.Contains(a, "://"):
			withScheme = append(withScheme, hostOf(a))
		case !strings.HasPrefix(a, "-") && a != "":
			plain = append(plain, hostOf(a))
		}
	}
	if len(withScheme) > 0 {
		return withScheme
	}
	return plain
}

func hostOf(s string) string {
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return strings.ToLower(s)
	}
	return strings.ToLower(u.Hostname())
}

func classifyCopy(prog string, args []string) (model.Level, string) {
	n := 0
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		n++
		if strings.Contains(a, "@") || strings.Contains(a, "://") ||
			(strings.Contains(a, ":") && !strings.HasPrefix(a, "/") && !strings.HasPrefix(a, ".")) {
			return model.RiskHigh, prog + " to a remote machine"
		}
	}
	if n == 0 {
		return model.RiskHigh, prog + " to any remote machine"
	}
	return model.RiskMedium, "copies files"
}

func classifyGH(args []string) (model.Level, string) {
	sub, rest := firstWord(args)
	act, _ := firstWord(rest)
	switch sub {
	case "pr", "issue", "repo", "run", "release", "workflow":
		switch act {
		case "view", "list", "status", "diff", "checks":
			return model.RiskMedium, "reads GitHub data with your login"
		}
	case "version", "help":
		return model.RiskLow, "read-only command"
	}
	return model.RiskHigh, "acts on GitHub with your login"
}
