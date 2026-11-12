// Package cli implements the command-line interface.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/drau6/keydra/internal/buildinfo"
	"github.com/drau6/keydra/internal/report"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1 // findings at or above --fail-on
	ExitError    = 2 // usage or runtime error
)

const usage = `keydra — find what your vibe-coded app is leaking.

Usage:
  keydra scan <url> [flags]    scan a deployed web app
  keydra scan --repo <dir>     scan local source before you deploy
  keydra scan --list <file>    scan every URL in the file, one per line (max 50)
  keydra rules                 list every check (--markdown for docs)
  keydra version               print version

Shortcut:
  keydra <url>                 same as 'keydra scan <url>'

Run 'keydra scan -h' for scan flags.
`

// Run executes the CLI and returns a process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printTitle(stderr)
		fmt.Fprint(stderr, usage)
		return ExitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return runScan(ctx, rest, stdout, stderr)
	case "rules":
		return runRules(rest, stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "keydra %s\n", buildinfo.Version)
		return ExitOK
	case "help", "-h", "--help":
		printTitle(stdout)
		fmt.Fprint(stdout, usage)
		return ExitOK
	default:
		if strings.HasPrefix(cmd, "-") || !looksLikeTarget(cmd) {
			// Unknown flag, or a bare word with no scheme and no dot
			// ("keydra asd") that is a mistyped command rather than a
			// target: report it instead of attempting a doomed DNS lookup.
			printTitle(stderr)
			fmt.Fprintf(stderr, "unknown command or flag %q\n\n%s", cmd, usage)
			return ExitError
		}
		return runScan(ctx, args, stdout, stderr) // bare URL shortcut
	}
}

// looksLikeTarget reports whether a bare argument is plausibly a URL or
// hostname to scan: an explicit scheme, something with a dot (example.com,
// 127.0.0.1), or localhost (with or without a port). Anything else is treated
// as a mistyped command.
func looksLikeTarget(s string) bool {
	if strings.Contains(s, "://") || strings.Contains(s, ".") {
		return true
	}
	host := s
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i] // strip :port
	}
	return host == "localhost"
}

// printTitle prints the banner (ASCII art when the terminal is wide enough,
// the compact one-line title otherwise) plus the permission notice.
func printTitle(w io.Writer) {
	color := useColor("auto", w)
	st := report.Style{Color: color, Version: buildinfo.Version, Art: showArt(color, w)}
	report.Banner(w, st)
}

// parseInterspersed parses flags that may appear before or after positional
// arguments, e.g. "scan example.com --json".
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// isTerminal reports whether w is an interactive terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// useColor decides whether to emit ANSI colors. NO_COLOR always wins;
// FORCE_COLOR enables colors even when piped (e.g. into `less -R`).
func useColor(mode string, w io.Writer) bool {
	switch mode {
	case "never":
		return false
	case "always":
		return true
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	return os.Getenv("TERM") != "dumb" && isTerminal(w)
}

// showArt reports whether the large banner fits and is wanted: only on an
// interactive terminal (or when colors are forced) that is wide enough.
func showArt(color bool, w io.Writer) bool {
	if !color && !isTerminal(w) {
		return false
	}
	if cols, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && cols < report.ArtWidth()+4 {
		return false
	}
	return true
}
