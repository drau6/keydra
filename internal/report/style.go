package report

import (
	"fmt"

	"github.com/drau6/keydra/internal/model"
)

// Style controls ANSI coloring. With Color false every helper returns its
// input unchanged, so output stays clean when piped or logged.
type Style struct {
	Color   bool
	Version string
	Art     bool // print the large ASCII-art banner instead of a one-line title
}

// sgr wraps text in an ANSI SGR sequence.
func (s Style) sgr(code, text string) string {
	if !s.Color || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Style) bold(t string) string         { return s.sgr("1", t) }
func (s Style) dim(t string) string          { return s.sgr("2", t) }
func (s Style) green(t string) string        { return s.sgr("32", t) }
func (s Style) yellow(t string) string       { return s.sgr("33", t) }
func (s Style) indigo(t string) string       { return s.sgr("35", t) }
func (s Style) cyanLink(t string) string     { return s.sgr("4;36", t) }
func (s Style) fg256(n int, t string) string { return s.sgr(fmt.Sprintf("38;5;%d", n), t) }

// Severity palette (256-color): foreground and badge codes.
var sevFG = map[model.Severity]int{
	model.Critical: 196,
	model.High:     203,
	model.Medium:   220,
	model.Low:      45,
	model.Info:     245,
}

func (s Style) sev(sev model.Severity, text string) string { return s.fg256(sevFG[sev], text) }

var categoryColor = map[string]int{
	"Supabase":   42,  // green
	"Firebase":   214, // amber
	"Appwrite":   205, // pink
	"PocketBase": 111, // light blue
	"Convex":     209, // coral
	"Secrets":    203, // red
	"Repository": 117, // sky
	"Exposure":   141, // lavender
}

func (s Style) category(name string) string {
	c, ok := categoryColor[name]
	if !ok {
		c = 250
	}
	return s.fg256(c, "["+name+"]")
}

// Dim exposes the dim style for package-external use (list summary line).
func (s Style) Dim(t string) string { return s.dim(t) }

// verified renders the outcome of an opt-in live credential check.
func (s Style) verified(state string) string {
	switch state {
	case "active":
		return s.green("✔ provider confirms this key is active right now")
	case "rejected":
		return s.yellow("✖ provider rejected it — likely revoked or fake")
	default:
		return s.dim("? provider unreachable or unexpected answer — unverified")
	}
}
