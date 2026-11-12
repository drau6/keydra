package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/drau6/keydra/internal/model"
)

const labelWidth = 9

// Banner prints the title (ASCII art on wide interactive terminals, a compact
// one-line title otherwise) and the permission notice. CLI callers print it
// immediately, before the scan runs, so the user sees it while waiting.
func Banner(w io.Writer, st Style) {
	banner(w, st)
}

// Terminal prints a human-readable report. When verbose is false, fix
// snippets are shortened to their first line.
func Terminal(w io.Writer, r *model.Report, st Style, verbose bool) {
	kind := "url "
	if r.Mode == "repo" {
		kind = "repo"
	}
	fmt.Fprintf(w, "\n  %s  %s\n", st.dim(kind), st.cyanLink(r.Target))
	scanned := fmt.Sprintf("%d files scanned", r.FilesScanned)
	if r.PagesScanned > 1 {
		scanned = fmt.Sprintf("%d pages · %s", r.PagesScanned, scanned)
	}
	fmt.Fprintf(w, "  %s\n", st.dim(fmt.Sprintf("%s · %s", scanned, r.Duration.Round(time.Millisecond))))
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  "+st.green("✔ No issues found. Nothing exposed that we could see from the outside."))
		fmt.Fprintln(w)
	}

	for i, f := range r.Findings {
		gutter := "     " + st.sev(f.Severity, "│") + " "
		fmt.Fprintf(w, " %s  %s %s\n", st.bold(fmt.Sprintf("%2d", i+1)), st.category(f.Category), st.bold(f.Title))
		fmt.Fprintf(w, "%s%s\n", gutter, f.Detail)
		if f.Evidence != "" {
			fmt.Fprintf(w, "%s%s%s\n", gutter, label(st, "evidence"), st.yellow(f.Evidence))
		}
		if f.Verified != "" {
			fmt.Fprintf(w, "%s%s%s\n", gutter, label(st, "verified"), st.verified(f.Verified))
		}
		if f.Location != "" {
			fmt.Fprintf(w, "%s%s%s\n", gutter, label(st, "where"), st.cyanLink(f.Location))
		}
		if f.Fix != "" {
			fix := f.Fix
			hint := ""
			if !verbose {
				if idx := strings.IndexByte(fix, '\n'); idx >= 0 {
					fix = fix[:idx]
					hint = st.dim("  …(use -v for the full fix)")
				}
			}
			cont := "\n" + gutter + strings.Repeat(" ", labelWidth)
			fmt.Fprintf(w, "%s%s%s%s\n", gutter, label(st, "fix"), st.green(strings.ReplaceAll(fix, "\n", cont)), hint)
		}
		fmt.Fprintln(w)
	}

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "  %s %s\n", st.yellow("note:"), st.dim(warn))
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w)
	}
}

// Separator prints the dim rule line drawn between reports in --list mode.
func Separator(w io.Writer, st Style) {
	fmt.Fprintf(w, "\n  %s\n\n", st.dim(strings.Repeat("─", 58)))
}

func banner(w io.Writer, st Style) {
	ver := st.Version
	if ver == "" {
		ver = "dev"
	}
	if st.Art {
		fmt.Fprintln(w)
		for _, line := range st.artLines() {
			fmt.Fprintf(w, "  %s\n", line)
		}
		return
	}
	fmt.Fprintf(w, "\n  %s  %s\n", st.bold(st.fg256(BrandColor, "KEYDRA")), st.dim(ver))
}

func label(st Style, name string) string {
	return st.dim(fmt.Sprintf("%-*s", labelWidth, name))
}
