package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/drau6/keydra/internal/buildinfo"
	"github.com/drau6/keydra/internal/fetcher"
	"github.com/drau6/keydra/internal/model"
	"github.com/drau6/keydra/internal/report"
	"github.com/drau6/keydra/internal/scanner"
)

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		repoDir    = fs.String("repo", "", "scan a local source directory (no network) instead of a URL")
		asJSON     = fs.Bool("json", false, "shortcut for --format json")
		format     = fs.String("format", "text", "output format: text|json|sarif")
		noProbe    = fs.Bool("no-probe", false, "static analysis only; do not contact discovered backends")
		list       = fs.String("list", "", "file with one URL per line (blank lines and #comments ignored, max 50); scans every URL in sequence")
		validate   = fs.Bool("validate", false, "confirm detected secrets with one read-only request to each provider (reports active/rejected/unverified)")
		timeout    = fs.Duration("timeout", 15*time.Second, "per-request timeout")
		maxFiles   = fs.Int("max-files", 40, "maximum number of JavaScript files to download (URL mode)")
		depth      = fs.Int("depth", 1, "page levels to crawl in URL mode: 1 = only the given page, 2 = also its internal links (max 5)")
		maxPages   = fs.Int("max-pages", 20, "maximum number of HTML pages to fetch (URL mode, max 200)")
		sitemap    = fs.Bool("sitemap", false, "also scan pages listed in /sitemap.xml (URL mode)")
		tables     = fs.String("tables", "", "comma-separated table/collection names to probe even if auto-discovery finds none")
		noBanner   = fs.Bool("no-banner", false, "print a one-line title instead of the ASCII-art banner")
		thirdParty = fs.Bool("third-party", false, "also scan scripts hosted on other origins")
		userAgent  = fs.String("user-agent", fmt.Sprintf("keydra/%s (+https://github.com/drau6/keydra)", buildinfo.Version), "User-Agent header")
		failOn     = fs.String("fail-on", "high", "exit with code 1 if a finding of this severity or higher exists (info|low|medium|high|critical|never)")
		colorMode  = fs.String("color", "auto", "colored output: auto|always|never")
		noColor    = fs.Bool("no-color", false, "disable colored output (same as --color=never)")
		verbose    = fs.Bool("v", false, "show full fix snippets")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage:\n  keydra scan <url> [flags]\n  keydra scan --repo <dir> [flags]\n  keydra scan --list <file> [flags]\n\nFlags:")
		fs.PrintDefaults()
	}

	pos, err := parseInterspersed(fs, args)
	if err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitError
	}
	if *list != "" {
		if *repoDir != "" || len(pos) != 0 {
			fmt.Fprintln(stderr, "--list cannot be combined with --repo or a URL argument")
			return ExitError
		}
	} else {
		if (*repoDir == "" && len(pos) != 1) || (*repoDir != "" && len(pos) != 0) {
			fs.Usage()
			return ExitError
		}
	}

	threshold, never := model.Critical, false
	if *failOn == "never" {
		never = true
	} else if sev, ok := model.ParseSeverity(*failOn); ok {
		threshold = sev
	} else {
		fmt.Fprintf(stderr, "invalid --fail-on value %q\n", *failOn)
		return ExitError
	}

	outFormat := *format
	if *asJSON {
		outFormat = "json"
	}
	if outFormat != "text" && outFormat != "json" && outFormat != "sarif" {
		fmt.Fprintf(stderr, "invalid --format value %q (use text, json or sarif)\n", outFormat)
		return ExitError
	}

	if *depth < 1 || *depth > 5 {
		fmt.Fprintln(stderr, "--depth must be between 1 and 5")
		return ExitError
	}
	if *maxPages < 1 || *maxPages > 200 {
		fmt.Fprintln(stderr, "--max-pages must be between 1 and 200")
		return ExitError
	}

	targets := pos
	switch {
	case *list != "":
		targets, err = parseURLList(*list)
		if err != nil {
			fmt.Fprintf(stderr, "keydra: %v\n", err)
			return ExitError
		}
	case *repoDir != "":
		// Repo mode scans exactly one target; give the loop an entry so
		// error reporting and the empty-reports guard behave uniformly.
		targets = []string{*repoDir}
	}

	// Show the banner immediately so it is on screen while the scan runs;
	// machine formats (json, sarif) keep stdout clean and print nothing here.
	var st report.Style
	if outFormat == "text" {
		mode := *colorMode
		if *noColor {
			mode = "never"
		}
		color := useColor(mode, stdout)
		st = report.Style{Color: color, Version: buildinfo.Version, Art: !*noBanner && showArt(color, stdout)}
		report.Banner(stdout, st)
	}

	var reports []*model.Report
	for _, target := range targets {
		var rep *model.Report
		if *repoDir != "" {
			rep, err = scanner.RunRepo(ctx, *repoDir, scanner.RepoOptions{Validate: *validate})
		} else {
			rep, err = scanner.Run(ctx, target, scanner.Options{
				Probe:    !*noProbe,
				Validate: *validate,
				Fetch: fetcher.Options{
					Timeout:    *timeout,
					MaxFiles:   *maxFiles,
					Depth:      *depth,
					MaxPages:   *maxPages,
					Sitemap:    *sitemap,
					UserAgent:  *userAgent,
					ThirdParty: *thirdParty,
				},
				ExtraTables: splitTables(*tables),
			})
		}
		if err != nil {
			fmt.Fprintf(stderr, "keydra: %v: %v\n", target, err)
			continue
		}
		reports = append(reports, rep)
	}
	if len(reports) == 0 {
		return ExitError
	}

	switch outFormat {
	case "json":
		if err := writeJSON(stdout, reports, *list != ""); err != nil {
			fmt.Fprintf(stderr, "keydra: %v\n", err)
			return ExitError
		}
	case "sarif":
		if err := writeSARIF(stdout, reports, buildinfo.Version); err != nil {
			fmt.Fprintf(stderr, "keydra: %v\n", err)
			return ExitError
		}
	default:
		for i, rep := range reports {
			if i > 0 {
				report.Separator(stdout, st)
			}
			report.Terminal(stdout, rep, st, *verbose)
		}
		if *list != "" {
			fmt.Fprintln(stdout, listSummary(reports, len(targets), st))
		}
	}

	if !never {
		for _, rep := range reports {
			for _, f := range rep.Findings {
				if f.Severity >= threshold {
					return ExitFindings
				}
			}
		}
	}
	if len(reports) < len(targets) {
		return ExitError // at least one target failed to scan
	}
	return ExitOK
}

// writeJSON emits one object for a single scan, or an array for --list.
func writeJSON(w io.Writer, reports []*model.Report, multi bool) error {
	if !multi {
		return report.JSON(w, reports[0])
	}
	return report.JSONAll(w, reports)
}

// listSummary builds the one-line tally printed after a --list text run.
func listSummary(reports []*model.Report, targets int, st report.Style) string {
	withFindings := 0
	for _, rep := range reports {
		if len(rep.Findings) > 0 {
			withFindings++
		}
	}
	s := fmt.Sprintf("%d of %d targets scanned · %d clean · %d with findings",
		len(reports), targets, len(reports)-withFindings, withFindings)
	if failed := targets - len(reports); failed > 0 {
		s += fmt.Sprintf(" · %d failed (see stderr)", failed)
	}
	return "  " + st.Dim(s)
}

// writeSARIF emits one run per report.
func writeSARIF(w io.Writer, reports []*model.Report, version string) error {
	if len(reports) == 1 {
		return report.SARIF(w, reports[0], version)
	}
	return report.SARIFAll(w, reports, version)
}

// maxListTargets keeps --list from becoming an unbounded mass scanner.
const maxListTargets = 50

// parseURLList reads one URL per line; blank lines and #comments are ignored.
func parseURLList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs found in %s", path)
	}
	if len(urls) > maxListTargets {
		return nil, fmt.Errorf("%s lists %d URLs; --list supports at most %d per run", path, len(urls), maxListTargets)
	}
	return urls, nil
}

func splitTables(csv string) []string {
	var out []string
	for _, t := range strings.Split(csv, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}
