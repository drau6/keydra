package cli

import (
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/drau6/keydra/internal/detectors"
)

func runRules(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	markdown := fs.Bool("markdown", false, "print the catalog as Markdown tables (used to generate the README)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitError
	}

	if *markdown {
		detectors.Markdown(stdout)
		return ExitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tWHERE\tDETECTS")
	for _, e := range detectors.Catalog() {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.ID, e.Severity, e.Where, e.Name)
	}
	tw.Flush()
	return ExitOK
}
