// Command keydra scans deployed web apps for exposed backends and secrets
// that commonly leak from AI-generated ("vibe-coded") projects.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/drau6/keydra/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
