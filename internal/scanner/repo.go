package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/drau6/keydra/internal/fetcher"
	"github.com/drau6/keydra/internal/model"
	"github.com/drau6/keydra/internal/repo"
)

// RepoOptions configures a source-tree scan.
type RepoOptions struct {
	MaxFiles int
	Validate bool // opt-in: confirm detected secrets with one read-only request to each provider
}

// RunRepo scans a local source tree without touching the network.
func RunRepo(ctx context.Context, dir string, opts RepoOptions) (*model.Report, error) {
	start := time.Now()
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	files, warnings, err := repo.Walk(abs, repo.WalkOptions{MaxFiles: opts.MaxFiles})
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	rep := &model.Report{
		Mode:         "repo",
		Target:       abs,
		ScannedAt:    start.UTC(),
		FilesScanned: len(files),
		Warnings:     warnings,
	}
	col := newCollector(rep)
	if opts.Validate {
		col.enableValidation(10 * time.Second)
	}

	// Gitignored .env files are expected to hold secrets; do not flag their
	// contents. Everything else (including build output) is scanned.
	var assets []fetcher.Asset
	for _, f := range files {
		if f.IsEnv && f.Ignored {
			continue
		}
		assets = append(assets, fetcher.Asset{URL: f.Rel, Kind: "file", Body: f.Body})
	}
	cfg := col.analyze(assets)

	for _, f := range repo.Check(files) {
		col.add(f)
	}

	if found := backendsFound(cfg); len(found) > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"%s configuration found in source; run `keydra scan <deployed-url>` to test the live backend",
			strings.Join(found, ", ")))
	}

	col.finish(ctx, start)
	return rep, nil
}
