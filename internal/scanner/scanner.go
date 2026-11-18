// Package scanner orchestrates a full scan: fetch, extract, detect, probe.
package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/drau6/keydra/internal/fetcher"
	"github.com/drau6/keydra/internal/model"
	"github.com/drau6/keydra/internal/netutil"
	"github.com/drau6/keydra/internal/probe"
)

// Options configures a scan of a deployed app.
type Options struct {
	Fetch        fetcher.Options
	Probe        bool     // run read-only network checks against discovered backends
	Validate     bool     // opt-in: confirm detected secrets with one read-only request to each provider
	ExtraTables  []string // Supabase table names to probe even if not auto-discovered (--tables)
	AllowPrivate bool     // allow loopback/private backend endpoints (local development)
}

// Run scans a deployed web app and returns a finished report.
func Run(ctx context.Context, target string, opts Options) (*model.Report, error) {
	start := time.Now()
	target, err := NormalizeURL(target)
	if err != nil {
		return nil, err
	}
	if opts.Fetch.Timeout <= 0 {
		opts.Fetch.Timeout = fetcher.DefaultTimeout
	}

	// A local target is a local development scan, so allow its local backend
	// (for example a Supabase instance on 127.0.0.1). Public targets need the
	// explicit --allow-private flag to reach local endpoints.
	allowPrivate := opts.AllowPrivate
	if u, perr := url.Parse(target); perr == nil {
		allowPrivate = allowPrivate || netutil.IsPrivateHost(u.Hostname())
	}
	opts.Fetch.AllowPrivate = opts.Fetch.AllowPrivate || allowPrivate

	crawl, err := fetcher.New(opts.Fetch).Crawl(ctx, target)
	if err != nil {
		return nil, err
	}

	rep := &model.Report{
		Mode:         "web",
		Target:       target,
		ScannedAt:    start.UTC(),
		PagesScanned: len(crawl.Pages),
		FilesScanned: len(crawl.Assets),
		Probed:       opts.Probe,
		Warnings:     crawl.Warnings,
	}
	col := newCollector(rep)
	if opts.Validate {
		col.enableValidation(opts.Fetch.Timeout)
	}
	cfg := col.analyze(crawl.Assets)

	found := backendsFound(cfg)
	switch {
	case opts.Probe:
		p := probe.New(opts.Fetch.Timeout, opts.Fetch.UserAgent)
		p.ExtraTables = opts.ExtraTables
		p.AllowPrivate = allowPrivate
		var results []probe.Result
		if cfg.HasSupabase() {
			results = append(results, p.Supabase(ctx, cfg))
		}
		if cfg.HasFirebase() {
			results = append(results, p.Firebase(ctx, cfg))
		}
		if cfg.HasAppwrite() {
			results = append(results, p.Appwrite(ctx, cfg))
		}
		if cfg.HasPocketBase() {
			results = append(results, p.PocketBase(ctx, cfg))
		}
		if cfg.HasConvex() {
			results = append(results, p.Convex(ctx, cfg))
		}
		for _, r := range results {
			for _, f := range r.Findings {
				col.add(f)
			}
			rep.Warnings = append(rep.Warnings, r.Warnings...)
		}
	case len(found) > 0:
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("backend detected (%s) but probing is disabled (--no-probe); only static checks were run", strings.Join(found, ", ")))
	}

	col.finish(ctx, start)
	return rep, nil
}

// NormalizeURL adds a scheme when missing and validates the result.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid url %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	return u.String(), nil
}
