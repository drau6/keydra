// Package fetcher downloads a page and the public JavaScript it references.
// It only performs plain GET requests against URLs the page itself exposes.
package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Options controls crawl limits.
type Options struct {
	Timeout    time.Duration
	MaxFiles   int
	MaxBytes   int64
	UserAgent  string
	ThirdParty bool // also fetch scripts hosted on other origins

	// Depth is the number of page levels to crawl: 1 scans only the given
	// page, 2 also follows its internal links, and so on.
	Depth int
	// MaxPages caps the total number of HTML pages fetched.
	MaxPages int
	// Sitemap also scans pages listed in /sitemap.xml (counts toward MaxPages).
	Sitemap bool
	// Delay is the pause between page requests.
	Delay time.Duration
}

// Asset kinds.
const (
	KindHTML      = "html"
	KindJS        = "js"
	KindSourceMap = "sourcemap"
)

// Asset is one downloaded file.
type Asset struct {
	URL  string
	Kind string
	Body string
}

// Result is everything gathered for a target.
type Result struct {
	Pages    []string // HTML pages that were fetched
	Assets   []Asset
	Warnings []string
}

// Fetcher downloads assets with sane limits.
type Fetcher struct {
	opts   Options
	client *http.Client
}

// New creates a Fetcher.
func New(opts Options) *Fetcher {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 40
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 5 << 20
	}
	if opts.Depth <= 0 {
		opts.Depth = 1
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 20
	}
	if opts.Delay <= 0 {
		opts.Delay = 150 * time.Millisecond
	}
	return &Fetcher{
		opts: opts,
		client: &http.Client{
			Timeout: opts.Timeout,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	preloadRe   = regexp.MustCompile(`(?i)<link[^>]+href\s*=\s*["']([^"']+\.m?js(?:\?[^"']*)?)["']`)
	inlineRe    = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
	hasSrcRe    = regexp.MustCompile(`(?i)\ssrc\s*=`)
	chunkRe     = regexp.MustCompile(`["'(]((?:\.{0,2}/)?(?:assets|_next/static|static/js|build)/[A-Za-z0-9_./\-\[\]%~@]+?\.m?js)["')]`)
	sourceMapRe = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s'"]+)`)
)

// Crawl fetches the target page (and, depending on Depth and Sitemap, more
// pages of the same site), the scripts they reference, one level of lazy
// chunks and any publicly exposed source maps.
func (f *Fetcher) Crawl(ctx context.Context, target string) (*Result, error) {
	if _, err := url.Parse(target); err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	html, finalURL, err := f.get(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", target, err)
	}
	root, err := url.Parse(finalURL)
	if err != nil {
		return nil, err
	}

	res := &Result{}
	pages := []page{{url: finalURL, html: html}}
	visited := map[string]bool{pageKey(root): true}

	// Extra pages: sitemap entries first, then breadth-first internal links.
	if f.opts.Sitemap {
		var seeds []string
		for _, u := range f.sitemapURLs(ctx, root) {
			if len(pages)+len(seeds) >= f.opts.MaxPages {
				break
			}
			if k := pageKeyStr(u); !visited[k] {
				visited[k] = true
				seeds = append(seeds, u)
			}
		}
		pages = append(pages, f.fetchPages(ctx, seeds, res)...)
	}
	frontier := pages
	for level := 1; level < f.opts.Depth && len(pages) < f.opts.MaxPages; level++ {
		var next []string
		for _, p := range frontier {
			base, perr := url.Parse(p.url)
			if perr != nil {
				continue
			}
			for _, link := range f.pageLinks(base, p.html) {
				if len(pages)+len(next) >= f.opts.MaxPages {
					break
				}
				if k := pageKeyStr(link); !visited[k] {
					visited[k] = true
					next = append(next, link)
				}
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = f.fetchPages(ctx, next, res)
		pages = append(pages, frontier...)
	}
	if f.opts.Depth > 1 && len(pages) == 1 && !f.opts.Sitemap {
		res.Warnings = append(res.Warnings, "--depth found no internal links in the HTML; client-rendered apps expose routes through their JavaScript instead (try --sitemap)")
	}

	// Collect scripts from every page; shared scripts are fetched once.
	seen := map[string]bool{}
	var queue []string
	add := func(base *url.URL, raw string) {
		u := f.resolve(base, raw)
		if u == "" || seen[u] || len(seen) >= f.opts.MaxFiles {
			return
		}
		seen[u] = true
		queue = append(queue, u)
	}
	for _, p := range pages {
		res.Pages = append(res.Pages, p.url)
		res.Assets = append(res.Assets, Asset{URL: p.url, Kind: KindHTML, Body: p.html})
		for i, m := range inlineRe.FindAllStringSubmatchIndex(p.html, -1) {
			open := p.html[m[0]:m[2]]
			if hasSrcRe.MatchString(open) || strings.TrimSpace(p.html[m[2]:m[3]]) == "" {
				continue
			}
			res.Assets = append(res.Assets, Asset{
				URL:  fmt.Sprintf("%s#inline-%d", p.url, i+1),
				Kind: KindJS,
				Body: p.html[m[2]:m[3]],
			})
		}
		base, perr := url.Parse(p.url)
		if perr != nil {
			continue
		}
		for _, rx := range []*regexp.Regexp{scriptSrcRe, preloadRe} {
			for _, m := range rx.FindAllStringSubmatch(p.html, -1) {
				add(base, m[1])
			}
		}
	}

	// Two rounds: initial scripts, then chunks they reference.
	for round := 0; round < 2 && len(queue) > 0; round++ {
		batch := queue
		queue = nil
		fetched := f.fetchAll(ctx, batch, res)
		if round == 0 {
			for _, a := range fetched {
				// Bundlers reference chunks relative to the site root.
				for _, m := range chunkRe.FindAllStringSubmatch(a.Body, -1) {
					add(root, m[1])
				}
			}
		}
	}

	f.collectSourceMaps(ctx, res)
	return res, nil
}

type page struct {
	url  string
	html string
}

// fetchPages downloads pages one at a time with a pause between requests.
func (f *Fetcher) fetchPages(ctx context.Context, urls []string, res *Result) []page {
	var out []page
	for _, u := range urls {
		select {
		case <-time.After(f.opts.Delay):
		case <-ctx.Done():
			return out
		}
		body, final, err := f.get(ctx, u)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("skip page %s: %v", u, err))
			continue
		}
		out = append(out, page{url: final, html: body})
	}
	return out
}

var (
	linkRe     = regexp.MustCompile(`(?i)<a\s[^>]*?href\s*=\s*["']([^"'\s>]+)["']`)
	locRe      = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)
	skipExt    = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".webp": true, ".ico": true, ".avif": true, ".css": true, ".js": true, ".mjs": true, ".json": true, ".xml": true, ".txt": true, ".pdf": true, ".zip": true, ".gz": true, ".mp4": true, ".webm": true, ".mp3": true, ".woff": true, ".woff2": true, ".ttf": true}
	unsafePath = regexp.MustCompile(`(?i)log-?out|sign-?out|delete|remove|destroy|unsubscribe|revoke|cancel`)
)

// resolvePage returns an absolute same-host page URL, or "" if raw should not
// be crawled. Links that look like they trigger actions (logout, delete, …)
// are skipped because crawling only ever issues GET requests.
func (f *Fetcher) resolvePage(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	low := strings.ToLower(raw)
	if raw == "" || strings.HasPrefix(low, "#") || strings.HasPrefix(low, "mailto:") ||
		strings.HasPrefix(low, "tel:") || strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u := base.ResolveReference(ref)
	if (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, base.Host) {
		return ""
	}
	u.Fragment = ""
	if skipExt[strings.ToLower(path.Ext(u.Path))] || unsafePath.MatchString(u.Path+"?"+u.RawQuery) {
		return ""
	}
	return u.String()
}

func (f *Fetcher) pageLinks(base *url.URL, html string) []string {
	var out []string
	for _, m := range linkRe.FindAllStringSubmatch(html, -1) {
		if u := f.resolvePage(base, m[1]); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// sitemapURLs reads /sitemap.xml (one level; nested sitemaps are ignored).
func (f *Fetcher) sitemapURLs(ctx context.Context, root *url.URL) []string {
	sm := *root
	sm.Path, sm.RawQuery, sm.Fragment = "/sitemap.xml", "", ""
	body, _, err := f.get(ctx, sm.String())
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range locRe.FindAllStringSubmatch(body, -1) {
		if u := f.resolvePage(root, m[1]); u != "" {
			out = append(out, u)
		}
	}
	return out
}

func pageKey(u *url.URL) string {
	c := *u
	c.Fragment = ""
	return strings.TrimRight(c.String(), "/")
}

func pageKeyStr(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return pageKey(u)
}

// fetchAll downloads urls concurrently and appends successes to res.
func (f *Fetcher) fetchAll(ctx context.Context, urls []string, res *Result) []Asset {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, 8)
		out []Asset
	)
	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			body, _, err := f.get(ctx, u)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("skip %s: %v", u, err))
				return
			}
			a := Asset{URL: u, Kind: KindJS, Body: body}
			out = append(out, a)
			res.Assets = append(res.Assets, a)
		}(u)
	}
	wg.Wait()
	return out
}

// collectSourceMaps looks for sourceMappingURL comments and downloads maps.
func (f *Fetcher) collectSourceMaps(ctx context.Context, res *Result) {
	var maps []string
	for _, a := range res.Assets {
		if a.Kind != KindJS {
			continue
		}
		m := sourceMapRe.FindStringSubmatch(a.Body)
		if m == nil || strings.HasPrefix(m[1], "data:") {
			continue
		}
		base, err := url.Parse(a.URL)
		if err != nil {
			continue
		}
		if u := f.resolve(base, m[1]); u != "" {
			maps = append(maps, u)
		}
		if len(maps) >= 10 {
			break
		}
	}
	for _, u := range maps {
		body, _, err := f.get(ctx, u)
		if err != nil {
			continue
		}
		var sm struct {
			Sources        []string `json:"sources"`
			SourcesContent []string `json:"sourcesContent"`
		}
		if json.Unmarshal([]byte(body), &sm) != nil || len(sm.Sources) == 0 {
			continue
		}
		res.Assets = append(res.Assets, Asset{
			URL:  u,
			Kind: KindSourceMap,
			Body: strings.Join(sm.SourcesContent, "\n"),
		})
	}
}

// resolve makes raw absolute relative to base and applies host policy.
func (f *Fetcher) resolve(base *url.URL, raw string) string {
	ref, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	u := base.ResolveReference(ref)
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if !f.opts.ThirdParty && !strings.EqualFold(u.Host, base.Host) {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

// get downloads one URL, capped at MaxBytes, and returns the final URL.
func (f *Fetcher) get(ctx context.Context, rawURL string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", "", err
	}
	if f.opts.UserAgent != "" {
		req.Header.Set("User-Agent", f.opts.UserAgent)
	}
	req.Header.Set("Accept", "text/html,application/javascript,application/json,*/*;q=0.5")
	resp, err := f.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, f.opts.MaxBytes))
	if err != nil {
		return "", "", err
	}
	return string(b), resp.Request.URL.String(), nil
}
