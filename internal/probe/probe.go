// Package probe performs minimal, read-only checks against backends that a
// scanned app exposes. It never writes data, never stores response bodies and
// only inspects status codes, row counts and top-level key names.
package probe

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/drau6/keydra/internal/model"
)

// Prober issues throttled, read-only requests.
type Prober struct {
	client *http.Client
	ua     string
	delay  time.Duration
	// MaxTargets caps tables / collections checked per backend.
	MaxTargets int
	// ExtraTables are table/collection names supplied by the user (--tables)
	// to probe even when they cannot be auto-discovered.
	ExtraTables []string
}

// New builds a Prober.
func New(timeout time.Duration, userAgent string) *Prober {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Prober{
		client:     &http.Client{Timeout: timeout},
		ua:         userAgent,
		delay:      150 * time.Millisecond,
		MaxTargets: 25,
	}
}

// Result bundles probe output.
type Result struct {
	Findings []model.Finding
	Warnings []string
}

func (r *Result) add(f model.Finding) { r.Findings = append(r.Findings, f) }
func (r *Result) warn(s string)       { r.Warnings = append(r.Warnings, s) }

// do sends req after a short pause so we stay polite to the target.
func (p *Prober) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if p.ua != "" {
		req.Header.Set("User-Agent", p.ua)
	}
	return p.client.Do(req.WithContext(ctx))
}

// peek reads at most n bytes of the body and discards the rest.
func peek(resp *http.Response, n int64) []byte {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, n))
	return b
}

// severityFor raises severity when a table or collection name suggests
// personal or financial data.
func severityFor(name string) model.Severity { return model.SeverityForName(name) }

func capList(in []string, n int) []string {
	if n > 0 && len(in) > n {
		return in[:n]
	}
	return in
}

var totalRe = regexp.MustCompile(`"(?:total|totalItems)"\s*:\s*(\d+)`)

// totalFrom reads the record count Appwrite ("total") or PocketBase
// ("totalItems") put at the start of list responses. It returns -1 when the
// count is missing. Only the count is kept.
func totalFrom(resp *http.Response) int {
	m := totalRe.FindSubmatch(peek(resp, 4<<10))
	if m == nil {
		return -1
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return -1
	}
	return n
}
