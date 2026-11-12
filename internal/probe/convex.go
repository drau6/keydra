package probe

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/drau6/keydra/internal/extractor"
	"github.com/drau6/keydra/internal/model"
)

var (
	convexOK    = regexp.MustCompile(`"status"\s*:\s*"success"`)
	convexEmpty = regexp.MustCompile(`"value"\s*:\s*(?:null|\[\s*\]|\{\s*\})`)
)

// Convex calls query functions found in the client bundle with no arguments
// and no credentials. The /api/query endpoint only runs queries (never
// mutations), so this is read-only. Queries are public by design, so results
// are reported as "verify this is intended", not as proof of a leak.
func (p *Prober) Convex(ctx context.Context, cfg extractor.Config) Result {
	var res Result
	for _, base := range capList(cfg.Convex.URLs, 2) {
		for _, fn := range capList(cfg.Convex.Functions, p.MaxTargets) {
			if ctx.Err() != nil {
				return res
			}
			payload := fmt.Sprintf(`{"path":%q,"args":{},"format":"json"}`, fn)
			req, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+"/api/query", bytes.NewBufferString(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := p.do(ctx, req)
			if err != nil {
				res.warn(fmt.Sprintf("convex %s: %v", fn, err))
				continue
			}
			body := string(peek(resp, 16<<10))
			status := resp.StatusCode
			resp.Body.Close()
			if status != http.StatusOK || !convexOK.MatchString(body) || convexEmpty.MatchString(body) {
				continue
			}
			res.add(model.Finding{
				ID:       "convex-public-query-returns-data",
				Title:    fmt.Sprintf("Convex query %q returns data to unauthenticated callers", fn),
				Severity: model.Medium,
				Category: "Convex",
				Detail:   "Anyone can call this query with no login. That is fine for genuinely public data; if it returns user or business data, add an auth check.",
				Evidence: fmt.Sprintf("POST /api/query {path:%q} → success with a non-empty value", fn),
				Location: base,
				Fix: "In the function body, require identity and scope results to it:\n" +
					"const identity = await ctx.auth.getUserIdentity();\n" +
					"if (!identity) throw new Error(\"Not authenticated\");\n" +
					"// then filter by identity.subject; use internalQuery for server-only functions",
			})
		}
	}
	return res
}
