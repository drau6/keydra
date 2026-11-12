package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/drau6/keydra/internal/extractor"
	"github.com/drau6/keydra/internal/model"
)

// PocketBase checks whether collections referenced by the app can be listed
// without authentication (empty API rule) and whether the admin UI is public.
func (p *Prober) PocketBase(ctx context.Context, cfg extractor.Config) Result {
	var res Result
	for _, base := range capList(cfg.PocketBase, 2) {
		base = strings.TrimRight(base, "/")
		for _, col := range capList(cfg.Collections, p.MaxTargets) {
			if ctx.Err() != nil {
				return res
			}
			path := fmt.Sprintf("/api/collections/%s/records?perPage=1", url.PathEscape(col))
			req, err := http.NewRequest(http.MethodGet, base+path, nil)
			if err != nil {
				continue
			}
			resp, err := p.do(ctx, req)
			if err != nil {
				res.warn(fmt.Sprintf("pocketbase %s/%s: %v", base, col, err))
				continue
			}
			status := resp.StatusCode
			total := -1
			if status == http.StatusOK {
				total = totalFrom(resp)
			}
			resp.Body.Close()
			if status != http.StatusOK || total == 0 {
				continue
			}
			res.add(model.Finding{
				ID:       "pocketbase-collection-exposed",
				Title:    fmt.Sprintf("PocketBase collection %q can be listed without login", col),
				Severity: severityFor(col),
				Category: "PocketBase",
				Detail:   "The collection's List/Search rule is empty (public), so anyone can read its records through the REST API.",
				Evidence: fmt.Sprintf("GET /api/collections/%s/records → 200, records visible without login: %s", col, countLabel(total)),
				Location: base,
				Fix: "In the PocketBase dashboard open the collection → API Rules. An empty rule means public; a locked rule means superusers only. " +
					"Set List/Search and View to something like: @request.auth.id != \"\" && owner = @request.auth.id",
			})
		}

		if req, err := http.NewRequest(http.MethodGet, base+"/_/", nil); err == nil {
			if resp, err := p.do(ctx, req); err == nil {
				if resp.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(string(peek(resp, 4<<10))), "pocketbase") {
					res.add(model.Finding{
						ID:       "pocketbase-admin-ui-public",
						Title:    "PocketBase admin dashboard is reachable from the internet",
						Severity: model.Low,
						Category: "PocketBase",
						Detail:   "The login page is public by design, but it invites brute-force and credential-stuffing against the superuser account.",
						Location: base + "/_/",
						Fix:      "Restrict /_/ at your reverse proxy (IP allowlist or VPN), use a long unique superuser password and enable MFA/rate limits.",
					})
				}
				resp.Body.Close()
			}
		}
	}
	return res
}
