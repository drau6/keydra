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

const appwriteCloud = "https://cloud.appwrite.io/v1"

const appwriteFix = "In the Appwrite Console open the collection/bucket → Settings → Permissions and remove the \"Any\" role from Read. " +
	"Grant read only to \"Users\", a team, or a specific user, and prefer document-level permissions for per-user data."

// Appwrite checks whether collections and buckets referenced by the app are
// readable without logging in (the "Any" role).
func (p *Prober) Appwrite(ctx context.Context, cfg extractor.Config) Result {
	var res Result
	aw := cfg.Appwrite
	if len(aw.Projects) == 0 {
		return res
	}
	endpoint := appwriteCloud
	if len(aw.Endpoints) > 0 {
		endpoint = strings.TrimRight(aw.Endpoints[0], "/")
	}
	project := aw.Projects[0]

	get := func(path string) (int, int, error) {
		req, err := http.NewRequest(http.MethodGet, endpoint+path, nil)
		if err != nil {
			return 0, 0, err
		}
		req.Header.Set("X-Appwrite-Project", project)
		req.Header.Set("Accept", "application/json")
		resp, err := p.do(ctx, req)
		if err != nil {
			return 0, 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, 0, nil
		}
		return resp.StatusCode, totalFrom(resp), nil
	}

	for _, c := range capList2(aw.Collections, p.MaxTargets) {
		if ctx.Err() != nil {
			return res
		}
		path := fmt.Sprintf("/databases/%s/collections/%s/documents", url.PathEscape(c.Database), url.PathEscape(c.Collection))
		status, total, err := get(path)
		if err != nil {
			res.warn(fmt.Sprintf("appwrite %s: %v", c.Collection, err))
			continue
		}
		if status != http.StatusOK || total == 0 {
			continue
		}
		res.add(model.Finding{
			ID:       "appwrite-collection-exposed",
			Title:    fmt.Sprintf("Appwrite collection %q is readable without login", c.Collection),
			Severity: severityFor(c.Collection),
			Category: "Appwrite",
			Detail:   "Documents can be listed by anyone who knows the project ID, which is visible in your JavaScript.",
			Evidence: fmt.Sprintf("GET %s → 200, documents visible without login: %s", path, countLabel(total)),
			Location: endpoint,
			Fix:      appwriteFix,
		})
	}

	for _, t := range capList2(aw.Tables, p.MaxTargets) {
		if ctx.Err() != nil {
			return res
		}
		path := fmt.Sprintf("/tablesdb/%s/tables/%s/rows", url.PathEscape(t.Database), url.PathEscape(t.Collection))
		status, total, err := get(path)
		if err != nil {
			res.warn(fmt.Sprintf("appwrite table %s: %v", t.Collection, err))
			continue
		}
		if status != http.StatusOK || total == 0 {
			continue
		}
		res.add(model.Finding{
			ID:       "appwrite-table-exposed",
			Title:    fmt.Sprintf("Appwrite table %q is readable without login", t.Collection),
			Severity: severityFor(t.Collection),
			Category: "Appwrite",
			Detail:   "Rows can be listed by anyone who knows the project ID, which is visible in your JavaScript.",
			Evidence: fmt.Sprintf("GET %s → 200, rows visible without login: %s", path, countLabel(total)),
			Location: endpoint,
			Fix:      appwriteFix,
		})
	}

	for _, b := range capList(aw.Buckets, p.MaxTargets) {
		if ctx.Err() != nil {
			return res
		}
		path := fmt.Sprintf("/storage/buckets/%s/files", url.PathEscape(b))
		status, total, err := get(path)
		if err != nil {
			res.warn(fmt.Sprintf("appwrite bucket %s: %v", b, err))
			continue
		}
		if status != http.StatusOK || total == 0 {
			continue
		}
		res.add(model.Finding{
			ID:       "appwrite-bucket-exposed",
			Title:    fmt.Sprintf("Appwrite storage bucket %q is listable without login", b),
			Severity: model.High,
			Category: "Appwrite",
			Detail:   "Files in this bucket can be listed by anyone.",
			Evidence: fmt.Sprintf("GET %s → 200, files visible without login: %s", path, countLabel(total)),
			Location: endpoint,
			Fix:      appwriteFix,
		})
	}
	return res
}

func capList2(in []extractor.DocRef, n int) []extractor.DocRef {
	if n > 0 && len(in) > n {
		return in[:n]
	}
	return in
}

func countLabel(n int) string {
	if n < 0 {
		return "unknown (non-empty)"
	}
	return fmt.Sprintf("%d", n)
}
