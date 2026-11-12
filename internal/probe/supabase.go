package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/drau6/keydra/internal/extractor"
	"github.com/drau6/keydra/internal/model"
)

// Supabase checks whether tables referenced by the app are readable with the
// public anon key (i.e. Row Level Security is missing or too permissive).
func (p *Prober) Supabase(ctx context.Context, cfg extractor.Config) Result {
	var res Result
	key := publicKey(cfg.SupabaseKeys)
	if key == "" || len(cfg.SupabaseURLs) == 0 {
		return res
	}
	for _, base := range cfg.SupabaseURLs {
		tables := cfg.Tables
		found, err := p.supabaseTables(ctx, base, key)
		if err != nil {
			res.warn(fmt.Sprintf("supabase %s: table discovery via OpenAPI failed (%v); only table names seen in client code will be probed. "+
				"Pass known names with --tables to probe them anyway.", base, err))
		} else {
			tables = mergeNames(tables, found)
		}
		extra := capList(p.ExtraTables, 0)
		tables = mergeNames(tables, extra)
		tables = capList(tables, p.MaxTargets)
		if len(tables) == 0 {
			res.warn(fmt.Sprintf("supabase %s: no table names discovered (none referenced in client code, and OpenAPI introspection "+
				"returned none — the project may have no public tables, RLS/grants may hide them from introspection, or it may be disabled). "+
				"Pass known names with --tables to probe them directly.", base))
			continue
		}
		for _, t := range tables {
			if ctx.Err() != nil {
				return res
			}
			status, count, err := p.supabaseCount(ctx, base, key, t)
			if err != nil {
				res.warn(fmt.Sprintf("supabase %s/%s: %v", base, t, err))
				continue
			}
			if status != http.StatusOK && status != http.StatusPartialContent {
				continue // denied or missing: good
			}
			if count == 0 {
				continue // empty or hidden by RLS; cannot tell, so stay quiet
			}
			detail := "The table can be read with the public anon key."
			evidence := fmt.Sprintf("GET /rest/v1/%s → %d, rows visible to anonymous role: %s", t, status, rowsLabel(count))
			res.add(model.Finding{
				ID:       "supabase-table-exposed",
				Title:    fmt.Sprintf("Supabase table %q is publicly readable", t),
				Severity: severityFor(t),
				Category: "Supabase",
				Detail:   detail + " Anyone who opens your site's JavaScript can dump this data.",
				Evidence: evidence,
				Location: base,
				Fix: fmt.Sprintf("alter table public.%s enable row level security;\n"+
					"-- then add explicit policies, for example:\n"+
					"create policy \"users read own rows\" on public.%s\n"+
					"  for select to authenticated using (auth.uid() = user_id);", t, t),
			})
		}
	}
	return res
}

// publicKey prefers a key that is meant to be public.
func publicKey(keys []extractor.SupabaseKey) string {
	for _, k := range keys {
		if k.Role == extractor.RoleAnon || k.Role == extractor.RolePublishable {
			return k.Value
		}
	}
	return ""
}

// supabaseTables lists tables from the PostgREST OpenAPI document if exposed.
func (p *Prober) supabaseTables(ctx context.Context, base, key string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, base+"/rest/v1/", nil)
	if err != nil {
		return nil, err
	}
	setSupabaseAuth(req, key)
	// PostgREST only returns the OpenAPI document for this exact media type;
	// "application/json" alone can return an empty or minimal body.
	req.Header.Set("Accept", "application/openapi+json")
	resp, err := p.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openapi: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("openapi: unexpected response (%d bytes, not a parseable OpenAPI document)", len(body))
	}
	if len(doc.Paths) == 0 {
		return nil, fmt.Errorf("openapi: document had no paths (no public tables, or anon/authenticated roles have no grants)")
	}
	var out []string
	for path := range doc.Paths {
		name := strings.TrimPrefix(path, "/")
		if name == "" || strings.HasPrefix(name, "rpc/") || strings.Contains(name, "/") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// supabaseCount asks for a single row with an exact count. Only the status and
// the Content-Range total are used; the body is not kept.
func (p *Prober) supabaseCount(ctx context.Context, base, key, table string) (status, count int, err error) {
	u := fmt.Sprintf("%s/rest/v1/%s?select=*&limit=1", base, url.PathEscape(table))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, 0, err
	}
	setSupabaseAuth(req, key)
	req.Header.Set("Prefer", "count=exact")
	req.Header.Set("Range", "0-0")
	resp, err := p.do(ctx, req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if cr := resp.Header.Get("Content-Range"); cr != "" {
		if i := strings.LastIndex(cr, "/"); i >= 0 {
			if n, convErr := strconv.Atoi(cr[i+1:]); convErr == nil {
				return resp.StatusCode, n, nil
			}
		}
	}
	// No usable count header: peek at the first bytes only.
	b := strings.TrimSpace(string(peek(resp, 8)))
	if b == "" || strings.HasPrefix(b, "[]") {
		return resp.StatusCode, 0, nil
	}
	return resp.StatusCode, -1, nil // readable, total unknown
}

func setSupabaseAuth(req *http.Request, key string) {
	req.Header.Set("apikey", key)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
}

func rowsLabel(n int) string {
	if n < 0 {
		return "unknown (non-empty)"
	}
	return strconv.Itoa(n)
}

func mergeNames(a, b []string) []string {
	set := map[string]struct{}{}
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
