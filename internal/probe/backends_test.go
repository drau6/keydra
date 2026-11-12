package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/drau6/keydra/internal/extractor"
)

func ids(res Result) map[string]int {
	m := map[string]int{}
	for _, f := range res.Findings {
		m[f.ID]++
	}
	return m
}

func TestAppwrite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Appwrite-Project") != "proj1" {
			t.Errorf("project header missing")
		}
		switch r.URL.Path {
		case "/databases/db1/collections/users/documents":
			w.Write([]byte(`{"total":5,"documents":[{"name":"private"}]}`))
		case "/tablesdb/db1/tables/orders/rows":
			w.Write([]byte(`{"total":2,"rows":[{"x":1}]}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	cfg := extractor.Config{Appwrite: extractor.Appwrite{
		Endpoints:   []string{srv.URL},
		Projects:    []string{"proj1"},
		Collections: []extractor.DocRef{{Database: "db1", Collection: "users"}, {Database: "db1", Collection: "locked"}},
		Tables:      []extractor.DocRef{{Database: "db1", Collection: "orders"}},
		Buckets:     []string{"b1"},
	}}
	got := ids(newTestProber().Appwrite(context.Background(), cfg))
	if got["appwrite-collection-exposed"] != 1 || got["appwrite-table-exposed"] != 1 || len(got) != 2 {
		t.Fatalf("unexpected findings: %v", got)
	}
}

func TestPocketBase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/collections/posts/records":
			w.Write([]byte(`{"page":1,"perPage":1,"totalItems":3,"totalPages":3,"items":[{"id":"x"}]}`))
		case "/_/":
			w.Write([]byte(`<html><title>PocketBase</title></html>`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()

	cfg := extractor.Config{PocketBase: []string{srv.URL}, Collections: []string{"posts", "secrets"}}
	got := ids(newTestProber().PocketBase(context.Background(), cfg))
	if got["pocketbase-collection-exposed"] != 1 || got["pocketbase-admin-ui-public"] != 1 || len(got) != 2 {
		t.Fatalf("unexpected findings: %v", got)
	}
}

func TestConvex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/query" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req struct{ Path string }
		json.NewDecoder(r.Body).Decode(&req)
		switch req.Path {
		case "tasks:list":
			w.Write([]byte(`{"status":"success","value":[{"text":"x"}]}`))
		case "tasks:empty":
			w.Write([]byte(`{"status":"success","value":[]}`))
		default:
			w.Write([]byte(`{"status":"error","errorMessage":"needs args"}`))
		}
	}))
	defer srv.Close()

	cfg := extractor.Config{Convex: extractor.Convex{
		URLs:      []string{srv.URL},
		Functions: []string{"tasks:list", "tasks:empty", "tasks:needsArgs"},
	}}
	got := ids(newTestProber().Convex(context.Background(), cfg))
	if got["convex-public-query-returns-data"] != 1 || len(got) != 1 {
		t.Fatalf("unexpected findings: %v", got)
	}
}

func TestSupabaseOpenAPIRequiresAcceptHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/v1/" {
			if r.Header.Get("Accept") != "application/openapi+json" {
				w.Write([]byte(`{}`)) // what a misconfigured request would see
				return
			}
			w.Write([]byte(`{"paths":{"/items":{}}}`))
			return
		}
		w.Header().Set("Content-Range", "0-0/3")
		w.Write([]byte(`[{"x":1}]`))
	}))
	defer srv.Close()

	p := newTestProber()
	got, err := p.supabaseTables(context.Background(), srv.URL, "key")
	if err != nil || len(got) != 1 || got[0] != "items" {
		t.Fatalf("expected table discovery via the openapi+json Accept header, got %v, %v", got, err)
	}
}

func TestSupabaseExtraTablesProbedWhenDiscoveryEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/v1/":
			w.Write([]byte(`{"paths":{}}`)) // nothing exposed to introspection
		case "/rest/v1/profiles":
			w.Header().Set("Content-Range", "0-0/42")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"id":1}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := newTestProber()
	p.ExtraTables = []string{"profiles"}
	cfg := extractor.Config{
		SupabaseURLs: []string{srv.URL},
		SupabaseKeys: []extractor.SupabaseKey{{Value: "anon-key", Role: extractor.RoleAnon}},
	}
	res := p.Supabase(context.Background(), cfg)
	if len(res.Findings) != 1 || res.Findings[0].ID != "supabase-table-exposed" {
		t.Fatalf("expected profiles (from --tables) to be probed and flagged, got %+v / warnings=%v", res.Findings, res.Warnings)
	}
}
