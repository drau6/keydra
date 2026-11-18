package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drau6/keydra/internal/extractor"
)

func newTestProber() *Prober {
	p := New(5*time.Second, "test")
	p.delay = 0
	// httptest servers listen on loopback; production scans block private
	// endpoints unless AllowPrivate is set explicitly.
	p.AllowPrivate = true
	return p
}

func TestSupabaseCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apikey") == "" {
			t.Error("apikey header missing")
		}
		switch r.URL.Path {
		case "/rest/v1/profiles":
			w.Header().Set("Content-Range", "0-0/1204")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(`[{"secret":"row data that must not be kept"}]`))
		case "/rest/v1/locked":
			w.Header().Set("Content-Range", "*/0")
			w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := newTestProber()
	status, n, err := p.supabaseCount(context.Background(), srv.URL, "key", "profiles")
	if err != nil || status != http.StatusPartialContent || n != 1204 {
		t.Fatalf("profiles: status=%d n=%d err=%v", status, n, err)
	}
	if _, n, _ = p.supabaseCount(context.Background(), srv.URL, "key", "locked"); n != 0 {
		t.Fatalf("locked table must report 0 visible rows, got %d", n)
	}
}

func TestRTDB(t *testing.T) {
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"users":true,"orders":true}`))
	}))
	defer open.Close()
	locked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer locked.Close()

	p := newTestProber()
	var res Result
	p.rtdb(context.Background(), open.URL, &res)
	p.rtdb(context.Background(), locked.URL, &res)
	if len(res.Findings) != 1 || res.Findings[0].ID != "firebase-rtdb-open" {
		t.Fatalf("expected exactly one open-rtdb finding, got %+v", res.Findings)
	}
}

func TestSeverityFor(t *testing.T) {
	if severityFor("customers") <= severityFor("todos") {
		t.Fatal("sensitive table names should rank higher")
	}
}

func TestSafeURLRejectsPrivateAndMetadata(t *testing.T) {
	p := New(5*time.Second, "test")
	for _, raw := range []string{
		"http://127.0.0.1:5432",
		"http://localhost:3000",
		"http://169.254.169.254/latest/meta-data",
		"http://metadata.google.internal",
		"file:///etc/passwd",
		"https://user:pass@example.com",
	} {
		if got, ok := p.safeURL(raw); ok {
			t.Errorf("safeURL(%q) = %q, true; want it rejected", raw, got)
		}
	}
	if got, ok := p.safeURL("https://example.com/api"); !ok || got != "https://example.com/api" {
		t.Errorf("safeURL(public) = %q, %v", got, ok)
	}

	p.AllowPrivate = true
	if _, ok := p.safeURL("http://127.0.0.1:5432"); !ok {
		t.Error("AllowPrivate should permit a local development backend")
	}
}

func TestSupabaseSkipsPrivateEndpoint(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Range", "0-0/5")
		w.Write([]byte(`[{"x":1}]`))
	}))
	defer srv.Close()

	p := New(5*time.Second, "test")
	p.delay = 0 // AllowPrivate stays false, like a scan of a public target
	cfg := extractor.Config{
		SupabaseURLs: []string{srv.URL},
		SupabaseKeys: []extractor.SupabaseKey{{Value: "anon-key", Role: extractor.RoleAnon}},
		Tables:       []string{"profiles"},
	}
	res := p.Supabase(context.Background(), cfg)

	if n := hits.Load(); n != 0 {
		t.Errorf("private endpoint was contacted %d times", n)
	}
	if len(res.Findings) != 0 {
		t.Errorf("private endpoint produced findings: %+v", res.Findings)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "non-public") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a skipped-endpoint warning, got %v", res.Warnings)
	}
}

func TestRedirectPolicyBlocksPrivateTargets(t *testing.T) {
	p := New(5*time.Second, "test")
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9000/secret", nil)
	if err := p.client.CheckRedirect(req, nil); err == nil || !strings.Contains(err.Error(), "redirect blocked") {
		t.Fatalf("private redirect should be blocked, got %v", err)
	}

	p.AllowPrivate = true
	if err := p.client.CheckRedirect(req, nil); err != nil {
		t.Fatalf("AllowPrivate should permit a local redirect, got %v", err)
	}
}

func TestRedirectPolicyCapsHops(t *testing.T) {
	p := New(5*time.Second, "test")
	req := httptest.NewRequest(http.MethodGet, "https://example.com/next", nil)
	if err := p.client.CheckRedirect(req, make([]*http.Request, 5)); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("redirect loop should be capped, got %v", err)
	}
}
