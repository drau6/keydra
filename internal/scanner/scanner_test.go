package scanner

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/drau6/keydra/internal/fetcher"
	"github.com/drau6/keydra/internal/model"
)

func TestNormalizeURL(t *testing.T) {
	got, err := NormalizeURL("example.com/app")
	if err != nil || got != "https://example.com/app" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := NormalizeURL("ftp://example.com"); err == nil {
		t.Fatal("ftp must be rejected")
	}
}

// TestAnonKeyStillReported keeps the Supabase anon key visible: the user
// wants every key found in client code to surface as a finding, including
// public-by-design anon keys, so the entropy heuristic must report the JWT.
func TestAnonKeyStillReported(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	anon := enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"iss":"supabase","ref":"alqavrioetqfylwkqmak","role":"anon","iat":1749818249,"exp":2065394249}`)) + "." + strings.Repeat("V", 20)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><script src="/supabase-env.js"></script></html>`))
	})
	mux.HandleFunc("/supabase-env.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("window.SUPABASE_URL = 'https://alqavrioetqfylwkqmak.supabase.co';\nwindow.SUPABASE_ANON_KEY = '" + anon + "';\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rep, err := Run(context.Background(), srv.URL, Options{
		Probe: false, // no live Supabase backend behind this fake host
		Fetch: fetcher.Options{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.ID == "high-entropy-string" {
			found = true
			if f.Evidence != anon {
				t.Errorf("evidence should be the full key, got %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Error("anon key must still be reported as a finding")
	}
}

func TestRunStaticFindings(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	svc := enc([]byte(`{"alg":"HS256"}`)) + "." +
		enc([]byte(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role"}`)) + "." + strings.Repeat("s", 20)
	stripe := "sk_" + "live_" + strings.Repeat("z", 24)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><script src="/assets/app.js"></script></html>`))
	})
	mux.HandleFunc("/assets/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`const s="` + stripe + `"; const k="` + svc + `";`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rep, err := Run(context.Background(), srv.URL, Options{
		Probe: false,
		Fetch: fetcher.Options{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]model.Severity{}
	for _, f := range rep.Findings {
		ids[f.ID] = f.Severity
		if f.Evidence == "" {
			t.Errorf("finding %s has empty evidence", f.ID)
		}
	}
	if ids["stripe-secret-key"] != model.Critical || ids["supabase-service-key-exposed"] != model.Critical {
		t.Fatalf("missing critical findings: %v", ids)
	}
}
