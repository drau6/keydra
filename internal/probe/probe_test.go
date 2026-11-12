package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestProber() *Prober {
	p := New(5*time.Second, "test")
	p.delay = 0
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
