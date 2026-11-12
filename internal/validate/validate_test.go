package validate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckClassification(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		invalid []int
		jsonOK  bool
		want    Result
	}{
		{"2xx is active", http.StatusOK, `{}`, nil, false, Valid},
		{"401 is revoked", http.StatusUnauthorized, "", nil, false, Invalid},
		{"403 is revoked by default", http.StatusForbidden, "", nil, false, Invalid},
		{"403 is unknown when scope-limited (Stripe restricted)", http.StatusForbidden, "", []int{401}, false, Unknown},
		{"500 is unknown", http.StatusInternalServerError, "", nil, false, Unknown},
		{"429 is unknown", http.StatusTooManyRequests, "", nil, false, Unknown},
		{"slack ok=false is revoked", http.StatusOK, `{"ok":false,"error":"invalid_auth"}`, nil, true, Invalid},
		{"slack ok=true is active", http.StatusOK, `{"ok":true}`, nil, true, Valid},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		p := Provider{Endpoint: srv.URL, Bearer: true, Invalid: c.invalid, JSONOK: c.jsonOK}
		got := check(context.Background(), p, "test-value", time.Second)
		srv.Close()
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCheckSendsCredentials(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
	}))
	defer srv.Close()
	check(context.Background(), Provider{Endpoint: srv.URL, Bearer: true}, "test-value", time.Second)
	if auth != "Bearer test-value" {
		t.Errorf("bearer header not sent: %q", auth)
	}
	check(context.Background(), Provider{Endpoint: srv.URL, Bearer: true, AuthPrefix: "Bot"}, "test-value", time.Second)
	if auth != "Bot test-value" {
		t.Errorf("bot prefix not sent: %q", auth)
	}
}

func TestLookup(t *testing.T) {
	if _, ok := Lookup("openai-key"); !ok {
		t.Error("openai-key should have a validation endpoint")
	}
	if _, ok := Lookup("database-url-with-password"); ok {
		t.Error("rules without endpoints must not validate")
	}
}
