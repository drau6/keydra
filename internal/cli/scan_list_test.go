package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drau6/keydra/internal/model"
)

// b64 builds a URL-safe base64 string at runtime so no secret-shaped literal
// lives in this file.
func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestScanListJSON(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><script src="/app.js"></script></html>`))
	}))
	defer srv1.Close()
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><body>hi</body></html>`))
	})
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()

	list := filepath.Join(t.TempDir(), "urls.txt")
	content := "# my own sites\n\n" + srv1.URL + "\n" + srv2.URL + "\n"
	if err := os.WriteFile(list, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--list", list, "--format", "json", "--no-color", "--no-probe"}, &out, &errOut)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	var reports []*model.Report
	if err := json.Unmarshal(out.Bytes(), &reports); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out.String())
	}
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2", len(reports))
	}
	if reports[0].Target != srv1.URL || reports[1].Target != srv2.URL {
		t.Errorf("wrong targets: %s, %s", reports[0].Target, reports[1].Target)
	}
}

func TestScanListSARIFFailsOnFindings(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	svc := enc([]byte(`{"alg":"HS256"}`)) + "." +
		enc([]byte(`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role"}`)) + "." + strings.Repeat("s", 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`const k="` + svc + `";`))
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(list, []byte(srv.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--list", list, "--format", "sarif", "--no-color", "--no-probe"}, &out, &errOut)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d; stderr: %s", code, ExitFindings, errOut.String())
	}
	var log struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &log); err != nil {
		t.Fatalf("bad sarif: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Errorf("got %d runs, want 1", len(log.Runs))
	}
}

func TestScanListContinueOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()

	// Port 1 is unassigned; the connection is refused quickly.
	list := filepath.Join(t.TempDir(), "urls.txt")
	content := srv.URL + "\nhttp://127.0.0.1:1/\n"
	if err := os.WriteFile(list, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--list", list, "--format", "json", "--no-color", "--no-probe", "--timeout", "3s"}, &out, &errOut)
	if code != ExitError {
		t.Fatalf("exit %d, want %d (one target failed)", code, ExitError)
	}
	var reports []*model.Report
	if err := json.Unmarshal(out.Bytes(), &reports); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out.String())
	}
	if len(reports) != 1 || reports[0].Target != srv.URL {
		t.Fatalf("expected only the healthy target in output, got %+v", reports)
	}
	if !strings.Contains(errOut.String(), "127.0.0.1:1") {
		t.Errorf("failed target not reported on stderr: %s", errOut.String())
	}
}

func TestScanListAllFailed(t *testing.T) {
	list := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(list, []byte("http://127.0.0.1:1/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--list", list, "--no-color", "--no-probe", "--timeout", "3s"}, &out, &errOut)
	if code != ExitError {
		t.Errorf("exit %d, want %d", code, ExitError)
	}
	if strings.Contains(out.String(), "files scanned") {
		t.Errorf("stdout must stay report-free when no scan succeeded, got %q", out.String())
	}
}

func TestScanListTextSummary(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><body>clean</body></html>`))
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`const s="` + strings.Repeat("sk_live_", 1)[:8] + strings.Repeat("a", 24) + `";`))
	}))
	defer srv2.Close()

	list := filepath.Join(t.TempDir(), "urls.txt")
	content := srv1.URL + "\n" + srv2.URL + "\n"
	if err := os.WriteFile(list, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--list", list, "--no-color", "--no-banner", "--no-probe"}, &out, &errOut)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d (findings on one target)", code, ExitFindings)
	}
	text := out.String()
	for _, want := range []string{srv1.URL, srv2.URL, "2 of 2 targets scanned · 1 clean · 1 with findings"} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
}

func TestScanListErrors(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("# nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	over := filepath.Join(dir, "over.txt")
	var sb strings.Builder
	for i := 0; i < maxListTargets+1; i++ {
		fmt.Fprintf(&sb, "https://host%d.example.com\n", i)
	}
	if err := os.WriteFile(over, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
	}{
		{"empty list", []string{"--list", empty}},
		{"list plus url", []string{"--list", empty, "https://example.com"}},
		{"list plus repo", []string{"--list", empty, "--repo", "."}},
		{"over the cap", []string{"--list", over}},
		{"missing file", []string{"--list", filepath.Join(dir, "nope.txt")}},
	}
	var out, errOut bytes.Buffer
	for _, c := range cases {
		if code := runScan(context.Background(), c.args, &out, &errOut); code != ExitError {
			t.Errorf("%s: exit %d, want %d", c.name, code, ExitError)
		}
	}
}
