package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drau6/keydra/internal/model"
)

// TestScanRepoModeRegression guards against a silent exit-2 regression: when
// the scan loop became targets-driven for --list, repo mode was left with an
// empty targets slice, so the loop never ran and runScan returned ExitError
// without printing anything.
func TestScanRepoModeRegression(t *testing.T) {
	dir := t.TempDir()

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--repo", dir, "--no-color", "--no-banner", "--fail-on", "never"}, &out, &errOut)
	if code != ExitOK {
		t.Fatalf("clean repo: exit %d, stderr: %q, stdout: %q", code, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), dir) {
		t.Errorf("repo scan produced no report on stdout: %q", out.String())
	}
}

// TestScanRepoErrorReported checks that a failing repo scan reports the error
// on stderr instead of exiting silently. The banner is printed immediately
// (before the scan runs), but no report appears on stdout.
func TestScanRepoErrorReported(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--repo", missing, "--no-color", "--no-banner"}, &out, &errOut)
	if code != ExitError {
		t.Fatalf("missing repo: exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(out.String(), "KEYDRA") {
		t.Errorf("banner should print before the scan, got %q", out.String())
	}
	if strings.Contains(out.String(), "files scanned") {
		t.Errorf("no report should be rendered for a failed target, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), missing) {
		t.Errorf("stderr should name the failing target, got %q", errOut.String())
	}
}

func TestScanRepoHonorsMaxFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.js", "b.js", "c.js"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("const x = 1;\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{
		"--repo", dir, "--max-files", "1", "--json", "--no-banner", "--no-color", "--fail-on", "never",
	}, &out, &errOut)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr: %q", code, errOut.String())
	}
	var rep model.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode report: %v\n%s", err, out.String())
	}
	if rep.FilesScanned != 1 {
		t.Errorf("files_scanned = %d, want 1", rep.FilesScanned)
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "1-file limit") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing truncation warning, got %v", rep.Warnings)
	}
}

func TestScanRejectsNonPositiveLimits(t *testing.T) {
	cases := []struct {
		name string
		arg  string
		want string
	}{
		{"timeout", "--timeout=0", "--timeout must be greater than zero"},
		{"max-files", "--max-files=0", "--max-files must be at least 1"},
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		code := runScan(context.Background(), []string{"--repo", t.TempDir(), c.arg, "--no-banner", "--no-color"}, &out, &errOut)
		if code != ExitError {
			t.Errorf("%s: exit %d, want %d", c.name, code, ExitError)
		}
		if !strings.Contains(errOut.String(), c.want) {
			t.Errorf("%s: stderr %q missing %q", c.name, errOut.String(), c.want)
		}
	}
}
