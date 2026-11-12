package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
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
