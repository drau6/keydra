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

// TestScanRedactJSON checks that --redact masks credential evidence in
// machine-readable output while leaving the report itself usable.
func TestScanRedactJSON(t *testing.T) {
	stripe := "sk_" + "live_" + strings.Repeat("z", 24)

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib", "api.js"),
		[]byte("export const STRIPE = \""+stripe+"\";\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scan := func(extra ...string) (string, int) {
		t.Helper()
		var out, errOut bytes.Buffer
		args := append([]string{"--repo", dir, "--json", "--fail-on", "never"}, extra...)
		code := runScan(context.Background(), args, &out, &errOut)
		if code != ExitOK {
			t.Fatalf("scan failed: exit %d, stderr: %s", code, errOut.String())
		}
		return out.String(), code
	}

	full, _ := scan()
	if !strings.Contains(full, stripe) {
		t.Fatal("without --redact the full credential should be visible")
	}

	masked, _ := scan("--redact")
	if strings.Contains(masked, stripe) || strings.Contains(masked, strings.Repeat("z", 24)) {
		t.Fatalf("--redact leaked the full credential:\n%s", masked)
	}
	if !strings.Contains(masked, "sk_l…zzzz") {
		t.Errorf("--redact should keep a recognizable masked prefix/suffix:\n%s", masked)
	}
	if strings.Contains(masked, `"secret"`) {
		t.Errorf("the internal Secret marker must not be serialized:\n%s", masked)
	}

	var rep model.Report
	if err := json.Unmarshal([]byte(masked), &rep); err != nil {
		t.Fatalf("redacted JSON no longer parses: %v\n%s", err, masked)
	}
	found := false
	for _, f := range rep.Findings {
		if f.ID == "stripe-secret-key" {
			found = true
			if f.Severity != model.Critical {
				t.Errorf("severity round-trip failed: %v", f.Severity)
			}
			if f.Evidence == "" || f.Evidence == stripe {
				t.Errorf("credential evidence was not masked: %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Errorf("stripe-secret-key finding missing from %s", masked)
	}
}
