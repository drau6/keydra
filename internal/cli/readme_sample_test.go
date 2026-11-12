package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestReadmeSampleOutput keeps the "What the output looks like" section in
// README.md honest: it rebuilds the documented fixture (a Supabase
// service_role key in JS, an unignored .env, a long random string), runs the
// scan exactly as documented and compares the rendered report with the fenced
// block in the README. Fails when the output format changes and the sample
// is not updated with it.
func TestReadmeSampleOutput(t *testing.T) {
	// Fixture values, byte-identical to the ones documented in the README.
	// Built at runtime so this file never contains a secret-shaped literal.
	const sbURL = "https://abcdefghij0123456789.supabase.co"
	enc := base64.RawURLEncoding.EncodeToString
	svc := enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"iss":"supabase","ref":"abcdefghij0123456789","role":"service_role","iat":1749818249,"exp":2065394249}`)) + "." +
		strings.Repeat("A", 8) + strings.Repeat("b", 8) + strings.Repeat("C", 8) +
		strings.Repeat("d", 8) + strings.Repeat("E", 8)

	dir := filepath.Join(t.TempDir(), "my-app")
	lib := filepath.Join(dir, "lib")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"lib/api.js": "export const supabase = createClient(\"" + sbURL + "\", \"" + svc + "\");\n" +
			"export const OPENAI = \"sk-proj-xxx\";\n",
		".env": "STRIPE_SECRET=STRIPE_SECRET_PLACEHOLDER\n",
		// .env must stay un-ignored so the repository check fires.
		".gitignore": "node_modules\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--repo", dir, "--no-color", "--no-banner", "--fail-on", "never"}, &out, &errOut)
	if code != ExitOK {
		t.Fatalf("fixture scan failed: exit %d, stderr: %s", code, errOut.String())
	}

	got := normalizeSample(out.String(), dir)

	want := normalizeSample(extractReadmeBlock(t), dir)
	if want == "" {
		t.Fatal("README has no fenced block under '### What the output looks like'")
	}
	if strings.TrimSpace(got) != want {
		t.Errorf("README sample output has drifted from real output.\n--- real output ---\n%s\n--- README block ---\n%s", got, want)
	}
}

// normalizeSample replaces path and timing details that legitimately vary
// between runs, so only the stable report layout is compared.
func normalizeSample(s, dir string) string {
	s = strings.ReplaceAll(s, dir, "my-app")
	return regexp.MustCompile(`· \d+ms`).ReplaceAllString(s, "· <duration>")
}

// extractReadmeBlock returns the first fenced code block after the sample
// heading in README.md.
func extractReadmeBlock(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	const heading = "### What the output looks like"
	i := strings.Index(string(b), heading)
	if i < 0 {
		return ""
	}
	rest := string(b)[i+len(heading):]
	open := strings.Index(rest, "```")
	if open < 0 {
		return ""
	}
	rest = rest[open+3:]
	close := strings.Index(rest, "```")
	if close < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:close])
}
