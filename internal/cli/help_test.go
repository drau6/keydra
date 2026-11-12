package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestBannerInHelpAndUsage checks that bare `keydra` and `keydra -h` both
// show the banner (title + permission notice) before the usage text.
func TestBannerInHelpAndUsage(t *testing.T) {
	cases := []struct {
		name string
		args []string
		dest func(out, errOut *bytes.Buffer) string // which buffer to inspect
		code int
	}{
		{"bare invocation", nil, func(out, errOut *bytes.Buffer) string { return errOut.String() }, ExitError},
		{"-h", []string{"-h"}, func(out, errOut *bytes.Buffer) string { return out.String() }, ExitOK},
		{"--help", []string{"--help"}, func(out, errOut *bytes.Buffer) string { return out.String() }, ExitOK},
		{"help", []string{"help"}, func(out, errOut *bytes.Buffer) string { return out.String() }, ExitOK},
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), c.args, &out, &errOut); code != c.code {
			t.Errorf("%s: exit %d, want %d", c.name, code, c.code)
		}
		got := c.dest(&out, &errOut)
		for _, want := range []string{"KEYDRA", "keydra: only scan apps you own", "Usage:"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: missing %q in:\n%s", c.name, want, got)
			}
		}
		if strings.Contains(out.String(), "\x1b[") {
			t.Errorf("%s: piped output must not contain ANSI escapes", c.name)
		}
	}
}

// TestBareWordIsUnknownCommand checks that `keydra asd` — a bare word with
// no scheme and no dot — is rejected as a mistyped command instead of being
// attempted as a URL (which used to surface a raw DNS error).
func TestBareWordIsUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"asd"}, &out, &errOut); code != ExitError {
		t.Fatalf("exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(errOut.String(), `unknown command or flag "asd"`) {
		t.Errorf("expected unknown-command error, got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "KEYDRA") {
		t.Errorf("error path should still show the banner, got %q", out.String())
	}
}

// TestLooksLikeTarget keeps the bare-URL shortcut working for plausible
// targets while refusing bare words.
func TestLooksLikeTarget(t *testing.T) {
	yes := []string{"example.com", "https://x.co", "http://localhost:3000", "localhost", "localhost:8080", "127.0.0.1:9000", "sub.domain.io/app"}
	no := []string{"asd", "rules2", "scan_rules", "v1"}
	for _, s := range yes {
		if !looksLikeTarget(s) {
			t.Errorf("%q should look like a target", s)
		}
	}
	for _, s := range no {
		if looksLikeTarget(s) {
			t.Errorf("%q should not look like a target", s)
		}
	}
}
