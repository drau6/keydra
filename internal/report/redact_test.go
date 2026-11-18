package report

import (
	"strings"
	"testing"

	"github.com/drau6/keydra/internal/model"
)

func TestMaskSecret(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"short", "[redacted]"},
		{"12345678", "[redacted]"},
		{"sk_live_abcdefghijklmnop", "sk_l…mnop"},
	}
	for _, c := range cases {
		if got := MaskSecret(c.in); got != c.want {
			t.Errorf("MaskSecret(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactOnlyMasksCredentials(t *testing.T) {
	long := "sk_live_abcdefghijklmnop"
	rep := &model.Report{Findings: []model.Finding{
		{ID: "stripe-secret-key", Evidence: long, Secret: true},
		{ID: "source-map-exposed", Evidence: "https://example.com/app.js.map"},
	}}

	Redact(rep)

	if got := rep.Findings[0].Evidence; got != "sk_l…mnop" {
		t.Errorf("secret evidence = %q, want it masked", got)
	}
	if got := rep.Findings[1].Evidence; got != "https://example.com/app.js.map" {
		t.Errorf("non-secret evidence = %q, want it untouched", got)
	}

	// Redacting twice must not mangle the already-masked value further.
	Redact(rep)
	if got := rep.Findings[0].Evidence; got != "sk_l…mnop" {
		t.Errorf("second Redact changed evidence to %q", got)
	}
}

func TestRedactedEvidence(t *testing.T) {
	if got := redactedEvidence(model.Finding{Evidence: "visible"}); got != "visible" {
		t.Errorf("non-secret evidence = %q", got)
	}
	if got := redactedEvidence(model.Finding{Evidence: "sk_live_abcdefghijklmnop", Secret: true}); strings.Contains(got, "abcdefghijklmnop") {
		t.Errorf("secret evidence leaked: %q", got)
	}
}
