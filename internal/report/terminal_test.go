package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/drau6/keydra/internal/model"
)

func sample() *model.Report {
	rep := &model.Report{
		Mode: "web", Target: "https://example.com", FilesScanned: 3, Duration: 120 * time.Millisecond,
		Warnings: []string{"something to note"},
		Findings: []model.Finding{
			{ID: "a", Title: "Open table", Severity: model.Critical, Category: "Supabase", Detail: "d1", Evidence: "e1", Location: "https://x", Fix: "line1\nline2"},
			{ID: "b", Title: "Source map", Severity: model.Low, Category: "Exposure", Detail: "d2"},
		},
	}
	return rep
}

func TestTerminalPlain(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, sample(), Style{Color: false}, false)
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Fatal("plain output must not contain ANSI escapes")
	}
	for _, want := range []string{"[Supabase]", "Open table", "use -v for the full fix"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "line2") {
		t.Error("non-verbose output must truncate multi-line fixes")
	}
}

func TestTerminalColorAndVerbose(t *testing.T) {
	var buf bytes.Buffer
	st := Style{Color: true, Version: "v9.9.9"}
	Banner(&buf, st)
	Terminal(&buf, sample(), st, true)
	out := buf.String()
	if !strings.Contains(out, "\x1b[") || !strings.Contains(out, "v9.9.9") || !strings.Contains(out, "line2") {
		t.Fatalf("colored verbose output incomplete:\n%q", out)
	}
}

func TestArtBanner(t *testing.T) {
	lines := strings.Split(strings.Trim(Art, "\n"), "\n")
	first := ""
	for _, line := range lines {
		if s := strings.TrimRight(line, " "); strings.TrimSpace(s) != "" {
			first = s
			break
		}
	}
	if first == "" {
		t.Fatal("Art is empty; put the banner art in the Art string")
	}

	var plain, colored bytes.Buffer
	Banner(&plain, Style{Art: true, Version: "v1.0.0"})
	Banner(&colored, Style{Art: true, Color: true, Version: "v1.0.0"})
	if strings.Contains(plain.String(), "\x1b[") {
		t.Error("art banner without color must not contain escapes")
	}
	for _, want := range []string{first, "v1.0.0", "leaking"} {
		if !strings.Contains(plain.String(), want) {
			t.Errorf("art banner missing %q", want)
		}
	}
	if !strings.Contains(colored.String(), "\x1b[38;5;") {
		t.Error("colored art banner should use 256-color escapes")
	}
}
