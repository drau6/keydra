package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRepo(t *testing.T) {
	stripe := "sk_" + "live_" + strings.Repeat("r", 24)
	root := t.TempDir()
	put := func(rel, body string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	put(".gitignore", ".env*\n")
	put(".env", "STRIPE_SECRET_KEY="+stripe+"\n") // ignored: must not be flagged
	put("src/pay.js", "const key='"+stripe+"';\n")
	put("node_modules/dep/index.js", "const key='"+stripe+"';\n") // skipped dir

	rep, err := RunRepo(context.Background(), root, RepoOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode != "repo" || rep.Probed {
		t.Fatalf("mode=%q probed=%v", rep.Mode, rep.Probed)
	}
	var locs []string
	for _, f := range rep.Findings {
		if f.ID == "stripe-secret-key" {
			locs = append(locs, f.Location)
		}
	}
	if len(locs) != 1 || locs[0] != "src/pay.js" {
		t.Fatalf("stripe key should only be reported in src/pay.js, got %v", locs)
	}
}
