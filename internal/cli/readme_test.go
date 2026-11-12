package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/drau6/keydra/internal/detectors"
)

// The README detector tables are generated from the catalog. This test fails
// when someone adds a check but forgets to run `make docs`.
func TestReadmeListsEveryCheck(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	start := strings.Index(readme, "<!-- detectors:start -->")
	end := strings.Index(readme, "<!-- detectors:end -->")
	if start < 0 || end < start {
		t.Fatal("README is missing the detectors:start / detectors:end markers")
	}
	section := readme[start:end]
	for _, e := range detectors.Catalog() {
		if !strings.Contains(section, "`"+e.ID+"`") {
			t.Errorf("README is missing %s; run `make docs`", e.ID)
		}
	}
}
