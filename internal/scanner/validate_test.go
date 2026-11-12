package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/drau6/keydra/internal/model"
	"github.com/drau6/keydra/internal/validate"
)

// TestValidationAttribution guards two attribution bugs in live key
// validation: pointers into rep.Findings go stale when the slice grows
// (append reallocation) and when finish() sorts it. Verdicts must land on
// the finding that owns the raw secret, regardless of either.
func TestValidationAttribution(t *testing.T) {
	rep := &model.Report{}
	col := newCollector(rep)
	col.enableValidation(time.Second)
	col.checkFn = func(_ context.Context, _ string, value string, _ time.Duration) validate.Result {
		if value == "low-value" {
			return validate.Invalid
		}
		return validate.Valid
	}

	addSecret := func(id string, sev model.Severity, value string) {
		f := model.Finding{ID: id, Title: id, Severity: sev, Category: "Secrets"}
		if added := col.add(f); added != nil && col.validate {
			col.raw = append(col.raw, secretRecord{index: len(col.rep.Findings) - 1, value: value})
		}
	}
	// Recorded out of severity order: sorting will swap the slice entries.
	addSecret("huggingface-token", model.Medium, "low-value") // provider-mapped → Invalid
	addSecret("github-token", model.Critical, "crit-value")   // provider-mapped → Valid
	// Appends after recording, forcing the backing array to reallocate
	// (mirrors probe/repo-check findings arriving later).
	col.add(model.Finding{ID: "x", Title: "x", Severity: model.Info})
	col.add(model.Finding{ID: "y", Title: "y", Severity: model.Info})

	col.finish(context.Background(), time.Now())

	want := map[string]validate.Result{
		"github-token":      validate.Valid,
		"huggingface-token": validate.Invalid,
	}
	for _, f := range rep.Findings {
		res, checked := want[f.ID]
		if !checked {
			continue
		}
		if f.Verified != res.String() {
			t.Errorf("%s: verified=%q, want %q", f.ID, f.Verified, res.String())
		}
	}
	if rep.Findings[0].ID != "github-token" {
		t.Errorf("findings not sorted by severity: first is %s", rep.Findings[0].ID)
	}
}
