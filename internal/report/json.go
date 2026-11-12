package report

import (
	"encoding/json"
	"io"

	"github.com/drau6/keydra/internal/model"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *model.Report) error {
	if r.Findings == nil {
		r.Findings = []model.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// JSONAll writes multiple reports (--list mode) as an indented JSON array.
func JSONAll(w io.Writer, reports []*model.Report) error {
	for _, r := range reports {
		if r.Findings == nil {
			r.Findings = []model.Finding{}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}
