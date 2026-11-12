package scanner

import (
	"context"
	"sort"
	"time"

	"github.com/drau6/keydra/internal/detectors"
	"github.com/drau6/keydra/internal/extractor"
	"github.com/drau6/keydra/internal/fetcher"
	"github.com/drau6/keydra/internal/model"
	"github.com/drau6/keydra/internal/validate"
)

// collector accumulates de-duplicated findings into a report.
type collector struct {
	rep  *model.Report
	seen map[string]bool
	// validate enables opt-in live key checks. Records pair each secret
	// finding's index with its unmasked value; indices are stable until
	// finish() sorts, and validation runs before that sort.
	validate bool
	vTimeout time.Duration
	checkFn  validateFunc
	raw      []secretRecord
}

// validateFunc is the live-check call, injectable for tests.
type validateFunc func(ctx context.Context, ruleID, value string, timeout time.Duration) validate.Result

type secretRecord struct {
	index int // position in rep.Findings at recording time
	value string
}

func newCollector(rep *model.Report) *collector {
	return &collector{rep: rep, seen: map[string]bool{}}
}

// enableValidation opts this scan into live credential checks.
func (c *collector) enableValidation(timeout time.Duration) {
	c.validate = true
	c.vTimeout = timeout
	c.checkFn = validate.Check
}

func (c *collector) add(f model.Finding) *model.Finding {
	key := f.ID + "\x00" + f.Title + "\x00" + f.Evidence + "\x00" + f.Location
	if c.seen[key] {
		return nil
	}
	c.seen[key] = true
	c.rep.Findings = append(c.rep.Findings, f)
	return &c.rep.Findings[len(c.rep.Findings)-1]
}

// finish runs opt-in validation (before sorting: only the unsorted indices
// are valid), sorts findings by severity and stamps the duration.
func (c *collector) finish(ctx context.Context, start time.Time) {
	if c.validate {
		c.runValidation(ctx)
	}
	sort.SliceStable(c.rep.Findings, func(i, j int) bool {
		return c.rep.Findings[i].Severity > c.rep.Findings[j].Severity
	})
	c.rep.Duration = time.Since(start)
}

// runValidation asks each provider, once per unique key, whether the leaked
// credential is still active, and records the answer on the finding.
func (c *collector) runValidation(ctx context.Context) {
	type checkedKey struct{ id, value string }
	checked := map[checkedKey]validate.Result{}
	for _, rec := range c.raw {
		f := &c.rep.Findings[rec.index]
		if _, ok := validate.Lookup(f.ID); !ok {
			continue
		}
		k := checkedKey{f.ID, rec.value}
		res, done := checked[k]
		if !done {
			res = c.checkFn(ctx, f.ID, rec.value, c.vTimeout)
			checked[k] = res
		}
		f.Verified = res.String()
	}
}

// analyze runs the static checks shared by web and repo mode over assets and
// returns the backend configuration discovered in them.
func (c *collector) analyze(assets []fetcher.Asset) extractor.Config {
	var cfg extractor.Config
	for _, a := range assets {
		for _, m := range detectors.Scan(a.Body) {
			f := model.Finding{
				ID:       m.Rule.ID,
				Title:    m.Rule.Name + " exposed in client code",
				Severity: m.Rule.Severity,
				Category: "Secrets",
				Detail:   "This value ships to every visitor's browser and can be copied by anyone.",
				Evidence: m.Value,
				Location: a.URL,
				Fix:      m.Rule.Fix,
			}
			if added := c.add(f); added != nil && c.validate {
				c.raw = append(c.raw, secretRecord{index: len(c.rep.Findings) - 1, value: m.Value})
			}
		}
		cfg = cfg.Merge(extractor.Extract(a.Body))

		if a.Kind == fetcher.KindSourceMap {
			c.add(model.Finding{
				ID:       "source-map-exposed",
				Title:    "Source map is publicly downloadable",
				Severity: model.Low,
				Category: "Exposure",
				Detail:   "Anyone can reconstruct your original source code, including comments and internal endpoints.",
				Location: a.URL,
				Fix:      "Disable production source maps (e.g. Vite: build.sourcemap=false, Next.js: productionBrowserSourceMaps=false) or upload them privately to your error tracker.",
			})
		}
	}

	for _, k := range cfg.SupabaseKeys {
		if k.Role == extractor.RoleServiceRole || k.Role == extractor.RoleSecret {
			c.add(model.Finding{
				ID:       "supabase-service-key-exposed",
				Title:    "Supabase service/secret key exposed in client code",
				Severity: model.Critical,
				Category: "Supabase",
				Detail:   "This key bypasses Row Level Security. Whoever holds it has full read/write access to the whole database.",
				Evidence: k.Value,
				Fix:      "Rotate the key in Supabase → Project Settings → API now, remove it from the frontend and use it only from server-side code.",
			})
		}
	}
	return cfg
}

// backendsFound lists the backends present in cfg, for notes.
func backendsFound(cfg extractor.Config) []string {
	var out []string
	if cfg.HasSupabase() {
		out = append(out, "Supabase")
	}
	if cfg.HasFirebase() {
		out = append(out, "Firebase")
	}
	if cfg.HasAppwrite() {
		out = append(out, "Appwrite")
	}
	if cfg.HasPocketBase() {
		out = append(out, "PocketBase")
	}
	if cfg.HasConvex() {
		out = append(out, "Convex")
	}
	return out
}
