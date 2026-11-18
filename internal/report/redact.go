package report

import "github.com/drau6/keydra/internal/model"

// MaskSecret keeps a short recognizable prefix and suffix while hiding the
// body of a credential. Short values are fully redacted so no live key can be
// recovered from a shared report.
func MaskSecret(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= 8 {
		return "[redacted]"
	}
	return v[:4] + "…" + v[len(v)-4:]
}

// Redact masks the evidence of every finding marked as a credential. It is
// used by --redact for text and JSON output; SARIF always redacts credentials
// because those reports are commonly uploaded to third-party services.
func Redact(r *model.Report) {
	if r == nil {
		return
	}
	for i := range r.Findings {
		if r.Findings[i].Secret {
			r.Findings[i].Evidence = MaskSecret(r.Findings[i].Evidence)
		}
	}
}

// redactedEvidence returns evidence safe to include in a shared report.
func redactedEvidence(f model.Finding) string {
	if f.Secret {
		return MaskSecret(f.Evidence)
	}
	return f.Evidence
}
