// Package model defines the shared data types passed between packages.
package model

import "time"

// Severity ranks how bad a finding is.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

// MarshalText makes severities render as words in JSON output.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity converts a name such as "high" into a Severity.
func ParseSeverity(name string) (Severity, bool) {
	for i, n := range severityNames {
		if n == name {
			return Severity(i), true
		}
	}
	return Info, false
}

// Finding is a single issue discovered during a scan.
type Finding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Detail   string   `json:"detail"`
	Evidence string   `json:"evidence,omitempty"` // matched secret value, shown in full
	Location string   `json:"location,omitempty"`
	Fix      string   `json:"fix,omitempty"`
	// Verified is set by opt-in live key validation: "active" (the provider
	// confirmed the credential works), "rejected" (revoked or fake) or
	// "unverified" (provider unreachable or unexpected answer).
	Verified string `json:"verified,omitempty"`
}

// Report is the full result of scanning one target.
type Report struct {
	Mode         string        `json:"mode"` // "web" or "repo"
	Target       string        `json:"target"`
	ScannedAt    time.Time     `json:"scanned_at"`
	Duration     time.Duration `json:"duration_ns"`
	PagesScanned int           `json:"pages_scanned,omitempty"`
	FilesScanned int           `json:"files_scanned"`
	Probed       bool          `json:"probed"`
	Warnings     []string      `json:"warnings,omitempty"`
	Findings     []Finding     `json:"findings"`
}
