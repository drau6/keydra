package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"

	"github.com/drau6/keydra/internal/detectors"
	"github.com/drau6/keydra/internal/model"
)

// SARIF 2.1.0 output, suitable for GitHub code scanning
// (github/codeql-action/upload-sarif). Findings carry file-level locations
// only: Keydra does not track line numbers, so every region starts at line 1.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	Help             *sarifText     `json:"help,omitempty"`
	DefaultConfig    sarifConfig    `json:"defaultConfiguration"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifText         `json:"message"`
	Locations    []sarifLocation   `json:"locations"`
	Fingerprints map[string]string `json:"partialFingerprints"`
	Properties   map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
	Region   sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.Critical, model.High:
		return "error"
	case model.Medium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps to GitHub's CVSS-like buckets (critical ≥ 9, high ≥ 7, medium ≥ 4).
func securitySeverity(s model.Severity) string {
	switch s {
	case model.Critical:
		return "9.5"
	case model.High:
		return "8.0"
	case model.Medium:
		return "5.5"
	case model.Low:
		return "3.0"
	default:
		return "1.0"
	}
}

// SARIF writes the report as a SARIF 2.1.0 log with a single run.
func SARIF(w io.Writer, r *model.Report, version string) error {
	return SARIFAll(w, []*model.Report{r}, version)
}

// SARIFAll writes one SARIF run per report (--list mode).
func SARIFAll(w io.Writer, reports []*model.Report, version string) error {
	names := map[string]string{}
	for _, e := range detectors.Catalog() {
		names[e.ID] = e.Name
	}

	runs := make([]sarifRun, 0, len(reports))
	for _, r := range reports {
		runs = append(runs, buildSarifRun(r, names, version))
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    runs,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// buildSarifRun builds one run's results and rule table from a report.
func buildSarifRun(r *model.Report, names map[string]string, version string) sarifRun {
	rules := map[string]*sarifRule{}
	maxSev := map[string]model.Severity{}
	results := []sarifResult{}

	for _, f := range r.Findings {
		if _, ok := rules[f.ID]; !ok {
			desc := names[f.ID]
			if desc == "" {
				desc = f.Title
			}
			rule := &sarifRule{
				ID:               f.ID,
				ShortDescription: sarifText{Text: desc},
				Properties:       sarifRuleProps{Tags: []string{"security", f.Category}},
			}
			if f.Fix != "" {
				rule.Help = &sarifText{Text: f.Fix}
			}
			rules[f.ID] = rule
			maxSev[f.ID] = f.Severity
		} else if f.Severity > maxSev[f.ID] {
			maxSev[f.ID] = f.Severity
		}

		uri := f.Location
		if uri == "" {
			uri = r.Target
			if r.Mode == "repo" {
				uri = "."
			}
		}
		sum := sha256.Sum256([]byte(f.ID + "|" + uri + "|" + f.Title + "|" + f.Evidence))
		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title + ". " + f.Detail},
			Locations: []sarifLocation{{Physical: sarifPhysical{
				Artifact: sarifArtifact{URI: uri},
				Region:   sarifRegion{StartLine: 1},
			}}},
			Fingerprints: map[string]string{"keydra/v1": hex.EncodeToString(sum[:16])},
		}
		if f.Evidence != "" {
			res.Properties = map[string]string{"evidence": f.Evidence}
		}
		results = append(results, res)
	}

	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	outRules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rule := rules[id]
		rule.DefaultConfig = sarifConfig{Level: sarifLevel(maxSev[id])}
		rule.Properties.SecuritySeverity = securitySeverity(maxSev[id])
		outRules = append(outRules, *rule)
	}

	return sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "keydra",
			Version:        version,
			InformationURI: "https://github.com/drau6/keydra",
			Rules:          outRules,
		}},
		Results: results,
	}
}
