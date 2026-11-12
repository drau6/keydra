package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/drau6/keydra/internal/model"
)

func TestSARIF(t *testing.T) {
	rep := sample()
	rep.Mode = "repo"
	rep.Findings = append(rep.Findings, model.Finding{
		ID: "a", Title: "Another open table", Severity: model.High, Category: "Supabase", Detail: "d3", Location: "supabase/m.sql",
	})

	var buf bytes.Buffer
	if err := SARIF(&buf, rep, "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Version string `json:"version"`
					Rules   []struct {
						ID         string `json:"id"`
						DefaultCfg struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Fingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Version != "v1.2.3" || len(run.Results) != 3 {
		t.Fatalf("driver/results: %+v", run)
	}
	// Rule "a" is used by a critical and a high finding: it must carry the max severity.
	for _, rule := range run.Tool.Driver.Rules {
		if rule.ID == "a" && (rule.DefaultCfg.Level != "error" || rule.Properties.SecuritySeverity != "9.5") {
			t.Errorf("rule a: %+v", rule)
		}
	}
	levels := map[string]string{}
	for _, res := range run.Results {
		levels[res.RuleID+res.Locations[0].Physical.Artifact.URI] = res.Level
		if res.Locations[0].Physical.Region.StartLine != 1 || res.Fingerprints["keydra/v1"] == "" {
			t.Errorf("missing region or fingerprint: %+v", res)
		}
	}
	if levels["asupabase/m.sql"] != "error" || levels["b."] != "note" {
		t.Errorf("levels: %v", levels)
	}
}
