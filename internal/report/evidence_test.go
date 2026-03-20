package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

func TestGenerateEvidencePackage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")

	report := &models.AuditReport{
		ID:          "audit-test",
		Org:         "testorg",
		Repos:       []string{"testrepo"},
		Frameworks:  []models.Framework{models.FrameworkSOC2},
		GeneratedAt: time.Now(),
		Summary: models.ReportSummary{
			TotalFindings: 2,
			CountByStatus: map[models.Status]int{models.StatusFail: 1, models.StatusPass: 1},
		},
		CheckResults: []models.CheckResult{
			{
				CheckID: "test.check",
				Findings: []models.Finding{
					{
						CheckID:  "test.check",
						Controls: []models.ControlID{"SOC2-CC6.1"},
						Status:   models.StatusFail,
						Severity: models.SeverityHigh,
						Target:   "testorg/testrepo:ci.yml",
						Message:  "Test failure",
						Evidence: []models.Evidence{
							{
								Type:        models.EvidenceWorkflowFile,
								Description: "test evidence",
								URL:         "https://example.com/workflow",
								CollectedAt: time.Now(),
							},
						},
					},
					{
						CheckID:  "test.check",
						Controls: []models.ControlID{"SOC2-CC9.2"},
						Status:   models.StatusPass,
						Target:   "testorg/testrepo:ci.yml",
						Message:  "Test pass",
						Evidence: []models.Evidence{
							{
								Type:        models.EvidenceWorkflowFile,
								Description: "pass evidence",
								URL:         "https://example.com/pass",
								CollectedAt: time.Now(),
							},
						},
					},
				},
			},
		},
	}

	if err := GenerateEvidencePackage(dir, report); err != nil {
		t.Fatal(err)
	}

	// Check metadata file exists
	metaPath := filepath.Join(dir, "audit-metadata.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("reading metadata: %v", err)
	}
	var meta map[string]interface{}
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("invalid metadata JSON: %v", err)
	}
	if meta["id"] != "audit-test" {
		t.Errorf("metadata id: got %v", meta["id"])
	}

	// Check control directories exist
	cc61Dir := filepath.Join(dir, "SOC2-CC6.1")
	if _, err := os.Stat(cc61Dir); os.IsNotExist(err) {
		t.Error("expected SOC2-CC6.1 directory")
	}

	cc92Dir := filepath.Join(dir, "SOC2-CC9.2")
	if _, err := os.Stat(cc92Dir); os.IsNotExist(err) {
		t.Error("expected SOC2-CC9.2 directory")
	}

	// Check findings.json in control dir
	findingsPath := filepath.Join(cc61Dir, "findings.json")
	fdata, err := os.ReadFile(findingsPath)
	if err != nil {
		t.Fatalf("reading findings: %v", err)
	}
	var findings []models.Finding
	if err := json.Unmarshal(fdata, &findings); err != nil {
		t.Fatalf("invalid findings JSON: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding in CC6.1, got %d", len(findings))
	}

	// Check evidence file
	evPath := filepath.Join(cc61Dir, "evidence-0-0.json")
	if _, err := os.Stat(evPath); os.IsNotExist(err) {
		t.Error("expected evidence-0-0.json")
	}
}
