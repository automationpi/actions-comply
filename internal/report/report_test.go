package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

func sampleReport() *models.AuditReport {
	now := time.Now()
	return &models.AuditReport{
		ID:          "audit-123",
		Org:         "testorg",
		Repos:       []string{"testrepo"},
		Frameworks:  []models.Framework{models.FrameworkSOC2},
		GeneratedAt: now,
		Summary: models.ReportSummary{
			TotalFindings:   3,
			CountByStatus:   map[models.Status]int{models.StatusPass: 1, models.StatusFail: 1, models.StatusWarn: 1},
			CountBySeverity: map[models.Severity]int{models.SeverityCritical: 1, models.SeverityHigh: 1, models.SeverityInfo: 1},
			ControlStatus:   map[models.ControlID]models.Status{"SOC2-CC6.1": models.StatusFail},
		},
		CheckResults: []models.CheckResult{
			{
				CheckID: "test.check",
				Findings: []models.Finding{
					{
						CheckID: "test.check", Status: models.StatusFail, Severity: models.SeverityCritical,
						Target: "testorg/testrepo:ci.yml", Message: "Something failed",
						Detail: "Fix this", Evidence: []models.Evidence{{URL: "https://example.com", Description: "evidence"}},
						EvaluatedAt: now,
					},
					{
						CheckID: "test.check", Status: models.StatusPass, Severity: models.SeverityInfo,
						Target: "testorg/testrepo:ci.yml", Message: "Something passed",
						Evidence:    []models.Evidence{{URL: "https://example.com", Description: "evidence"}},
						EvaluatedAt: now,
					},
					{
						CheckID: "test.check", Status: models.StatusWarn, Severity: models.SeverityHigh,
						Target: "testorg/testrepo:ci.yml", Message: "Something warned",
						Evidence:    []models.Evidence{{URL: "https://example.com", Description: "evidence"}},
						EvaluatedAt: now,
					},
				},
			},
		},
	}
}

func TestRenderText(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderText(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	checks := []string{
		"actions-comply Audit Report",
		"SCORECARD",
		"Total findings: 3",
		"CHECK SUMMARY",
		"Something failed",
		"Fix this",
		"1 passed",
	}
	for _, want := range checks {
		if !strings.Contains(output, want) {
			t.Errorf("text output missing %q", want)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}

	// Verify valid JSON
	var parsed models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.ID != "audit-123" {
		t.Errorf("ID: got %q, want %q", parsed.ID, "audit-123")
	}
	if parsed.Summary.TotalFindings != 3 {
		t.Errorf("total findings: got %d, want 3", parsed.Summary.TotalFindings)
	}
}

func TestRenderSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderSummary(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	checks := []string{
		"# actions-comply Audit Report",
		"## Scorecard",
		"## Control Status",
		"## Findings",
		"Something failed",
	}
	for _, want := range checks {
		if !strings.Contains(output, want) {
			t.Errorf("summary output missing %q", want)
		}
	}
}
