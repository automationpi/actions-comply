package engine

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/automationpi/actions-comply/internal/checks/changetrail"
	"github.com/automationpi/actions-comply/internal/checks/permissions"
	"github.com/automationpi/actions-comply/internal/checks/securedev"
	"github.com/automationpi/actions-comply/internal/checks/supplychain"
	"github.com/automationpi/actions-comply/pkg/models"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "workflows")
}

func TestEngine_FullAudit(t *testing.T) {
	e := New(
		&permissions.WorkflowOverage{},
		&supplychain.ActionBOM{},
		&supplychain.UnpinnedActions{},
		&securedev.ScanCoverage{},
		&changetrail.DeployApproval{},
	)

	opts := RunOptions{
		Org:         "testorg",
		Repo:        "testrepo",
		WorkflowDir: testdataDir(),
		Frameworks:  []models.Framework{models.FrameworkSOC2, models.FrameworkISO27001},
	}

	report, err := e.Run(opts)
	if err != nil {
		t.Fatal(err)
	}

	if report.Summary.TotalFindings == 0 {
		t.Error("expected findings from mixed fixture set")
	}

	// Should have 5 check results
	if len(report.CheckResults) != 5 {
		t.Errorf("expected 5 check results, got %d", len(report.CheckResults))
	}

	// Should have failures (write-all, unpinned, no-scanner, deploy-no-env)
	if report.Summary.CountByStatus[models.StatusFail] == 0 {
		t.Error("expected at least one failure")
	}

	// Should have critical severity (write-all, deploy-no-env)
	if report.Summary.CountBySeverity[models.SeverityCritical] == 0 {
		t.Error("expected at least one critical finding")
	}
}

func TestEngine_NoWorkflowDir(t *testing.T) {
	e := New()
	opts := RunOptions{Org: "test", Repo: "test"}

	_, err := e.Run(opts)
	if err == nil {
		t.Error("expected error when workflow-dir not set")
	}
}

func TestHasFindingsAtOrAbove(t *testing.T) {
	report := &models.AuditReport{
		CheckResults: []models.CheckResult{
			{
				Findings: []models.Finding{
					{Status: models.StatusFail, Severity: models.SeverityHigh},
					{Status: models.StatusPass, Severity: models.SeverityInfo},
				},
			},
		},
	}

	if !HasFindingsAtOrAbove(report, models.SeverityHigh) {
		t.Error("should find high severity failure")
	}
	if HasFindingsAtOrAbove(report, models.SeverityCritical) {
		t.Error("should not find critical severity failure")
	}
	if !HasFindingsAtOrAbove(report, models.SeverityMedium) {
		t.Error("should find findings at medium (high >= medium)")
	}
}
