package securedev

import (
	"testing"

	"github.com/automationpi/actions-comply/pkg/models"
)

func TestScanCoverage_WithScanner(t *testing.T) {
	check := &ScanCoverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/ci.yml",
				Triggers: []string{"pull_request"},
				Jobs: map[string]*models.Job{
					"scan": {
						Steps: []models.Step{
							{
								Uses: "github/codeql-action/analyze@v2",
								ActionRef: &models.ActionRef{
									Raw: "github/codeql-action/analyze@v2",
									Owner: "github", Name: "codeql-action",
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Status != models.StatusPass {
		t.Errorf("status: got %s, want pass", result.Findings[0].Status)
	}
}

func TestScanCoverage_NoScanner(t *testing.T) {
	check := &ScanCoverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/ci.yml",
				Triggers: []string{"pull_request"},
				Jobs: map[string]*models.Job{
					"test": {
						Steps: []models.Step{
							{
								Uses: "actions/checkout@v4",
								ActionRef: &models.ActionRef{
									Owner: "actions", Name: "checkout",
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Status != models.StatusFail {
		t.Errorf("status: got %s, want fail", result.Findings[0].Status)
	}
}

func TestScanCoverage_NoPRWorkflow(t *testing.T) {
	check := &ScanCoverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/ci.yml",
				Triggers: []string{"push"},
				Jobs:     map[string]*models.Job{},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Status != models.StatusWarn {
		t.Errorf("status: got %s, want warn", result.Findings[0].Status)
	}
}

func TestScanCoverage_UtilityWorkflowSkipped(t *testing.T) {
	check := &ScanCoverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/labeler.yml",
				Name:     "PR Labeler",
				Triggers: []string{"pull_request"},
				Jobs: map[string]*models.Job{
					"label": {
						Steps: []models.Step{
							{Uses: "actions/labeler@v4", ActionRef: &models.ActionRef{Owner: "actions", Name: "labeler"}},
						},
					},
				},
			},
			{
				Path:     ".github/workflows/cache-clean.yml",
				Name:     "Clean Cache",
				Triggers: []string{"pull_request"},
				Jobs:     map[string]*models.Job{},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range result.Findings {
		if f.Status == models.StatusFail {
			t.Errorf("utility workflow should not fail: %s (%s)", f.Message, f.Target)
		}
	}

	skipped := 0
	for _, f := range result.Findings {
		if f.Status == models.StatusSkipped {
			skipped++
		}
	}
	if skipped != 2 {
		t.Errorf("expected 2 skipped findings, got %d", skipped)
	}
}

func TestScanCoverage_MixedUtilityAndReal(t *testing.T) {
	check := &ScanCoverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/stale.yml",
				Name:     "Close Stale Issues",
				Triggers: []string{"pull_request"},
				Jobs:     map[string]*models.Job{},
			},
			{
				Path:     ".github/workflows/ci.yml",
				Name:     "CI",
				Triggers: []string{"pull_request"},
				Jobs: map[string]*models.Job{
					"test": {
						Steps: []models.Step{
							{Uses: "actions/checkout@v4", ActionRef: &models.ActionRef{Owner: "actions", Name: "checkout"}},
						},
					},
				},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// stale.yml should be skipped, ci.yml should fail (no scanner)
	var skippedCount, failCount int
	for _, f := range result.Findings {
		switch f.Status {
		case models.StatusSkipped:
			skippedCount++
		case models.StatusFail:
			failCount++
		}
	}
	if skippedCount != 1 {
		t.Errorf("expected 1 skipped, got %d", skippedCount)
	}
	if failCount != 1 {
		t.Errorf("expected 1 fail, got %d", failCount)
	}
}
