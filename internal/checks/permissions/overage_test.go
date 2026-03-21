package permissions

import (
	"testing"

	"github.com/automationpi/actions-comply/pkg/models"
)

func TestWorkflowOverage_WriteAll(t *testing.T) {
	check := &WorkflowOverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:        ".github/workflows/ci.yml",
				Permissions: &models.PermissionBlock{All: "write-all"},
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
	f := result.Findings[0]
	if f.Status != models.StatusFail {
		t.Errorf("status: got %s, want fail", f.Status)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("severity: got %s, want critical", f.Severity)
	}
}

func TestWorkflowOverage_NoPermissions(t *testing.T) {
	check := &WorkflowOverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:        ".github/workflows/ci.yml",
				Permissions: nil,
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

func TestWorkflowOverage_ExplicitMinimalPerms(t *testing.T) {
	check := &WorkflowOverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Permissions: &models.PermissionBlock{
					Scopes: map[string]string{"contents": "read"},
				},
				Jobs: map[string]*models.Job{
					"test": {
						ID: "test",
						Steps: []models.Step{
							{Uses: "actions/checkout@abc123", ActionRef: &models.ActionRef{Owner: "actions", Name: "checkout"}},
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

	// Should pass — contents:read is needed by checkout
	hasPass := false
	for _, f := range result.Findings {
		if f.Status == models.StatusPass {
			hasPass = true
		}
	}
	if !hasPass {
		t.Error("expected at least one PASS finding")
	}
}

func TestWorkflowOverage_UnnecessaryWrite(t *testing.T) {
	check := &WorkflowOverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Permissions: &models.PermissionBlock{
					Scopes: map[string]string{
						"contents": "read",
						"packages": "write", // Not needed by checkout
					},
				},
				Jobs: map[string]*models.Job{
					"test": {
						ID: "test",
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

	hasFail := false
	for _, f := range result.Findings {
		if f.Status == models.StatusFail && f.Severity == models.SeverityHigh {
			hasFail = true
		}
	}
	if !hasFail {
		t.Error("expected FAIL/HIGH for unnecessary packages:write")
	}
}

func TestWorkflowOverage_ReadAll(t *testing.T) {
	check := &WorkflowOverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:        ".github/workflows/ci.yml",
				Permissions: &models.PermissionBlock{All: "read-all"},
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

func TestWorkflowOverage_EvidencePresent(t *testing.T) {
	check := &WorkflowOverage{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:        ".github/workflows/ci.yml",
				Permissions: &models.PermissionBlock{All: "write-all"},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range result.Findings {
		if len(f.Evidence) == 0 {
			t.Errorf("finding %q has no evidence", f.Message)
		}
	}
}
