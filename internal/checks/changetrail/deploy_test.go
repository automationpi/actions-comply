package changetrail

import (
	"testing"

	"github.com/automationpi/actions-comply/pkg/models"
)

func TestDeployApproval_NoEnvironment(t *testing.T) {
	check := &DeployApproval{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/deploy.yml",
				Triggers: []string{"push"},
				Jobs: map[string]*models.Job{
					"deploy-prod": {
						ID:   "deploy-prod",
						Name: "Deploy to Production",
					},
				},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	hasCriticalFail := false
	for _, f := range result.Findings {
		if f.Status == models.StatusFail && f.Severity == models.SeverityCritical {
			hasCriticalFail = true
		}
	}
	if !hasCriticalFail {
		t.Error("expected CRITICAL FAIL for deploy without environment")
	}
}

func TestDeployApproval_WithEnvironment(t *testing.T) {
	check := &DeployApproval{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/deploy.yml",
				Triggers: []string{"push", "pull_request"},
				Jobs: map[string]*models.Job{
					"deploy-prod": {
						ID:          "deploy-prod",
						Name:        "Deploy to Production",
						Environment: "production",
					},
				},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range result.Findings {
		if f.Status == models.StatusFail {
			t.Errorf("deploy with environment should not fail: %s", f.Message)
		}
	}
}

func TestDeployApproval_PushOnlyTrigger(t *testing.T) {
	check := &DeployApproval{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/deploy.yml",
				Triggers: []string{"push"},
				Jobs: map[string]*models.Job{
					"deploy-prod": {
						ID:          "deploy-prod",
						Name:        "Deploy to Production",
						Environment: "production",
					},
				},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	hasWarn := false
	for _, f := range result.Findings {
		if f.Status == models.StatusWarn {
			hasWarn = true
		}
	}
	if !hasWarn {
		t.Error("expected WARN for push-only trigger")
	}
}

func TestDeployApproval_NonProdJob(t *testing.T) {
	check := &DeployApproval{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/ci.yml",
				Triggers: []string{"push"},
				Jobs: map[string]*models.Job{
					"test": {
						ID:   "test",
						Name: "Run Tests",
					},
				},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("non-prod job should produce no findings, got %d", len(result.Findings))
	}
}

func TestDeployApproval_EnvironmentNameMatch(t *testing.T) {
	check := &DeployApproval{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path:     ".github/workflows/deploy.yml",
				Triggers: []string{"push", "pull_request"},
				Jobs: map[string]*models.Job{
					"ship": {
						ID:          "ship",
						Name:        "Ship it",
						Environment: "production",
					},
				},
			},
		},
	}

	result, err := check.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Job name doesn't contain deploy/release/prod but env matches
	hasPass := false
	for _, f := range result.Findings {
		if f.Status == models.StatusPass {
			hasPass = true
		}
	}
	if !hasPass {
		t.Error("expected PASS for job with production environment")
	}
}
