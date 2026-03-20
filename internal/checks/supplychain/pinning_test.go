package supplychain

import (
	"testing"

	"github.com/automationpi/actions-comply/pkg/models"
)

func TestUnpinnedActions_SHAPinned(t *testing.T) {
	check := &UnpinnedActions{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: map[string]*models.Job{
					"test": {
						Steps: []models.Step{
							{
								Uses: "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
								ActionRef: &models.ActionRef{
									Owner: "actions", Name: "checkout",
									Version: "a5ac7e51b41094c92402da3b24376905380afc29",
									IsSHA: true,
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

	for _, f := range result.Findings {
		if f.Status == models.StatusFail {
			t.Errorf("SHA-pinned action should not fail: %s", f.Message)
		}
	}
}

func TestUnpinnedActions_MutableTag(t *testing.T) {
	check := &UnpinnedActions{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: map[string]*models.Job{
					"test": {
						Steps: []models.Step{
							{
								Uses: "actions/checkout@v4",
								ActionRef: &models.ActionRef{
									Owner: "actions", Name: "checkout",
									Version: "v4",
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

func TestUnpinnedActions_LocalSkipped(t *testing.T) {
	check := &UnpinnedActions{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: map[string]*models.Job{
					"test": {
						Steps: []models.Step{
							{
								Uses:      "./my-action",
								ActionRef: &models.ActionRef{IsLocal: true, Path: "./my-action"},
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

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for local action, got %d", len(result.Findings))
	}
}

func TestUnpinnedActions_NoVersion(t *testing.T) {
	check := &UnpinnedActions{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: map[string]*models.Job{
					"test": {
						Steps: []models.Step{
							{
								Uses: "actions/checkout",
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
		t.Errorf("no-version action should fail")
	}
}

func TestActionBOM_Inventory(t *testing.T) {
	check := &ActionBOM{}
	ctx := &models.CheckContext{
		Org:  "testorg",
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: map[string]*models.Job{
					"test": {
						Steps: []models.Step{
							{
								Uses: "actions/checkout@v4",
								ActionRef: &models.ActionRef{
									Owner: "actions", Name: "checkout", Version: "v4",
								},
							},
							{
								Uses: "actions/setup-go@v5",
								ActionRef: &models.ActionRef{
									Owner: "actions", Name: "setup-go", Version: "v5",
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

	if len(result.Findings) != 2 {
		t.Errorf("expected 2 BOM entries, got %d", len(result.Findings))
	}
	for _, f := range result.Findings {
		if f.Status != models.StatusPass {
			t.Errorf("BOM entries should be pass/info, got %s", f.Status)
		}
		if f.Severity != models.SeverityInfo {
			t.Errorf("BOM entries should be info severity, got %s", f.Severity)
		}
	}
}

func TestCollectBOM(t *testing.T) {
	ctx := &models.CheckContext{
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: map[string]*models.Job{
					"test": {
						Steps: []models.Step{
							{
								Name: "Checkout",
								Uses: "actions/checkout@v4",
								ActionRef: &models.ActionRef{
									Raw: "actions/checkout@v4", Owner: "actions", Name: "checkout", Version: "v4",
								},
							},
							{
								Name: "Local",
								Uses: "./my-action",
								ActionRef: &models.ActionRef{IsLocal: true, Path: "./my-action"},
							},
						},
					},
				},
			},
		},
	}

	entries := CollectBOM(ctx)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[1].RiskNote != "local action" {
		t.Errorf("local action risk note: got %q", entries[1].RiskNote)
	}
}
