package report

import (
	"bytes"
	"encoding/csv"
	"testing"

	"github.com/automationpi/actions-comply/pkg/models"
)

func TestRenderBOMCSV(t *testing.T) {
	ctx := &models.CheckContext{
		Repo: "testrepo",
		Workflows: []*models.WorkflowFile{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: map[string]*models.Job{
					"build": {
						Steps: []models.Step{
							{
								Name: "Checkout",
								Uses: "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
								ActionRef: &models.ActionRef{
									Raw: "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
									Owner: "actions", Name: "checkout",
									Version: "a5ac7e51b41094c92402da3b24376905380afc29",
									IsSHA: true,
								},
							},
							{
								Name: "Setup",
								Uses: "actions/setup-go@v5",
								ActionRef: &models.ActionRef{
									Raw: "actions/setup-go@v5",
									Owner: "actions", Name: "setup-go",
									Version: "v5",
								},
							},
							{
								Name: "Local step",
								Uses: "./my-action",
								ActionRef: &models.ActionRef{
									IsLocal: true, Path: "./my-action",
								},
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := RenderBOMCSV(&buf, ctx); err != nil {
		t.Fatal(err)
	}

	reader := csv.NewReader(&buf)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	// Header + 3 data rows
	if len(records) != 4 {
		t.Fatalf("expected 4 rows (1 header + 3 data), got %d", len(records))
	}

	// Check header
	if records[0][0] != "repo" {
		t.Errorf("first header: got %q", records[0][0])
	}

	// Check SHA-pinned row
	if records[1][8] != "true" {
		t.Errorf("checkout should be SHA-pinned, got %q", records[1][8])
	}

	// Check unpinned row
	if records[2][8] != "false" {
		t.Errorf("setup-go should not be SHA-pinned, got %q", records[2][8])
	}
	if records[2][9] != "not SHA-pinned" {
		t.Errorf("risk note: got %q", records[2][9])
	}

	// Local action
	if records[3][9] != "local action" {
		t.Errorf("local action risk note: got %q", records[3][9])
	}
}
