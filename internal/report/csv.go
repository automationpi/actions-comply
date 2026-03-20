package report

import (
	"encoding/csv"
	"fmt"
	"io"

	"github.com/automationpi/actions-comply/internal/checks/supplychain"
	"github.com/automationpi/actions-comply/pkg/models"
)

// RenderBOMCSV writes the action Bill of Materials as CSV.
func RenderBOMCSV(w io.Writer, ctx *models.CheckContext) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header
	if err := cw.Write([]string{
		"repo", "workflow_path", "job_id", "step_name",
		"action_ref", "owner", "name", "version",
		"is_sha_pinned", "risk_note",
	}); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	entries := supplychain.CollectBOM(ctx)
	for _, e := range entries {
		pinned := "false"
		if e.IsSHAPinned {
			pinned = "true"
		}
		if err := cw.Write([]string{
			e.Repo, e.WorkflowPath, e.JobID, e.StepName,
			e.ActionRef, e.Owner, e.Name, e.Version,
			pinned, e.RiskNote,
		}); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}
