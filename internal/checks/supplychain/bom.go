// Package supplychain implements supply chain checks: action BOM and SHA pinning.
package supplychain

import (
	"fmt"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

// ActionBOM inventories every third-party action reference.
type ActionBOM struct{}

func (c *ActionBOM) ID() string          { return "supplychain.action_bom" }
func (c *ActionBOM) Title() string        { return "Action Bill of Materials" }
func (c *ActionBOM) Description() string  { return "Inventories every third-party GitHub Action used across workflows" }
func (c *ActionBOM) Controls() []models.ControlID { return []models.ControlID{"SOC2-CC9.2", "ISO27001-A.15.1"} }
func (c *ActionBOM) Severity() models.Severity    { return models.SeverityInfo }

func (c *ActionBOM) Run(ctx *models.CheckContext) (*models.CheckResult, error) {
	result := &models.CheckResult{CheckID: c.ID()}

	// Track unique actions for dedup
	seen := make(map[string]bool)

	for _, wf := range ctx.Workflows {
		for jobID, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.ActionRef == nil {
					continue
				}
				ref := step.ActionRef

				// Skip local and docker actions for inventory (but note them)
				if ref.IsLocal || ref.IsDocker {
					continue
				}

				actionKey := ref.Owner + "/" + ref.Name
				if seen[actionKey] {
					continue
				}
				seen[actionKey] = true

				now := time.Now()
				result.Findings = append(result.Findings, models.Finding{
					CheckID:    c.ID(),
					CheckTitle: c.Title(),
					Controls:   c.Controls(),
					Status:     models.StatusPass,
					Severity:   models.SeverityInfo,
					Target:     actionKey,
					Message:    fmt.Sprintf("Third-party action: %s@%s", actionKey, ref.Version),
					Evidence: []models.Evidence{
						{
							Type:        models.EvidenceWorkflowFile,
							Description: fmt.Sprintf("Used in %s job %s", wf.Path, jobID),
							URL:         fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", ctx.Org, ctx.Repo, wf.Path),
							Ref:         ref.Version,
							CollectedAt: now,
						},
					},
					EvaluatedAt: now,
				})
			}
		}
	}

	return result, nil
}

// BOMEntry represents a single row in the CSV BOM export.
type BOMEntry struct {
	Repo         string
	WorkflowPath string
	JobID        string
	StepName     string
	ActionRef    string
	Owner        string
	Name         string
	Version      string
	IsSHAPinned  bool
	RiskNote     string
}

// CollectBOM returns all action references as BOM entries (not deduplicated).
func CollectBOM(ctx *models.CheckContext) []BOMEntry {
	var entries []BOMEntry

	for _, wf := range ctx.Workflows {
		for jobID, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.ActionRef == nil {
					continue
				}
				ref := step.ActionRef
				entry := BOMEntry{
					Repo:         ctx.Repo,
					WorkflowPath: wf.Path,
					JobID:        jobID,
					StepName:     step.Name,
					ActionRef:    ref.Raw,
					Owner:        ref.Owner,
					Name:         ref.Name,
					Version:      ref.Version,
					IsSHAPinned:  ref.IsSHA,
				}
				if ref.IsLocal {
					entry.RiskNote = "local action"
				} else if ref.IsDocker {
					entry.RiskNote = "docker action"
				} else if !ref.IsSHA {
					entry.RiskNote = "not SHA-pinned"
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries
}
