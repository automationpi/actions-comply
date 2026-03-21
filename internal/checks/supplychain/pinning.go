package supplychain

import (
	"fmt"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

// UnpinnedActions checks that all third-party actions are pinned to a full SHA.
type UnpinnedActions struct{}

func (c *UnpinnedActions) ID() string    { return "supplychain.unpinned_actions" }
func (c *UnpinnedActions) Title() string { return "Unpinned Action References" }
func (c *UnpinnedActions) Description() string {
	return "Detects third-party actions pinned to mutable tags instead of full SHA"
}
func (c *UnpinnedActions) Controls() []models.ControlID {
	return []models.ControlID{"SOC2-CC9.2", "ISO27001-A.15.1", "ISO27001-A.14.2"}
}
func (c *UnpinnedActions) Severity() models.Severity { return models.SeverityHigh }

func (c *UnpinnedActions) Run(ctx *models.CheckContext) (*models.CheckResult, error) {
	result := &models.CheckResult{CheckID: c.ID()}

	for _, wf := range ctx.Workflows {
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.ActionRef == nil {
					continue
				}
				ref := step.ActionRef

				// Skip local and docker actions
				if ref.IsLocal || ref.IsDocker {
					continue
				}

				target := fmt.Sprintf("%s/%s:%s → %s", ctx.Org, ctx.Repo, wf.Path, ref.Raw)
				now := time.Now()

				evidence := models.Evidence{
					Type:        models.EvidenceWorkflowFile,
					Description: fmt.Sprintf("Action reference: %s", ref.Raw),
					URL:         fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", ctx.Org, ctx.Repo, wf.Path),
					Ref:         ref.Version,
					CollectedAt: now,
				}

				if ref.IsSHA {
					result.Findings = append(result.Findings, models.Finding{
						CheckID:     c.ID(),
						CheckTitle:  c.Title(),
						Controls:    c.Controls(),
						Status:      models.StatusPass,
						Severity:    models.SeverityInfo,
						Target:      target,
						Message:     fmt.Sprintf("Securely pinned — %s/%s uses immutable SHA reference", ref.Owner, ref.Name),
						Evidence:    []models.Evidence{evidence},
						EvaluatedAt: now,
					})
				} else {
					msg := fmt.Sprintf("Action %s/%s uses tag '%s' — can be silently changed by the owner", ref.Owner, ref.Name, ref.Version)
					if ref.Version == "" {
						msg = fmt.Sprintf("Action %s/%s has no version at all — always pulls latest code", ref.Owner, ref.Name)
					}
					result.Findings = append(result.Findings, models.Finding{
						CheckID:     c.ID(),
						CheckTitle:  c.Title(),
						Controls:    c.Controls(),
						Status:      models.StatusFail,
						Severity:    models.SeverityHigh,
						Target:      target,
						Message:     msg,
						Detail:      fmt.Sprintf("Replace '%s@%s' with '%s@<full-sha>'. Tags like '%s' can be moved by the action owner to point to different code without your knowledge. Use 'gh api repos/%s/git/ref/tags/%s' to find the current SHA.", ref.Owner+"/"+ref.Name, ref.Version, ref.Owner+"/"+ref.Name, ref.Version, ref.Owner+"/"+ref.Name, ref.Version),
						Evidence:    []models.Evidence{evidence},
						EvaluatedAt: now,
					})
				}
			}
		}
	}

	return result, nil
}
