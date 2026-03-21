// Package changetrail implements the changetrail.deploy_approval check.
package changetrail

import (
	"fmt"
	"strings"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

// DefaultProdEnvironments lists environment names considered production.
var DefaultProdEnvironments = []string{
	"production", "prod", "live", "release", "prd", "main", "master",
}

// DeployApproval checks that production deploy jobs have environment gates.
type DeployApproval struct {
	ProdEnvironments []string
}

func (c *DeployApproval) ID() string    { return "changetrail.deploy_approval" }
func (c *DeployApproval) Title() string { return "Deploy Approval Gate" }
func (c *DeployApproval) Description() string {
	return "Verifies production deploy jobs have environment protection rules"
}
func (c *DeployApproval) Controls() []models.ControlID {
	return []models.ControlID{"SOC2-CC8.1", "ISO27001-A.12.1"}
}
func (c *DeployApproval) Severity() models.Severity { return models.SeverityCritical }

func (c *DeployApproval) prodEnvs() []string {
	if c.ProdEnvironments != nil {
		return c.ProdEnvironments
	}
	return DefaultProdEnvironments
}

func (c *DeployApproval) Run(ctx *models.CheckContext) (*models.CheckResult, error) {
	result := &models.CheckResult{CheckID: c.ID()}

	for _, wf := range ctx.Workflows {
		// Check if workflow triggers on push without pull_request
		hasPush := false
		hasPR := false
		for _, trigger := range wf.Triggers {
			if trigger == "push" {
				hasPush = true
			}
			if trigger == "pull_request" || trigger == "pull_request_target" {
				hasPR = true
			}
		}

		for jobID, job := range wf.Jobs {
			if !c.isProductionJob(job, jobID) {
				continue
			}

			target := fmt.Sprintf("%s/%s:%s/jobs/%s", ctx.Org, ctx.Repo, wf.Path, jobID)
			now := time.Now()

			evidence := models.Evidence{
				Type:        models.EvidenceWorkflowFile,
				Description: fmt.Sprintf("Production job '%s' in %s", jobID, wf.Path),
				URL:         fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", ctx.Org, ctx.Repo, wf.Path),
				CollectedAt: now,
			}

			if job.Environment == "" {
				result.Findings = append(result.Findings, models.Finding{
					CheckID:     c.ID(),
					CheckTitle:  c.Title(),
					Controls:    c.Controls(),
					Status:      models.StatusFail,
					Severity:    models.SeverityCritical,
					Target:      target,
					Message:     fmt.Sprintf("No approval gate — production job '%s' can deploy without review", jobID),
					Detail:      "Add 'environment: production' to this job and configure required reviewers in GitHub repo Settings > Environments. Without this, any push can trigger a production deploy with no human approval.",
					Evidence:    []models.Evidence{evidence},
					EvaluatedAt: now,
				})
			} else {
				result.Findings = append(result.Findings, models.Finding{
					CheckID:     c.ID(),
					CheckTitle:  c.Title(),
					Controls:    c.Controls(),
					Status:      models.StatusPass,
					Severity:    models.SeverityInfo,
					Target:      target,
					Message:     fmt.Sprintf("Approval gate configured — job '%s' uses environment '%s'", jobID, job.Environment),
					Evidence:    []models.Evidence{evidence},
					EvaluatedAt: now,
				})
			}

			// Warn if push-only trigger
			if hasPush && !hasPR {
				result.Findings = append(result.Findings, models.Finding{
					CheckID:     c.ID(),
					CheckTitle:  c.Title(),
					Controls:    c.Controls(),
					Status:      models.StatusWarn,
					Severity:    models.SeverityHigh,
					Target:      target,
					Message:     "No PR requirement — push to branch triggers deploy without code review",
					Detail:      "This workflow deploys on push without requiring a pull request. A direct push to the branch skips code review entirely. Add branch protection rules requiring PR approval, or add a pull_request trigger.",
					Evidence:    []models.Evidence{evidence},
					EvaluatedAt: now,
				})
			}
		}
	}

	return result, nil
}

func (c *DeployApproval) isProductionJob(job *models.Job, jobID string) bool {
	// Check if environment matches production list
	envLower := strings.ToLower(job.Environment)
	for _, prod := range c.prodEnvs() {
		if envLower == strings.ToLower(prod) {
			return true
		}
	}

	// Check if job name/ID contains deploy/release/prod keywords
	nameLower := strings.ToLower(job.Name)
	idLower := strings.ToLower(jobID)
	keywords := []string{"deploy", "release", "prod"}
	for _, kw := range keywords {
		if strings.Contains(nameLower, kw) || strings.Contains(idLower, kw) {
			return true
		}
	}

	return false
}
