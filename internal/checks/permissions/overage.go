// Package permissions implements the permissions.workflow_overage check.
package permissions

import (
	"fmt"
	"strings"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

// DefaultStepUsageMap maps known action prefixes to their minimum required permissions.
var DefaultStepUsageMap = map[string][]string{
	"actions/checkout":            {"contents:read"},
	"actions/upload-artifact":     {"contents:read"},
	"actions/download-artifact":   {"contents:read"},
	"actions/setup-go":            {"contents:read"},
	"actions/setup-node":          {"contents:read"},
	"actions/setup-python":        {"contents:read"},
	"actions/setup-java":          {"contents:read"},
	"actions/cache":               {"contents:read"},
	"github/codeql-action":        {"security-events:write"},
	"softprops/action-gh-release": {"contents:write"},
	"docker/build-push-action":    {"packages:write"},
	"docker/login-action":         {"packages:read"},
}

// WorkflowOverage checks for over-provisioned workflow permissions.
type WorkflowOverage struct {
	StepUsageMap map[string][]string
}

func (c *WorkflowOverage) ID() string          { return "permissions.workflow_overage" }
func (c *WorkflowOverage) Title() string        { return "Workflow Permission Overage" }
func (c *WorkflowOverage) Description() string  { return "Detects over-provisioned GitHub Actions workflow permissions" }
func (c *WorkflowOverage) Controls() []models.ControlID { return []models.ControlID{"SOC2-CC6.1", "ISO27001-A.9.4"} }
func (c *WorkflowOverage) Severity() models.Severity    { return models.SeverityHigh }

func (c *WorkflowOverage) stepMap() map[string][]string {
	if c.StepUsageMap != nil {
		return c.StepUsageMap
	}
	return DefaultStepUsageMap
}

func (c *WorkflowOverage) Run(ctx *models.CheckContext) (*models.CheckResult, error) {
	result := &models.CheckResult{CheckID: c.ID()}

	for _, wf := range ctx.Workflows {
		target := fmt.Sprintf("%s/%s:%s", ctx.Org, ctx.Repo, wf.Path)
		now := time.Now()

		evidence := models.Evidence{
			Type:        models.EvidenceWorkflowFile,
			Description: fmt.Sprintf("Workflow file %s", wf.Path),
			URL:         fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", ctx.Org, ctx.Repo, wf.Path),
			CollectedAt: now,
		}

		// Check top-level permissions
		if wf.Permissions == nil {
			result.Findings = append(result.Findings, models.Finding{
				CheckID:     c.ID(),
				CheckTitle:  c.Title(),
				Controls:    c.Controls(),
				Status:      models.StatusWarn,
				Severity:    models.SeverityMedium,
				Target:      target,
				Message:     "No explicit permissions block — GitHub defaults apply",
				Detail:      "Add an explicit permissions block to follow the principle of least privilege. Without it, workflows may receive broader permissions than needed.",
				Evidence:    []models.Evidence{evidence},
				EvaluatedAt: now,
			})
			continue
		}

		if wf.Permissions.All == "write-all" {
			result.Findings = append(result.Findings, models.Finding{
				CheckID:     c.ID(),
				CheckTitle:  c.Title(),
				Controls:    c.Controls(),
				Status:      models.StatusFail,
				Severity:    models.SeverityCritical,
				Target:      target,
				Message:     "Workflow declares permissions: write-all",
				Detail:      "Replace 'permissions: write-all' with explicit per-scope permissions. write-all grants every token scope at write level, violating least privilege.",
				Evidence:    []models.Evidence{evidence},
				EvaluatedAt: now,
			})
			continue
		}

		if wf.Permissions.All == "read-all" {
			result.Findings = append(result.Findings, models.Finding{
				CheckID:     c.ID(),
				CheckTitle:  c.Title(),
				Controls:    c.Controls(),
				Status:      models.StatusPass,
				Severity:    models.SeverityInfo,
				Target:      target,
				Message:     "Workflow declares permissions: read-all",
				Evidence:    []models.Evidence{evidence},
				EvaluatedAt: now,
			})
			continue
		}

		// Per-scope analysis
		c.checkScopes(ctx, wf, target, evidence, result)

		// Check job-level permissions
		for _, job := range wf.Jobs {
			c.checkJobPermissions(ctx, wf, job, result)
		}
	}

	return result, nil
}

func (c *WorkflowOverage) checkScopes(ctx *models.CheckContext, wf *models.WorkflowFile, target string, evidence models.Evidence, result *models.CheckResult) {
	if wf.Permissions == nil || wf.Permissions.Scopes == nil {
		return
	}

	// Collect all actions used across all jobs
	neededPerms := c.collectNeededPermissions(wf)
	now := time.Now()

	hasOverage := false
	for scope, level := range wf.Permissions.Scopes {
		if level != "write" {
			continue
		}
		permKey := scope + ":write"
		if !neededPerms[permKey] {
			hasOverage = true
			result.Findings = append(result.Findings, models.Finding{
				CheckID:     c.ID(),
				CheckTitle:  c.Title(),
				Controls:    c.Controls(),
				Status:      models.StatusFail,
				Severity:    models.SeverityHigh,
				Target:      target,
				Message:     fmt.Sprintf("Write scope '%s: write' declared but no step requires it", scope),
				Detail:      fmt.Sprintf("Remove or downgrade '%s: write' to '%s: read' unless a step genuinely needs write access.", scope, scope),
				Evidence:    []models.Evidence{evidence},
				EvaluatedAt: now,
			})
		}
	}

	if !hasOverage {
		result.Findings = append(result.Findings, models.Finding{
			CheckID:     c.ID(),
			CheckTitle:  c.Title(),
			Controls:    c.Controls(),
			Status:      models.StatusPass,
			Severity:    models.SeverityInfo,
			Target:      target,
			Message:     "Explicit permissions block with no over-provisioned write scopes",
			Evidence:    []models.Evidence{evidence},
			EvaluatedAt: now,
		})
	}
}

func (c *WorkflowOverage) checkJobPermissions(ctx *models.CheckContext, wf *models.WorkflowFile, job *models.Job, result *models.CheckResult) {
	if job.Permissions == nil {
		return
	}

	target := fmt.Sprintf("%s/%s:%s/jobs/%s", ctx.Org, ctx.Repo, wf.Path, job.ID)
	now := time.Now()

	evidence := models.Evidence{
		Type:        models.EvidenceWorkflowFile,
		Description: fmt.Sprintf("Job %s in %s", job.ID, wf.Path),
		URL:         fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", ctx.Org, ctx.Repo, wf.Path),
		CollectedAt: now,
	}

	if job.Permissions.All == "write-all" {
		result.Findings = append(result.Findings, models.Finding{
			CheckID:     c.ID(),
			CheckTitle:  c.Title(),
			Controls:    c.Controls(),
			Status:      models.StatusFail,
			Severity:    models.SeverityCritical,
			Target:      target,
			Message:     fmt.Sprintf("Job '%s' declares permissions: write-all", job.ID),
			Evidence:    []models.Evidence{evidence},
			EvaluatedAt: now,
		})
		return
	}

	// Check job-level scopes against step usage
	neededPerms := c.collectJobNeededPermissions(job)
	for scope, level := range job.Permissions.Scopes {
		if level != "write" {
			continue
		}
		permKey := scope + ":write"
		if !neededPerms[permKey] {
			result.Findings = append(result.Findings, models.Finding{
				CheckID:     c.ID(),
				CheckTitle:  c.Title(),
				Controls:    c.Controls(),
				Status:      models.StatusWarn,
				Severity:    models.SeverityMedium,
				Target:      target,
				Message:     fmt.Sprintf("Job '%s' has write scope '%s: write' with no matching step need", job.ID, scope),
				Evidence:    []models.Evidence{evidence},
				EvaluatedAt: now,
			})
		}
	}
}

func (c *WorkflowOverage) collectNeededPermissions(wf *models.WorkflowFile) map[string]bool {
	needed := make(map[string]bool)
	for _, job := range wf.Jobs {
		for perm := range c.collectJobNeededPermissions(job) {
			needed[perm] = true
		}
	}
	return needed
}

func (c *WorkflowOverage) collectJobNeededPermissions(job *models.Job) map[string]bool {
	needed := make(map[string]bool)
	smap := c.stepMap()
	for _, step := range job.Steps {
		if step.ActionRef == nil || step.ActionRef.IsLocal || step.ActionRef.IsDocker {
			continue
		}
		actionKey := step.ActionRef.Owner + "/" + step.ActionRef.Name
		for prefix, perms := range smap {
			if strings.HasPrefix(actionKey, prefix) {
				for _, p := range perms {
					needed[p] = true
				}
			}
		}
	}
	return needed
}

