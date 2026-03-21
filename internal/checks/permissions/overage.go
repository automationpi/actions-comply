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

func (c *WorkflowOverage) ID() string    { return "permissions.workflow_overage" }
func (c *WorkflowOverage) Title() string { return "Workflow Permission Overage" }
func (c *WorkflowOverage) Description() string {
	return "Detects over-provisioned GitHub Actions workflow permissions"
}
func (c *WorkflowOverage) Controls() []models.ControlID {
	return []models.ControlID{"SOC2-CC6.1", "ISO27001-A.9.4"}
}
func (c *WorkflowOverage) Severity() models.Severity { return models.SeverityHigh }

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
				Message:     "Missing permissions block — workflow runs with broad default token permissions",
				Detail:      "Add a 'permissions:' block at the top of this workflow with only the scopes you need. Without it, the GITHUB_TOKEN gets default permissions which may be wider than necessary.",
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
				Message:     "Token has full write access to everything — 'permissions: write-all' is set",
				Detail:      "This is the most dangerous permission setting. Replace 'permissions: write-all' with specific scopes like 'contents: read'. write-all gives the workflow token write access to code, packages, issues, deployments, and more.",
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
				Message:     "Permissions set to read-only — good least-privilege configuration",
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
				Message:     fmt.Sprintf("Unnecessary write access — '%s: write' granted but no step needs it", scope),
				Detail:      fmt.Sprintf("The workflow declares '%s: write' but none of the actions in this workflow require write access to %s. Change it to '%s: read' or remove it.", scope, scope, scope),
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
			Message:     "Permissions correctly scoped — no unnecessary write access",
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
			Message:     fmt.Sprintf("Job '%s' has full write access — 'permissions: write-all' at job level", job.ID),
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
				Message:     fmt.Sprintf("Job '%s' has unnecessary '%s: write' — no step needs it", job.ID, scope),
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
