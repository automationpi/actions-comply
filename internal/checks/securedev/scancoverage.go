// Package securedev implements the securedev.scan_coverage check.
package securedev

import (
	"fmt"
	"strings"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

// DefaultKnownScanners maps action prefixes to scanner types.
var DefaultKnownScanners = map[string]string{
	"github/codeql-action/analyze": "SAST (CodeQL)",
	"github/codeql-action/init":    "SAST (CodeQL)",
	"aquasecurity/trivy-action":     "SCA/Container (Trivy)",
	"snyk/actions":                  "SCA (Snyk)",
	"semgrep/semgrep-action":        "SAST (Semgrep)",
	"gitleaks/gitleaks-action":      "Secrets (Gitleaks)",
	"trufflesecurity/trufflehog":    "Secrets (TruffleHog)",
}

// ScanCoverage checks that PR workflows include security scanning.
type ScanCoverage struct {
	KnownScanners map[string]string
}

func (c *ScanCoverage) ID() string          { return "securedev.scan_coverage" }
func (c *ScanCoverage) Title() string        { return "Security Scan Coverage" }
func (c *ScanCoverage) Description() string  { return "Ensures PR workflows include security scanning steps" }
func (c *ScanCoverage) Controls() []models.ControlID { return []models.ControlID{"ISO27001-A.14.2", "SOC2-CC7.2"} }
func (c *ScanCoverage) Severity() models.Severity    { return models.SeverityHigh }

func (c *ScanCoverage) scanners() map[string]string {
	if c.KnownScanners != nil {
		return c.KnownScanners
	}
	return DefaultKnownScanners
}

func (c *ScanCoverage) Run(ctx *models.CheckContext) (*models.CheckResult, error) {
	result := &models.CheckResult{CheckID: c.ID()}

	// Find workflows triggered by pull_request
	var prWorkflows []*models.WorkflowFile
	for _, wf := range ctx.Workflows {
		for _, trigger := range wf.Triggers {
			if trigger == "pull_request" || trigger == "pull_request_target" {
				prWorkflows = append(prWorkflows, wf)
				break
			}
		}
	}

	now := time.Now()

	if len(prWorkflows) == 0 {
		result.Findings = append(result.Findings, models.Finding{
			CheckID:    c.ID(),
			CheckTitle: c.Title(),
			Controls:   c.Controls(),
			Status:     models.StatusWarn,
			Severity:   models.SeverityMedium,
			Target:     fmt.Sprintf("%s/%s", ctx.Org, ctx.Repo),
			Message:    "No pull_request triggered workflows found",
			Detail:     "Add a workflow triggered on pull_request that includes a security scanner (CodeQL, Trivy, Semgrep, etc.)",
			Evidence: []models.Evidence{
				{
					Type:        models.EvidenceWorkflowFile,
					Description: "No PR-triggered workflows detected",
					URL:         fmt.Sprintf("https://github.com/%s/%s/tree/main/.github/workflows", ctx.Org, ctx.Repo),
					CollectedAt: now,
				},
			},
			EvaluatedAt: now,
		})
		return result, nil
	}

	scanners := c.scanners()
	for _, wf := range prWorkflows {
		// Skip utility/housekeeping workflows that don't execute code
		if isUtilityWorkflow(wf) {
			result.Findings = append(result.Findings, models.Finding{
				CheckID:    c.ID(),
				CheckTitle: c.Title(),
				Controls:   c.Controls(),
				Status:     models.StatusSkipped,
				Severity:   models.SeverityInfo,
				Target:     fmt.Sprintf("%s/%s:%s", ctx.Org, ctx.Repo, wf.Path),
				Message:    fmt.Sprintf("Utility workflow skipped: %s", wf.Name),
				Evidence: []models.Evidence{
					{
						Type:        models.EvidenceWorkflowFile,
						Description: fmt.Sprintf("Utility workflow %s", wf.Path),
						URL:         fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", ctx.Org, ctx.Repo, wf.Path),
						CollectedAt: now,
					},
				},
				EvaluatedAt: now,
			})
			continue
		}

		target := fmt.Sprintf("%s/%s:%s", ctx.Org, ctx.Repo, wf.Path)
		evidence := models.Evidence{
			Type:        models.EvidenceWorkflowFile,
			Description: fmt.Sprintf("PR workflow %s", wf.Path),
			URL:         fmt.Sprintf("https://github.com/%s/%s/blob/main/%s", ctx.Org, ctx.Repo, wf.Path),
			CollectedAt: now,
		}

		found := c.findScanners(wf, scanners)
		if len(found) > 0 {
			result.Findings = append(result.Findings, models.Finding{
				CheckID:     c.ID(),
				CheckTitle:  c.Title(),
				Controls:    c.Controls(),
				Status:      models.StatusPass,
				Severity:    models.SeverityInfo,
				Target:      target,
				Message:     fmt.Sprintf("Scanner(s) found: %s", strings.Join(found, ", ")),
				Evidence:    []models.Evidence{evidence},
				EvaluatedAt: now,
			})
		} else {
			result.Findings = append(result.Findings, models.Finding{
				CheckID:     c.ID(),
				CheckTitle:  c.Title(),
				Controls:    c.Controls(),
				Status:      models.StatusFail,
				Severity:    models.SeverityHigh,
				Target:      target,
				Message:     "PR workflow contains no security scanning step",
				Detail:      "Add a security scanner (CodeQL, Trivy, Semgrep, Gitleaks, etc.) to this PR workflow.",
				Evidence:    []models.Evidence{evidence},
				EvaluatedAt: now,
			})
		}
	}

	return result, nil
}

func (c *ScanCoverage) findScanners(wf *models.WorkflowFile, scanners map[string]string) []string {
	var found []string
	seen := make(map[string]bool)

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.ActionRef == nil || step.ActionRef.IsLocal || step.ActionRef.IsDocker {
				continue
			}
			actionKey := step.ActionRef.Owner + "/" + step.ActionRef.Name
			// Check with sub-path if present
			fullKey := actionKey
			if step.ActionRef.Raw != "" {
				// Extract owner/name/subpath from the raw ref before @
				parts := strings.SplitN(step.ActionRef.Raw, "@", 2)
				if len(parts) > 0 {
					fullKey = parts[0]
				}
			}

			for prefix, scannerType := range scanners {
				if strings.HasPrefix(fullKey, prefix) || strings.HasPrefix(actionKey, prefix) {
					if !seen[scannerType] {
						seen[scannerType] = true
						found = append(found, scannerType)
					}
				}
			}
		}
	}

	return found
}

// utilityPatterns are substrings that identify housekeeping/utility workflows
// which don't execute application code and don't need security scanners.
var utilityPatterns = []string{
	"label", "cache", "stale", "lock", "assign", "triage",
	"greet", "welcome", "auto-merge", "automerge", "dependabot",
	"clean", "housekeep", "comment", "draft", "conflict",
	"semantic", "conventional", "changelog",
}

func isUtilityWorkflow(wf *models.WorkflowFile) bool {
	nameLower := strings.ToLower(wf.Name)
	pathLower := strings.ToLower(wf.Path)
	for _, pattern := range utilityPatterns {
		if strings.Contains(nameLower, pattern) || strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}
