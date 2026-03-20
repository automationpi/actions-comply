// Package engine orchestrates check execution and aggregates results.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	yamlparser "github.com/automationpi/actions-comply/internal/yaml"
	"github.com/automationpi/actions-comply/pkg/models"
)

// Engine runs compliance checks and produces an audit report.
type Engine struct {
	Checks []models.Check
}

// New creates an engine with the given checks.
func New(checks ...models.Check) *Engine {
	return &Engine{Checks: checks}
}

// RunOptions configures an engine run.
type RunOptions struct {
	Org         string
	Repo        string
	Frameworks  []models.Framework
	Period      models.Period
	WorkflowDir string // Local directory of workflow files (offline mode)
}

// Run executes all checks and returns an audit report.
func (e *Engine) Run(opts RunOptions) (*models.AuditReport, error) {
	workflows, err := e.loadWorkflows(opts)
	if err != nil {
		return nil, fmt.Errorf("loading workflows: %w", err)
	}

	ctx := &models.CheckContext{
		Org:       opts.Org,
		Repo:      opts.Repo,
		Workflows: workflows,
	}

	report := &models.AuditReport{
		ID:          fmt.Sprintf("audit-%d", time.Now().Unix()),
		Org:         opts.Org,
		Repos:       []string{opts.Repo},
		Frameworks:  opts.Frameworks,
		Period:      opts.Period,
		GeneratedAt: time.Now(),
		Summary: models.ReportSummary{
			CountByStatus:   make(map[models.Status]int),
			CountBySeverity: make(map[models.Severity]int),
			ControlStatus:   make(map[models.ControlID]models.Status),
		},
	}

	for _, check := range e.Checks {
		result, err := check.Run(ctx)
		if err != nil {
			return nil, fmt.Errorf("running check %s: %w", check.ID(), err)
		}
		report.CheckResults = append(report.CheckResults, *result)

		for _, f := range result.Findings {
			report.Summary.TotalFindings++
			report.Summary.CountByStatus[f.Status]++
			report.Summary.CountBySeverity[f.Severity]++

			// Update per-control status (worst status wins)
			for _, ctrl := range f.Controls {
				existing, ok := report.Summary.ControlStatus[ctrl]
				if !ok || statusRank(f.Status) > statusRank(existing) {
					report.Summary.ControlStatus[ctrl] = f.Status
				}
			}
		}
	}

	return report, nil
}

// HasFindingsAtOrAbove returns true if any finding has severity >= threshold.
func HasFindingsAtOrAbove(report *models.AuditReport, threshold models.Severity) bool {
	thresholdRank := models.SeverityRank(threshold)
	for _, cr := range report.CheckResults {
		for _, f := range cr.Findings {
			if f.Status == models.StatusFail && models.SeverityRank(f.Severity) >= thresholdRank {
				return true
			}
		}
	}
	return false
}

func statusRank(s models.Status) int {
	switch s {
	case models.StatusFail:
		return 3
	case models.StatusWarn:
		return 2
	case models.StatusPass:
		return 1
	case models.StatusSkipped:
		return 0
	default:
		return 0
	}
}

// LoadWorkflowContext loads workflows and returns a CheckContext.
// Exported for use by BOM CSV generation.
func (e *Engine) LoadWorkflowContext(opts RunOptions) (*models.CheckContext, error) {
	workflows, err := e.loadWorkflows(opts)
	if err != nil {
		return nil, err
	}
	return &models.CheckContext{
		Org:       opts.Org,
		Repo:      opts.Repo,
		Workflows: workflows,
	}, nil
}

func (e *Engine) loadWorkflows(opts RunOptions) ([]*models.WorkflowFile, error) {
	if opts.WorkflowDir == "" {
		return nil, fmt.Errorf("workflow-dir is required (GitHub API mode not yet implemented)")
	}

	var workflows []*models.WorkflowFile

	entries, err := os.ReadDir(opts.WorkflowDir)
	if err != nil {
		return nil, fmt.Errorf("reading workflow dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".yml" && filepath.Ext(name) != ".yaml" {
			continue
		}

		path := filepath.Join(opts.WorkflowDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		wfPath := ".github/workflows/" + name
		wf, err := yamlparser.Parse(wfPath, string(data))
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		workflows = append(workflows, wf)
	}

	return workflows, nil
}
