// Package report renders audit reports in various formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/automationpi/actions-comply/pkg/models"
)

// findingGroup collects findings with the same message for display.
type findingGroup struct {
	Status   models.Status
	Severity models.Severity
	Message  string
	Detail   string
	Targets  []string
	Count    int
}

// groupFindings groups non-pass findings by message within a check result.
func groupFindings(cr models.CheckResult) []findingGroup {
	order := []string{}
	groups := map[string]*findingGroup{}

	for _, f := range cr.Findings {
		if f.Status == models.StatusPass || f.Status == models.StatusSkipped {
			continue
		}
		key := f.Message
		if g, ok := groups[key]; ok {
			g.Count++
			g.Targets = append(g.Targets, f.Target)
			// Escalate severity
			if models.SeverityRank(f.Severity) > models.SeverityRank(g.Severity) {
				g.Severity = f.Severity
			}
		} else {
			order = append(order, key)
			groups[key] = &findingGroup{
				Status:   f.Status,
				Severity: f.Severity,
				Message:  f.Message,
				Detail:   f.Detail,
				Targets:  []string{f.Target},
				Count:    1,
			}
		}
	}

	result := make([]findingGroup, 0, len(order))
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

// RenderText writes a human-readable text report.
func RenderText(w io.Writer, report *models.AuditReport) error {
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(w, " actions-comply Audit Report\n")
	fmt.Fprintf(w, " ID: %s | Org: %s | Generated: %s\n",
		report.ID, report.Org, report.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════\n\n")

	// Scorecard
	fmt.Fprintf(w, "SCORECARD\n")
	fmt.Fprintf(w, "─────────────────────────────────────────\n")
	fmt.Fprintf(w, "  Total findings: %d\n", report.Summary.TotalFindings)
	fmt.Fprintf(w, "  Pass: %d | Fail: %d | Warn: %d | Skipped: %d\n",
		report.Summary.CountByStatus[models.StatusPass],
		report.Summary.CountByStatus[models.StatusFail],
		report.Summary.CountByStatus[models.StatusWarn],
		report.Summary.CountByStatus[models.StatusSkipped])
	fmt.Fprintf(w, "  Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n\n",
		report.Summary.CountBySeverity[models.SeverityCritical],
		report.Summary.CountBySeverity[models.SeverityHigh],
		report.Summary.CountBySeverity[models.SeverityMedium],
		report.Summary.CountBySeverity[models.SeverityLow],
		report.Summary.CountBySeverity[models.SeverityInfo])

	// Control status
	if len(report.Summary.ControlStatus) > 0 {
		fmt.Fprintf(w, "CONTROL STATUS\n")
		fmt.Fprintf(w, "─────────────────────────────────────────\n")
		for ctrl, status := range report.Summary.ControlStatus {
			fmt.Fprintf(w, "  %-20s %s\n", ctrl, strings.ToUpper(string(status)))
		}
		fmt.Fprintln(w)
	}

	// Check summary table
	fmt.Fprintf(w, "CHECK SUMMARY\n")
	fmt.Fprintf(w, "─────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(w, "  %-40s %5s %5s %5s %5s\n", "Check", "Fail", "Warn", "Pass", "Skip")
	fmt.Fprintf(w, "  %-40s %5s %5s %5s %5s\n", "─────", "────", "────", "────", "────")
	for _, cr := range report.CheckResults {
		fail, warn, pass, skip := 0, 0, 0, 0
		for _, f := range cr.Findings {
			switch f.Status {
			case models.StatusFail:
				fail++
			case models.StatusWarn:
				warn++
			case models.StatusPass:
				pass++
			case models.StatusSkipped:
				skip++
			}
		}
		fmt.Fprintf(w, "  %-40s %5d %5d %5d %5d\n", checkDisplayName(cr.CheckID), fail, warn, pass, skip)
	}
	fmt.Fprintln(w)

	// Grouped findings detail
	for _, cr := range report.CheckResults {
		groups := groupFindings(cr)
		if len(groups) == 0 {
			// All passed
			passCount := len(cr.Findings)
			if passCount > 0 {
				fmt.Fprintf(w, "  %s: %d passed\n\n", cr.CheckID, passCount)
			}
			continue
		}

		fmt.Fprintf(w, "CHECK: %s\n", cr.CheckID)
		fmt.Fprintf(w, "─────────────────────────────────────────\n")

		for _, g := range groups {
			if g.Count == 1 {
				fmt.Fprintf(w, "  [%s/%s] %s\n",
					strings.ToUpper(string(g.Status)),
					strings.ToUpper(string(g.Severity)),
					g.Message)
				fmt.Fprintf(w, "    Target: %s\n", g.Targets[0])
			} else {
				fmt.Fprintf(w, "  [%s/%s] %s (%d occurrences)\n",
					strings.ToUpper(string(g.Status)),
					strings.ToUpper(string(g.Severity)),
					g.Message, g.Count)
				// Show up to 3 example targets
				limit := 3
				if len(g.Targets) < limit {
					limit = len(g.Targets)
				}
				for _, t := range g.Targets[:limit] {
					fmt.Fprintf(w, "    - %s\n", t)
				}
				if len(g.Targets) > 3 {
					fmt.Fprintf(w, "    ... and %d more\n", len(g.Targets)-3)
				}
			}
			if g.Detail != "" {
				fmt.Fprintf(w, "    Detail: %s\n", g.Detail)
			}
			fmt.Fprintln(w)
		}

		// Count passes
		passCount := 0
		for _, f := range cr.Findings {
			if f.Status == models.StatusPass {
				passCount++
			}
		}
		if passCount > 0 {
			fmt.Fprintf(w, "  %s: %d passed\n\n", cr.CheckID, passCount)
		}
	}

	return nil
}

// RenderJSON writes the full audit report as indented JSON.
func RenderJSON(w io.Writer, report *models.AuditReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// RenderSummary writes a GitHub Step Summary in markdown.
func RenderSummary(w io.Writer, report *models.AuditReport) error {
	fmt.Fprintf(w, "# actions-comply Audit Report\n\n")
	fmt.Fprintf(w, "**Org:** %s | **Generated:** %s\n\n",
		report.Org, report.GeneratedAt.Format("2006-01-02 15:04:05"))

	// Scorecard table
	fmt.Fprintf(w, "## Scorecard\n\n")
	fmt.Fprintf(w, "| Metric | Count |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Total | %d |\n", report.Summary.TotalFindings)
	fmt.Fprintf(w, "| Pass | %d |\n", report.Summary.CountByStatus[models.StatusPass])
	fmt.Fprintf(w, "| Fail | %d |\n", report.Summary.CountByStatus[models.StatusFail])
	fmt.Fprintf(w, "| Warn | %d |\n", report.Summary.CountByStatus[models.StatusWarn])
	fmt.Fprintf(w, "| Critical | %d |\n", report.Summary.CountBySeverity[models.SeverityCritical])
	fmt.Fprintf(w, "| High | %d |\n\n", report.Summary.CountBySeverity[models.SeverityHigh])

	// Control status
	if len(report.Summary.ControlStatus) > 0 {
		fmt.Fprintf(w, "## Control Status\n\n")
		fmt.Fprintf(w, "| Control | Status |\n")
		fmt.Fprintf(w, "|---------|--------|\n")
		for ctrl, status := range report.Summary.ControlStatus {
			emoji := statusEmoji(status)
			fmt.Fprintf(w, "| %s | %s %s |\n", ctrl, emoji, status)
		}
		fmt.Fprintln(w)
	}

	// Grouped findings
	hasFindings := false
	for _, cr := range report.CheckResults {
		groups := groupFindings(cr)
		for _, g := range groups {
			if !hasFindings {
				fmt.Fprintf(w, "## Findings\n\n")
				hasFindings = true
			}
			if g.Count == 1 {
				fmt.Fprintf(w, "### %s [%s/%s]\n\n", g.Message, g.Status, g.Severity)
				fmt.Fprintf(w, "**Target:** %s\n\n", g.Targets[0])
			} else {
				fmt.Fprintf(w, "### %s [%s/%s] (%d occurrences)\n\n", g.Message, g.Status, g.Severity, g.Count)
				limit := 5
				if len(g.Targets) < limit {
					limit = len(g.Targets)
				}
				for _, t := range g.Targets[:limit] {
					fmt.Fprintf(w, "- `%s`\n", t)
				}
				if len(g.Targets) > 5 {
					fmt.Fprintf(w, "- ... and %d more\n", len(g.Targets)-5)
				}
				fmt.Fprintln(w)
			}
			if g.Detail != "" {
				fmt.Fprintf(w, "> %s\n\n", g.Detail)
			}
		}
	}

	return nil
}

func statusEmoji(s models.Status) string {
	switch s {
	case models.StatusPass:
		return "\u2705"
	case models.StatusFail:
		return "\u274C"
	case models.StatusWarn:
		return "\u26A0\uFE0F"
	default:
		return "\u2796"
	}
}
