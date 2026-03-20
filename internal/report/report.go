// Package report renders audit reports in various formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/automationpi/actions-comply/pkg/models"
)

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

	// Findings detail
	for _, cr := range report.CheckResults {
		hasNonPass := false
		for _, f := range cr.Findings {
			if f.Status != models.StatusPass {
				hasNonPass = true
				break
			}
		}

		if hasNonPass {
			fmt.Fprintf(w, "CHECK: %s\n", cr.CheckID)
			fmt.Fprintf(w, "─────────────────────────────────────────\n")
			for _, f := range cr.Findings {
				if f.Status == models.StatusPass {
					continue
				}
				fmt.Fprintf(w, "  [%s/%s] %s\n", strings.ToUpper(string(f.Status)), strings.ToUpper(string(f.Severity)), f.Message)
				fmt.Fprintf(w, "    Target: %s\n", f.Target)
				if f.Detail != "" {
					fmt.Fprintf(w, "    Detail: %s\n", f.Detail)
				}
				for _, ev := range f.Evidence {
					fmt.Fprintf(w, "    Evidence: %s — %s\n", ev.URL, ev.Description)
				}
				fmt.Fprintln(w)
			}
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

	// Failures
	hasFailures := false
	for _, cr := range report.CheckResults {
		for _, f := range cr.Findings {
			if f.Status == models.StatusFail || f.Status == models.StatusWarn {
				if !hasFailures {
					fmt.Fprintf(w, "## Findings\n\n")
					hasFailures = true
				}
				fmt.Fprintf(w, "### %s [%s/%s]\n\n", f.Message, f.Status, f.Severity)
				fmt.Fprintf(w, "**Target:** %s\n\n", f.Target)
				if f.Detail != "" {
					fmt.Fprintf(w, "> %s\n\n", f.Detail)
				}
				for _, ev := range f.Evidence {
					fmt.Fprintf(w, "- [%s](%s)\n", ev.Description, ev.URL)
				}
				fmt.Fprintln(w)
			}
		}
	}

	return nil
}

func statusEmoji(s models.Status) string {
	switch s {
	case models.StatusPass:
		return "\\u2705"
	case models.StatusFail:
		return "\\u274C"
	case models.StatusWarn:
		return "\\u26A0\\uFE0F"
	default:
		return "\\u2796"
	}
}
