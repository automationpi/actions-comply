// Package models defines the core domain types for actions-comply.
package models

import "time"

// Status represents the outcome of a compliance check.
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusWarn    Status = "warn"
	StatusSkipped Status = "skipped"
)

// Severity represents the impact level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SeverityRank returns a numeric rank for severity comparison.
// Higher rank = more severe.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ControlID identifies a specific compliance framework control.
type ControlID string

// Framework represents a compliance framework.
type Framework string

const (
	FrameworkSOC2     Framework = "soc2"
	FrameworkISO27001 Framework = "iso27001"
)

// EvidenceType classifies the kind of evidence backing a finding.
type EvidenceType string

const (
	EvidenceWorkflowFile      EvidenceType = "workflow_file"
	EvidenceRunURL            EvidenceType = "run_url"
	EvidencePRURL             EvidenceType = "pr_url"
	EvidenceAPIResponse       EvidenceType = "api_response"
	EvidenceEnvironmentConfig EvidenceType = "environment_config"
)

// Evidence is a raw artifact that backs a compliance finding.
type Evidence struct {
	Type        EvidenceType `json:"type"`
	Description string       `json:"description"`
	URL         string       `json:"url"`
	Ref         string       `json:"ref"`
	CollectedAt time.Time    `json:"collected_at"`
	Raw         string       `json:"raw,omitempty"`
}

// Finding is a single check result for a specific target.
type Finding struct {
	CheckID     string      `json:"check_id"`
	CheckTitle  string      `json:"check_title"`
	Controls    []ControlID `json:"controls"`
	Status      Status      `json:"status"`
	Severity    Severity    `json:"severity"`
	Target      string      `json:"target"`
	Message     string      `json:"message"`
	Detail      string      `json:"detail,omitempty"`
	Evidence    []Evidence  `json:"evidence"`
	EvaluatedAt time.Time   `json:"evaluated_at"`
}

// CheckResult holds all findings produced by a single check.
type CheckResult struct {
	CheckID  string    `json:"check_id"`
	Findings []Finding `json:"findings"`
}

// Period defines a time range for run history lookup.
type Period struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ReportSummary contains aggregate counts for an audit.
type ReportSummary struct {
	TotalFindings   int                  `json:"total_findings"`
	CountByStatus   map[Status]int       `json:"count_by_status"`
	CountBySeverity map[Severity]int     `json:"count_by_severity"`
	ControlStatus   map[ControlID]Status `json:"control_status"`
}

// AuditReport is the top-level output of a compliance audit.
type AuditReport struct {
	ID           string        `json:"id"`
	Org          string        `json:"org"`
	Repos        []string      `json:"repos"`
	Frameworks   []Framework   `json:"frameworks"`
	Period       Period        `json:"period"`
	GeneratedAt  time.Time     `json:"generated_at"`
	Summary      ReportSummary `json:"summary"`
	CheckResults []CheckResult `json:"check_results"`
}
