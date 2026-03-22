// Package scorecard maps OpenSSF Scorecard results to SOC2/ISO 27001 controls.
package scorecard

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/automationpi/actions-comply/pkg/models"
)

// ScorecardResult represents the top-level Scorecard JSON output.
type ScorecardResult struct {
	Date      string           `json:"date"`
	Repo      ScorecardRepo    `json:"repo"`
	Scorecard ScorecardMeta    `json:"scorecard"`
	Score     float64          `json:"score"`
	Checks    []ScorecardCheck `json:"checks"`
}

type ScorecardRepo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

type ScorecardMeta struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type ScorecardCheck struct {
	Name          string            `json:"name"`
	Score         int               `json:"score"`
	Reason        string            `json:"reason"`
	Details       []string          `json:"details"`
	Documentation ScorecardCheckDoc `json:"documentation"`
}

type ScorecardCheckDoc struct {
	URL   string `json:"url"`
	Short string `json:"short"`
}

// controlMapping maps Scorecard check names to compliance controls.
type controlMapping struct {
	Controls    []models.ControlID
	Category    string
	Why         string
	Severity    models.Severity
	PassMessage string
	FailMessage string
}

var scorecardControlMap = map[string]controlMapping{
	"Pinned-Dependencies": {
		Controls:    []models.ControlID{"SOC2-CC9.2", "ISO27001-A.15.1", "ISO27001-A.14.2"},
		Category:    "Supply Chain",
		Why:         "Unpinned dependencies can be silently modified by upstream maintainers, allowing supply-chain attacks to inject malicious code into your CI/CD pipeline.",
		Severity:    models.SeverityHigh,
		PassMessage: "All dependencies and actions are pinned to immutable references",
		FailMessage: "Some dependencies or actions use mutable references that can be changed without notice",
	},
	"Token-Permissions": {
		Controls:    []models.ControlID{"SOC2-CC6.1", "ISO27001-A.9.4"},
		Category:    "Access Control",
		Why:         "Workflow tokens with excessive permissions expand the blast radius of any compromised action or script injection, violating the principle of least privilege.",
		Severity:    models.SeverityHigh,
		PassMessage: "Workflow tokens follow least-privilege with explicit permission declarations",
		FailMessage: "Workflow tokens have excessive permissions — not all scopes are needed",
	},
	"Branch-Protection": {
		Controls:    []models.ControlID{"SOC2-CC8.1", "ISO27001-A.12.1", "ISO27001-A.9.4"},
		Category:    "Change Management",
		Why:         "Without branch protection, anyone with write access can push directly to production branches, bypassing code review and approval gates.",
		Severity:    models.SeverityCritical,
		PassMessage: "Branch protection rules enforce code review and status checks before merge",
		FailMessage: "Branch protection is missing or incomplete — direct pushes to main are possible",
	},
	"Code-Review": {
		Controls:    []models.ControlID{"SOC2-CC8.1", "ISO27001-A.12.1"},
		Category:    "Change Management",
		Why:         "Code review ensures that every change is seen by at least one other person before reaching production, providing separation of duties and catching errors early.",
		Severity:    models.SeverityHigh,
		PassMessage: "Changes require human code review before merge",
		FailMessage: "Code changes are merged without required human review",
	},
	"SAST": {
		Controls:    []models.ControlID{"SOC2-CC7.2", "ISO27001-A.14.2"},
		Category:    "Secure Development",
		Why:         "Static analysis tools catch vulnerabilities, bugs, and security issues before code reaches production, demonstrating proactive security testing.",
		Severity:    models.SeverityHigh,
		PassMessage: "Static analysis (SAST) tools are configured and running",
		FailMessage: "No static analysis tools detected — code is not automatically scanned for vulnerabilities",
	},
	"Dangerous-Workflow": {
		Controls:    []models.ControlID{"SOC2-CC6.1", "ISO27001-A.14.2"},
		Category:    "Secure Development",
		Why:         "Dangerous workflow patterns like pull_request_target with checkout can allow untrusted code to run with elevated privileges, enabling privilege escalation attacks.",
		Severity:    models.SeverityCritical,
		PassMessage: "No dangerous workflow patterns detected",
		FailMessage: "Dangerous workflow patterns found that could allow privilege escalation",
	},
	"Vulnerabilities": {
		Controls:    []models.ControlID{"SOC2-CC7.2", "ISO27001-A.12.6"},
		Category:    "Vulnerability Management",
		Why:         "Known vulnerabilities in dependencies represent exploitable weaknesses. Tracking and remediating them demonstrates active vulnerability management.",
		Severity:    models.SeverityCritical,
		PassMessage: "No known vulnerabilities detected in dependencies",
		FailMessage: "Known vulnerabilities exist in project dependencies",
	},
	"Dependency-Update-Tool": {
		Controls:    []models.ControlID{"SOC2-CC9.2", "ISO27001-A.15.1"},
		Category:    "Supply Chain",
		Why:         "Automated dependency update tools (Dependabot, Renovate) ensure that security patches are applied promptly and dependencies don't fall behind.",
		Severity:    models.SeverityMedium,
		PassMessage: "Automated dependency update tool is configured",
		FailMessage: "No automated dependency update tool detected — security patches may be missed",
	},
	"Security-Policy": {
		Controls:    []models.ControlID{"SOC2-CC2.2", "ISO27001-A.16.1"},
		Category:    "Incident Response",
		Why:         "A SECURITY.md file tells security researchers how to responsibly disclose vulnerabilities, reducing the risk of public zero-day disclosures.",
		Severity:    models.SeverityMedium,
		PassMessage: "Security policy (SECURITY.md) is published",
		FailMessage: "No security policy found — vulnerability reporters have no disclosure guidance",
	},
	"License": {
		Controls:    []models.ControlID{"ISO27001-A.18.1"},
		Category:    "Legal Compliance",
		Why:         "A clear license file ensures legal clarity for users and contributors, and demonstrates compliance with intellectual property requirements.",
		Severity:    models.SeverityLow,
		PassMessage: "License file detected",
		FailMessage: "No license file detected",
	},
	"Binary-Artifacts": {
		Controls:    []models.ControlID{"SOC2-CC8.1", "ISO27001-A.14.2"},
		Category:    "Secure Development",
		Why:         "Binary artifacts in source repos cannot be reviewed or audited, and could contain malicious code. All artifacts should be built from source in CI.",
		Severity:    models.SeverityHigh,
		PassMessage: "No binary artifacts found in the source repository",
		FailMessage: "Binary artifacts found in source — these cannot be code-reviewed",
	},
	"Fuzzing": {
		Controls:    []models.ControlID{"SOC2-CC7.2", "ISO27001-A.14.2"},
		Category:    "Secure Development",
		Why:         "Fuzz testing discovers edge-case bugs and security vulnerabilities by providing random inputs, catching issues that unit tests miss.",
		Severity:    models.SeverityLow,
		PassMessage: "Fuzz testing is configured",
		FailMessage: "No fuzz testing detected",
	},
	"Maintained": {
		Controls:    []models.ControlID{"SOC2-CC9.2"},
		Category:    "Supply Chain",
		Why:         "An actively maintained project is more likely to receive security patches and respond to vulnerability reports promptly.",
		Severity:    models.SeverityMedium,
		PassMessage: "Project shows active maintenance",
		FailMessage: "Project may not be actively maintained",
	},
	"CI-Tests": {
		Controls:    []models.ControlID{"SOC2-CC7.2", "ISO27001-A.14.2"},
		Category:    "Secure Development",
		Why:         "CI tests running on pull requests ensure that changes are validated before merge, catching regressions and broken functionality.",
		Severity:    models.SeverityMedium,
		PassMessage: "CI tests run on pull requests before merge",
		FailMessage: "No CI tests detected on pull requests",
	},
	"Signed-Releases": {
		Controls:    []models.ControlID{"SOC2-CC9.2", "ISO27001-A.14.2"},
		Category:    "Supply Chain",
		Why:         "Signed releases allow users to verify that artifacts haven't been tampered with, providing integrity guarantees for the software supply chain.",
		Severity:    models.SeverityLow,
		PassMessage: "Releases are signed",
		FailMessage: "Releases are not signed — artifact integrity cannot be verified",
	},
	"Contributors": {
		Controls:    []models.ControlID{"SOC2-CC9.2"},
		Category:    "Supply Chain",
		Why:         "Projects with diverse contributors from multiple organizations are less likely to be abandoned or have single points of failure.",
		Severity:    models.SeverityInfo,
		PassMessage: "Project has contributors from multiple organizations",
		FailMessage: "Project has limited organizational diversity in contributors",
	},
	"Packaging": {
		Controls:    []models.ControlID{"SOC2-CC8.1"},
		Category:    "Change Management",
		Why:         "Automated packaging workflows ensure consistent, reproducible builds and reduce the risk of human error in the release process.",
		Severity:    models.SeverityLow,
		PassMessage: "Packaging workflow detected",
		FailMessage: "No packaging workflow detected",
	},
	"CII-Best-Practices": {
		Controls:    []models.ControlID{"SOC2-CC1.1"},
		Category:    "Governance",
		Why:         "The OpenSSF Best Practices Badge demonstrates commitment to security best practices and provides a framework for continuous improvement.",
		Severity:    models.SeverityInfo,
		PassMessage: "OpenSSF Best Practices badge earned",
		FailMessage: "No OpenSSF Best Practices badge — consider applying at bestpractices.coreinfrastructure.org",
	},
}

// Parse reads Scorecard JSON from a reader.
func Parse(r io.Reader) (*ScorecardResult, error) {
	var result ScorecardResult
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		return nil, fmt.Errorf("parsing scorecard JSON: %w", err)
	}
	return &result, nil
}

// ToAuditReport converts Scorecard results into an actions-comply AuditReport
// with compliance control mappings.
func ToAuditReport(sc *ScorecardResult, org, repo string) *models.AuditReport {
	now := time.Now()

	report := &models.AuditReport{
		ID:          fmt.Sprintf("scorecard-%d", now.Unix()),
		Org:         org,
		Repos:       []string{repo},
		Frameworks:  []models.Framework{models.FrameworkSOC2, models.FrameworkISO27001},
		GeneratedAt: now,
		Summary: models.ReportSummary{
			TotalFindings:   0,
			CountByStatus:   make(map[models.Status]int),
			CountBySeverity: make(map[models.Severity]int),
			ControlStatus:   make(map[models.ControlID]models.Status),
		},
	}

	var checkResults []models.CheckResult

	for _, check := range sc.Checks {
		mapping, ok := scorecardControlMap[check.Name]
		if !ok {
			continue
		}

		cr := models.CheckResult{
			CheckID: fmt.Sprintf("scorecard.%s", toSnakeCase(check.Name)),
		}

		var status models.Status
		var severity models.Severity
		var message string

		switch {
		case check.Score < 0:
			// Inconclusive — skip
			status = models.StatusSkipped
			severity = models.SeverityInfo
			message = fmt.Sprintf("Scorecard could not evaluate: %s", check.Reason)
		case check.Score >= 8:
			status = models.StatusPass
			severity = models.SeverityInfo
			message = mapping.PassMessage
		case check.Score >= 5:
			status = models.StatusWarn
			severity = lowerSeverity(mapping.Severity)
			message = fmt.Sprintf("%s (score: %d/10)", mapping.FailMessage, check.Score)
		default:
			status = models.StatusFail
			severity = mapping.Severity
			message = fmt.Sprintf("%s (score: %d/10)", mapping.FailMessage, check.Score)
		}

		finding := models.Finding{
			CheckID:    cr.CheckID,
			CheckTitle: check.Name,
			Controls:   mapping.Controls,
			Status:     status,
			Severity:   severity,
			Target:     sc.Repo.Name,
			Message:    message,
			Detail:     fmt.Sprintf("%s\n\nScorecard reason: %s", mapping.Why, check.Reason),
			Evidence: []models.Evidence{
				{
					Type:        models.EvidenceAPIResponse,
					Description: fmt.Sprintf("OpenSSF Scorecard %s check (v%s)", check.Name, sc.Scorecard.Version),
					URL:         check.Documentation.URL,
					Ref:         fmt.Sprintf("score:%d/10", check.Score),
					CollectedAt: now,
					Raw:         check.Reason,
				},
			},
			EvaluatedAt: now,
		}

		cr.Findings = append(cr.Findings, finding)
		checkResults = append(checkResults, cr)

		// Update summary
		report.Summary.TotalFindings++
		report.Summary.CountByStatus[status]++
		report.Summary.CountBySeverity[severity]++

		for _, ctrl := range mapping.Controls {
			existing, exists := report.Summary.ControlStatus[ctrl]
			if !exists || statusRank(status) > statusRank(existing) {
				report.Summary.ControlStatus[ctrl] = status
			}
		}
	}

	report.CheckResults = checkResults
	return report
}

func toSnakeCase(s string) string {
	var result []byte
	for i, c := range s {
		if c == '-' {
			result = append(result, '_')
		} else if c >= 'A' && c <= 'Z' {
			if i > 0 {
				result = append(result, '_')
			}
			result = append(result, byte(c)+32)
		} else {
			result = append(result, byte(c))
		}
	}
	return string(result)
}

func lowerSeverity(s models.Severity) models.Severity {
	switch s {
	case models.SeverityCritical:
		return models.SeverityHigh
	case models.SeverityHigh:
		return models.SeverityMedium
	case models.SeverityMedium:
		return models.SeverityLow
	default:
		return s
	}
}

func statusRank(s models.Status) int {
	switch s {
	case models.StatusFail:
		return 3
	case models.StatusWarn:
		return 2
	case models.StatusPass:
		return 1
	default:
		return 0
	}
}
