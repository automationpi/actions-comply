package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/automationpi/actions-comply/pkg/models"
)

// checkExplainer provides human-friendly context for each check group.
type checkExplainer struct {
	Title    string
	Why      string
	Risk     string
	FixHint  string
	Controls string
}

var checkExplainers = map[string]checkExplainer{
	"permissions.workflow_overage": {
		Title: "Workflow Permissions",
		Why: "GitHub Actions workflows run with a token that has access to your repository. " +
			"If the token has more permissions than needed (e.g., write access to packages " +
			"when it only reads code), a compromised action or script injection can do far " +
			"more damage than necessary.",
		Risk: "Over-permissioned tokens violate least-privilege and expand the blast radius " +
			"of supply-chain attacks. Auditors flag this under access control (SOC2 CC6.1).",
		FixHint: "Add an explicit 'permissions:' block at the top of every workflow. " +
			"Start with 'contents: read' and only add write scopes that a step actually needs.",
		Controls: "SOC2 CC6.1 (Logical Access)  |  ISO 27001 A.9.4 (System Access Control)",
	},
	"supplychain.action_bom": {
		Title: "Action Bill of Materials",
		Why: "Every third-party GitHub Action you use is code that runs inside your CI/CD " +
			"pipeline with access to your secrets and source code. Knowing exactly which " +
			"actions you depend on is step one of supply-chain security.",
		Risk: "Without an inventory, you cannot track which actions are maintained, which " +
			"have known vulnerabilities, or which have been silently replaced.",
		FixHint: "This is an informational check — review the BOM periodically and remove " +
			"actions that are no longer maintained or needed.",
		Controls: "SOC2 CC9.2 (Risk Assessment)  |  ISO 27001 A.15.1 (Supplier Relationships)",
	},
	"supplychain.unpinned_actions": {
		Title: "Action SHA Pinning",
		Why: "When you reference an action with a tag like '@v4', the tag owner can " +
			"push new code to that tag at any time. Your workflow silently picks up " +
			"the change on the next run — you have no review, no diff, no approval.",
		Risk: "This is the #1 GitHub Actions supply-chain risk. An attacker who compromises " +
			"an action repo can push malicious code to an existing tag and it will run " +
			"in every workflow that references it. Pinning to a full SHA prevents this.",
		FixHint: "Replace 'actions/checkout@v4' with 'actions/checkout@<full-40-char-sha>'. " +
			"Add a comment with the tag for readability. Use Dependabot or Renovate to " +
			"get PRs when new versions are released.",
		Controls: "SOC2 CC9.2 (Risk Assessment)  |  ISO 27001 A.15.1, A.14.2 (Supply Chain, Secure Dev)",
	},
	"securedev.scan_coverage": {
		Title: "Security Scan Coverage",
		Why: "Pull request workflows are the last gate before code merges. If no security " +
			"scanner (SAST, SCA, secrets detection) runs on PRs, vulnerabilities and " +
			"leaked credentials can reach your default branch undetected.",
		Risk: "Missing scan coverage means you cannot demonstrate to auditors that code " +
			"is reviewed for security issues before deployment. This is a core secure " +
			"development requirement.",
		FixHint: "Add at least one scanner to your PR workflow: GitHub CodeQL (free SAST), " +
			"Trivy (container/SCA), Gitleaks (secrets), or Semgrep (custom rules).",
		Controls: "SOC2 CC7.2 (Security Monitoring)  |  ISO 27001 A.14.2 (Secure Development)",
	},
	"changetrail.deploy_approval": {
		Title: "Deploy Approval Gates",
		Why: "Production deployments without an approval gate mean any push to main can " +
			"go straight to production. There is no human review, no separation of duties, " +
			"and no audit trail linking a deployment to a specific change and approver.",
		Risk: "This is a critical control for SOC2 — auditors need to see that every " +
			"production change was reviewed and approved by someone other than the author. " +
			"Without environment protection rules, you cannot demonstrate this.",
		FixHint: "Add 'environment: production' to deploy jobs and configure required " +
			"reviewers in GitHub repository Settings > Environments. This creates an " +
			"approval gate with a full audit trail.",
		Controls: "SOC2 CC8.1 (Change Management)  |  ISO 27001 A.12.1 (Operations Security)",
	},
}

// executiveSummary generates a plain-English summary based on findings.
func executiveSummary(totalFindings int, fails int, criticals int, checks map[string]int) []string {
	var lines []string

	if fails == 0 {
		lines = append(lines,
			"Your GitHub Actions workflows passed all compliance checks. No issues were",
			"found that would require remediation before an audit. Continue to run this",
			"audit regularly to maintain compliance posture.")
		return lines
	}

	// Severity context
	if criticals > 0 {
		lines = append(lines,
			fmt.Sprintf("This audit found %d compliance issues, including %d critical findings", fails, criticals),
			"that should be addressed before your next audit review. Critical findings",
			"represent missing controls that auditors will flag as exceptions.")
	} else {
		lines = append(lines,
			fmt.Sprintf("This audit found %d compliance issues across your GitHub Actions workflows.", fails),
			"None are critical, but they represent gaps that auditors may question during",
			"your SOC2 or ISO 27001 review.")
	}

	lines = append(lines, "")

	// Top priorities
	lines = append(lines, "Priority areas to address:")
	lines = append(lines, "")

	if n, ok := checks["changetrail.deploy_approval"]; ok && n > 0 {
		lines = append(lines, fmt.Sprintf("  1. Deploy Approval Gates (%d issues) — Production jobs without", n))
		lines = append(lines, "     environment protection. This is the most auditor-visible gap.")
	}
	if n, ok := checks["supplychain.unpinned_actions"]; ok && n > 0 {
		lines = append(lines, fmt.Sprintf("  2. SHA Pinning (%d issues) — Actions using mutable tags instead", n))
		lines = append(lines, "     of commit SHAs. High supply-chain risk, easy to fix.")
	}
	if n, ok := checks["securedev.scan_coverage"]; ok && n > 0 {
		lines = append(lines, fmt.Sprintf("  3. Scan Coverage (%d issues) — PR workflows without security", n))
		lines = append(lines, "     scanners. Add CodeQL or Trivy to close this gap.")
	}
	if n, ok := checks["permissions.workflow_overage"]; ok && n > 0 {
		lines = append(lines, fmt.Sprintf("  4. Permissions (%d issues) — Over-provisioned or missing", n))
		lines = append(lines, "     permission blocks. Quick wins for least-privilege.")
	}

	return lines
}

// scopeAndMethodology returns text explaining what was audited and how.
func scopeAndMethodology(org string, repos []string, workflowCount int, frameworks []string) []string {
	return []string{
		"SCOPE",
		"",
		fmt.Sprintf("This audit covers the CI/CD pipeline configuration for %s across %d", org, len(repos)),
		fmt.Sprintf("repository(ies): %s.", truncForText(joinStrings(repos), 90)),
		fmt.Sprintf("A total of %d GitHub Actions workflow files were analysed.", workflowCount),
		"",
		"The audit evaluates compliance against the following frameworks:",
		fmt.Sprintf("  %s", joinStrings(frameworks)),
		"",
		"METHODOLOGY",
		"",
		"All checks are deterministic and rule-based — no AI or probabilistic analysis is used.",
		"Each finding is backed by a direct reference to a workflow file, job, or step. The audit",
		"covers five control areas:",
		"",
		"  1. Permissions — Least-privilege analysis of GITHUB_TOKEN scopes",
		"  2. Supply Chain — Inventory and SHA-pinning status of third-party actions",
		"  3. Secure Development — Security scanner presence in PR workflows",
		"  4. Change Trail — Deployment approval gates and environment protection",
		"  5. Action BOM — Complete bill of materials for third-party dependencies",
		"",
		"LIMITATIONS",
		"",
		"This audit covers workflow file configuration only. It does not assess:",
		"  - Branch protection rules (evaluated at the GitHub API level, not in YAML)",
		"  - Runtime behavior of actions or scripts",
		"  - Network controls, data encryption, or HR processes",
		"  - GitHub Enterprise Server-specific configurations",
		"  - Repository-level secrets management",
	}
}

// whatsWorkingWell generates positive findings — what the org is doing right.
func whatsWorkingWell(passCount int, totalCount int, checkPasses map[string][]string) []string {
	var lines []string

	if passCount == 0 {
		return lines
	}

	pct := 0
	if totalCount > 0 {
		pct = passCount * 100 / totalCount
	}

	lines = append(lines,
		fmt.Sprintf("%d of %d checks passed (%d%%). The following areas are well-configured:", passCount, totalCount, pct),
		"")

	order := []struct {
		id    string
		title string
	}{
		{"permissions.workflow_overage", "Workflow Permissions"},
		{"supplychain.unpinned_actions", "Action SHA Pinning"},
		{"securedev.scan_coverage", "Security Scan Coverage"},
		{"changetrail.deploy_approval", "Deploy Approval Gates"},
		{"supplychain.action_bom", "Action Inventory"},
	}

	for _, o := range order {
		passes, ok := checkPasses[o.id]
		if !ok || len(passes) == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s — %d workflows compliant", o.title, len(passes)))
		limit := 3
		if len(passes) < limit {
			limit = len(passes)
		}
		for _, p := range passes[:limit] {
			lines = append(lines, fmt.Sprintf("    %s", truncForText(p, 85)))
		}
		if len(passes) > 3 {
			lines = append(lines, fmt.Sprintf("    + %d more", len(passes)-3))
		}
	}

	return lines
}

// checkDisplayName returns a human-friendly name for a check ID.
func checkDisplayName(checkID string) string {
	// Workflow check explainers
	if exp, ok := checkExplainers[checkID]; ok {
		return exp.Title
	}
	// Scorecard check names
	scorecardNames := map[string]string{
		"scorecard.pinned_dependencies": "Pinned Dependencies",
		"scorecard.token_permissions":   "Token Permissions",
		"scorecard.branch_protection":   "Branch Protection",
		"scorecard.code_review":         "Code Review",
		"scorecard.sast":                "Static Analysis (SAST)",
		"scorecard.dangerous_workflow":  "Dangerous Workflow Patterns",
		"scorecard.vulnerabilities":     "Known Vulnerabilities",
		"scorecard.dependency_updates":  "Dependency Update Tool",
		"scorecard.security_policy":     "Security Policy",
		"scorecard.license":             "License",
		"scorecard.binary_artifacts":    "Binary Artifacts",
		"scorecard.fuzzing":             "Fuzz Testing",
		"scorecard.maintained":          "Project Maintenance",
		"scorecard.ci_tests":            "CI Tests",
		"scorecard.signed_releases":     "Signed Releases",
		"scorecard.contributors":        "Contributor Diversity",
		"scorecard.packaging":           "Release Packaging",
		"scorecard.best_practices":      "OpenSSF Best Practices",
	}
	if name, ok := scorecardNames[checkID]; ok {
		return name
	}
	return checkID
}

// ── Control Descriptions ─────────────────────────────────────────────────

// controlDescription provides the human-readable name and description for a control.
type controlDescription struct {
	Name        string
	Description string
	Framework   string // "SOC2" or "ISO27001"
}

// controlDescriptions maps ControlID to its human-readable details.
var controlDescriptions = map[models.ControlID]controlDescription{
	// SOC2 Trust Services Criteria
	"SOC2-CC1.1": {
		Name:        "Control Environment",
		Description: "The entity demonstrates a commitment to integrity and ethical values.",
		Framework:   "SOC2",
	},
	"SOC2-CC2.2": {
		Name:        "Communication and Information",
		Description: "The entity internally and externally communicates information necessary to achieve objectives.",
		Framework:   "SOC2",
	},
	"SOC2-CC6.1": {
		Name:        "Logical Access Controls",
		Description: "The entity implements logical access security software, infrastructure, and architectures to protect information assets from unauthorized access.",
		Framework:   "SOC2",
	},
	"SOC2-CC7.2": {
		Name:        "Security Monitoring",
		Description: "The entity monitors system components and the operation of those components for anomalies and security events.",
		Framework:   "SOC2",
	},
	"SOC2-CC8.1": {
		Name:        "Change Management",
		Description: "Changes to infrastructure and software are authorized, designed, developed, tested, and approved before implementation.",
		Framework:   "SOC2",
	},
	"SOC2-CC9.2": {
		Name:        "Risk Assessment",
		Description: "The entity identifies, assesses, and manages risks to the achievement of its objectives, including supply-chain risks.",
		Framework:   "SOC2",
	},
	// ISO 27001 Annex A
	"ISO27001-A.9.4": {
		Name:        "System Access Control",
		Description: "Prevent unauthorized access to systems and applications through technical controls and policy enforcement.",
		Framework:   "ISO27001",
	},
	"ISO27001-A.12.1": {
		Name:        "Operational Procedures and Responsibilities",
		Description: "Ensure correct and secure operations of information processing facilities through documented procedures.",
		Framework:   "ISO27001",
	},
	"ISO27001-A.12.6": {
		Name:        "Technical Vulnerability Management",
		Description: "Prevent exploitation of technical vulnerabilities through timely identification and remediation.",
		Framework:   "ISO27001",
	},
	"ISO27001-A.14.2": {
		Name:        "Security in Development and Support",
		Description: "Ensure that information security is designed and implemented within the development lifecycle.",
		Framework:   "ISO27001",
	},
	"ISO27001-A.15.1": {
		Name:        "Information Security in Supplier Relationships",
		Description: "Ensure protection of the organization's assets that are accessible by suppliers.",
		Framework:   "ISO27001",
	},
	"ISO27001-A.16.1": {
		Name:        "Management of Information Security Incidents",
		Description: "Ensure a consistent and effective approach to the management of information security incidents.",
		Framework:   "ISO27001",
	},
	"ISO27001-A.18.1": {
		Name:        "Compliance with Legal and Contractual Requirements",
		Description: "Avoid breaches of legal, statutory, regulatory, or contractual obligations related to information security.",
		Framework:   "ISO27001",
	},
}

// ── Statement of Applicability (ISO 27001) ──────────────────────────────

// soaRow represents a single row in the Statement of Applicability.
type soaRow struct {
	ControlID     models.ControlID
	ControlName   string
	Applicable    string // "Yes" or "No"
	Status        string // "Implemented", "Partially Implemented", "Not Implemented"
	Evidence      string // check ID that tested it
	Justification string
}

// buildSoA generates Statement of Applicability rows from report data.
func buildSoA(report *models.AuditReport) []soaRow {
	// Collect all ISO controls from findings
	isoControls := make(map[models.ControlID]bool)
	controlToChecks := make(map[models.ControlID][]string)
	for _, cr := range report.CheckResults {
		for _, f := range cr.Findings {
			for _, ctrl := range f.Controls {
				if strings.HasPrefix(string(ctrl), "ISO27001") {
					isoControls[ctrl] = true
					// Deduplicate check IDs
					found := false
					for _, c := range controlToChecks[ctrl] {
						if c == cr.CheckID {
							found = true
							break
						}
					}
					if !found {
						controlToChecks[ctrl] = append(controlToChecks[ctrl], cr.CheckID)
					}
				}
			}
		}
	}

	// Also include ISO controls from controlDescriptions that are in scope
	for ctrl := range controlDescriptions {
		if strings.HasPrefix(string(ctrl), "ISO27001") {
			if _, inReport := report.Summary.ControlStatus[ctrl]; inReport {
				isoControls[ctrl] = true
			}
		}
	}

	// Sort controls
	var sorted []models.ControlID
	for ctrl := range isoControls {
		sorted = append(sorted, ctrl)
	}
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })

	var rows []soaRow
	for _, ctrl := range sorted {
		desc := controlDescriptions[ctrl]
		status := report.Summary.ControlStatus[ctrl]

		implStatus := "Implemented"
		justification := "Verified by automated compliance checks"
		switch status {
		case models.StatusFail:
			implStatus = "Not Implemented"
			justification = "Automated checks identified gaps requiring remediation"
		case models.StatusWarn:
			implStatus = "Partially Implemented"
			justification = "Controls are partially in place; improvements recommended"
		case models.StatusPass:
			implStatus = "Implemented"
			justification = "All automated checks passed for this control"
		default:
			implStatus = "Not Assessed"
			justification = "Control not evaluated in this audit scope"
		}

		evidence := strings.Join(controlToChecks[ctrl], ", ")
		if evidence == "" {
			evidence = "-"
		}

		rows = append(rows, soaRow{
			ControlID:     ctrl,
			ControlName:   desc.Name,
			Applicable:    "Yes",
			Status:        implStatus,
			Evidence:      evidence,
			Justification: justification,
		})
	}
	return rows
}

// ── Tests of Controls (SOC2) ────────────────────────────────────────────

// tocRow represents a row in the SOC2 Tests of Controls table.
type tocRow struct {
	ControlObjective string // e.g., "CC8.1 — Change Management"
	ControlActivity  string // what the org does
	TestPerformed    string // what actions-comply checked
	TestResult       string // "Pass", "Fail", "Warn" with count
	ResultColor      rgb
	EvidenceRef      string // check IDs
}

// buildTestsOfControls generates SOC2 test-of-controls rows from report data.
func buildTestsOfControls(report *models.AuditReport) []tocRow {
	// Map SOC2 controls to their check results
	type controlData struct {
		checks []string
		pass   int
		fail   int
		warn   int
	}
	soc2Controls := make(map[models.ControlID]*controlData)

	for _, cr := range report.CheckResults {
		for _, f := range cr.Findings {
			for _, ctrl := range f.Controls {
				if !strings.HasPrefix(string(ctrl), "SOC2") {
					continue
				}
				cd, ok := soc2Controls[ctrl]
				if !ok {
					cd = &controlData{}
					soc2Controls[ctrl] = cd
				}
				// Deduplicate
				found := false
				for _, c := range cd.checks {
					if c == cr.CheckID {
						found = true
						break
					}
				}
				if !found {
					cd.checks = append(cd.checks, cr.CheckID)
				}
				switch f.Status {
				case models.StatusPass:
					cd.pass++
				case models.StatusFail:
					cd.fail++
				case models.StatusWarn:
					cd.warn++
				}
			}
		}
	}

	// Sort controls
	var sorted []models.ControlID
	for ctrl := range soc2Controls {
		sorted = append(sorted, ctrl)
	}
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })

	// controlActivity maps SOC2 controls to what the org does
	controlActivities := map[models.ControlID]string{
		"SOC2-CC1.1": "Organization follows OpenSSF security best practices",
		"SOC2-CC2.2": "Security policy published for vulnerability disclosure",
		"SOC2-CC6.1": "Workflow tokens scoped to least-privilege; access controlled",
		"SOC2-CC7.2": "Security scanners run on PRs; vulnerabilities tracked",
		"SOC2-CC8.1": "Production deploys require environment approval; changes reviewed",
		"SOC2-CC9.2": "Third-party actions inventoried, pinned, and monitored",
	}

	// testDescriptions maps SOC2 controls to what was tested
	testDescriptions := map[models.ControlID]string{
		"SOC2-CC1.1": "Checked for OpenSSF Best Practices badge",
		"SOC2-CC2.2": "Verified SECURITY.md or equivalent disclosure policy exists",
		"SOC2-CC6.1": "Analysed GITHUB_TOKEN permissions in all workflows for least-privilege",
		"SOC2-CC7.2": "Verified security scanners (SAST, SCA, secrets) present in PR workflows",
		"SOC2-CC8.1": "Checked deploy jobs for environment protection rules and code review",
		"SOC2-CC9.2": "Verified actions are SHA-pinned; generated bill of materials",
	}

	var rows []tocRow
	for _, ctrl := range sorted {
		cd := soc2Controls[ctrl]
		desc := controlDescriptions[ctrl]

		// Short control ID for display (e.g., "CC8.1")
		shortID := strings.TrimPrefix(string(ctrl), "SOC2-")
		objective := fmt.Sprintf("%s — %s", shortID, desc.Name)

		activity := controlActivities[ctrl]
		if activity == "" {
			activity = desc.Description
		}
		test := testDescriptions[ctrl]
		if test == "" {
			test = "Automated compliance check"
		}

		var result string
		var resultCol rgb
		if cd.fail > 0 {
			result = fmt.Sprintf("Fail (%d)", cd.fail)
			resultCol = colRed
		} else if cd.warn > 0 {
			result = fmt.Sprintf("Warn (%d)", cd.warn)
			resultCol = colAmber
		} else {
			result = fmt.Sprintf("Pass (%d)", cd.pass)
			resultCol = colGreen
		}

		rows = append(rows, tocRow{
			ControlObjective: objective,
			ControlActivity:  activity,
			TestPerformed:    test,
			TestResult:       result,
			ResultColor:      resultCol,
			EvidenceRef:      strings.Join(cd.checks, ", "),
		})
	}
	return rows
}

// ── Corrective Action Plan ──────────────────────────────────────────────

// capRow represents a row in the Corrective Action Plan.
type capRow struct {
	Finding     string
	Severity    models.Severity
	Controls    string
	Action      string
	Owner       string // blank — to be filled by org
	TargetDate  string // blank — to be filled by org
	Status      string // "Open"
}

// buildCorrectiveActionPlan extracts failing/warning findings into remediation rows.
func buildCorrectiveActionPlan(report *models.AuditReport) []capRow {
	var rows []capRow
	for _, cr := range report.CheckResults {
		for _, g := range groupFindings(cr) {
			if g.Status != models.StatusFail && g.Status != models.StatusWarn {
				continue
			}

			// Collect controls from findings
			ctrlSet := make(map[models.ControlID]bool)
			for _, f := range cr.Findings {
				if f.Message == g.Message {
					for _, c := range f.Controls {
						ctrlSet[c] = true
					}
				}
			}
			var ctrlStrs []string
			for c := range ctrlSet {
				ctrlStrs = append(ctrlStrs, string(c))
			}
			sort.Strings(ctrlStrs)

			action := g.Detail
			if action == "" {
				if exp, ok := checkExplainers[cr.CheckID]; ok {
					action = exp.FixHint
				}
			}
			if action == "" {
				action = "Review and remediate finding"
			}

			rows = append(rows, capRow{
				Finding:    truncStr(g.Message, 80),
				Severity:   g.Severity,
				Controls:   strings.Join(ctrlStrs, ", "),
				Action:     action,
				Owner:      "",
				TargetDate: "",
				Status:     "Open",
			})
		}
	}
	return rows
}

func joinStrings(ss []string) string {
	return fmt.Sprintf("%s", strings.Join(ss, ", "))
}

func truncForText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
