package report

import "fmt"

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
