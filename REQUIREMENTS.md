# actions-comply — Requirements

**GitHub Actions Compliance Auditor**
Product Requirements Document | v1.0

---

## 1. Overview

actions-comply is an open-source Go CLI tool and GitHub Action that audits GitHub Actions workflows for compliance with SOC2 Trust Services Criteria and ISO 27001 Annex A controls. It produces evidence packages, structured reports, and GitHub Step Summaries that platform teams and DevOps leads can hand directly to auditors.

v1.0 scope is the **Deterministic Core**: purely algorithmic check engine with no AI dependency. Every finding links to a raw artifact (workflow file URL, run URL, PR URL) so compliance claims are always backed by evidence.

## 2. Problem Statement

### 2.1 The Gap

Full GRC platforms (Vanta, Drata) integrate with GitHub at the surface level: branch protection on/off, repository visibility, user access counts. They do not look inside workflow files, track action versions, or produce deploy chains linking production deployments to authorising PRs.

This leaves a CI/CD-specific evidence layer that every company using GitHub Actions must assemble manually — typically 2-4 weeks per audit cycle.

### 2.2 Target Users

| Persona | Pain |
|---------|------|
| Series A/B startup CTO | First SOC2 needed to close enterprise deal. No GRC team. |
| Mid-size SaaS DevOps lead | Annual SOC2 renewal. Vanta covers 80% but CI/CD layer is manual. |
| Platform engineer (100+ teams) | Needs continuous compliance posture across hundreds of repos. |
| Compliance/security engineer | Owns evidence package assembly. Currently spreadsheets and screenshots. |

## 3. Goals & Non-Goals

### Goals

- Automate evidence collection for CI/CD-layer controls (SOC2 + ISO 27001)
- Produce auditor-ready evidence packages with every finding linked to a raw artifact
- Run as GitHub Action (zero-config) or local CLI
- Completely deterministic — rule-based, never probabilistic
- Support offline/air-gapped operation via local workflow file directory
- Zero external dependencies beyond Go stdlib

### Non-Goals (v1)

- Not a replacement for Vanta/Drata
- No AI (deferred to v2)
- No network controls, HR, data classification, or encryption at rest auditing
- No auto-remediation — suggests fixes, never applies them
- No GitHub Enterprise Server support

## 4. Architecture

### 4.1 Layers

| Layer | Package | Responsibility |
|-------|---------|----------------|
| Models | `pkg/models` | Domain types: Finding, CheckResult, AuditReport, WorkflowFile, Evidence |
| YAML Parser | `internal/yaml` | Parse GitHub Actions YAML using Go stdlib only |
| Check Engine | `internal/checks/*` | One sub-package per check group, implements Check interface |
| Engine | `internal/engine` | Orchestrates check execution, aggregates results, computes summary |
| Report | `internal/report` | Renders text, JSON, GitHub Step Summary, evidence package |
| GitHub Client | `internal/github` | Abstracts GitHub API behind interface |
| CLI | `cmd/comply` | Entry point, flags, sub-commands, exit codes |

### 4.2 Check Interface

```go
type Check interface {
    ID()          string
    Title()       string
    Description() string
    Controls()    []models.ControlID
    Severity()    models.Severity
    Run(ctx *CheckContext) (*models.CheckResult, error)
}
```

`CheckContext` carries pre-fetched workflows, run history, and a `GitHubClient` interface. Checks never call GitHub API directly.

### 4.3 Evidence Principle

Every `Finding` must carry at least one `Evidence` struct with a URL pointing to the raw artifact. A finding without evidence is invalid.

Evidence types: `workflow_file`, `run_url`, `pr_url`, `api_response`, `environment_config`.

## 5. Check Specifications

### 5.1 Permissions Audit (`permissions.workflow_overage`)

| Field | Value |
|-------|-------|
| Controls | SOC2 CC6.1, ISO 27001 A.9.4 |
| Default severity | High (Critical for write-all) |
| Data source | Workflow YAML (static analysis) |

**Rules:**
- **FAIL (Critical):** `permissions: write-all` at top level
- **FAIL (High):** Write scope declared with no known step requiring write access (per stepUsageMap)
- **WARN (Medium):** No explicit permissions block — defaults apply
- **WARN:** Job-level write scope with no matching step need
- **PASS:** Explicit permissions block, no over-provisioned write scopes

**stepUsageMap (built-in, extensible):**

| Action | Required Permission |
|--------|-------------------|
| `actions/checkout` | `contents:read` |
| `actions/upload-artifact` | `contents:read` |
| `github/codeql-action` | `security-events:write` |
| `softprops/action-gh-release` | `contents:write` |
| `docker/build-push-action` | `packages:write` |

### 5.2 Supply Chain — Action BOM (`supplychain.action_bom`)

| Field | Value |
|-------|-------|
| Controls | SOC2 CC9.2, ISO 27001 A.15.1 |
| Default severity | Info |
| Data source | Workflow YAML (static analysis) |

**Rules:**
- Inventories every third-party action reference across all workflow files
- One INFO finding per unique action with repo, workflow path, and version as evidence
- Local (`./path`) and Docker (`docker://`) actions noted but not flagged
- Exportable as CSV

### 5.3 Supply Chain — SHA Pinning (`supplychain.unpinned_actions`)

| Field | Value |
|-------|-------|
| Controls | SOC2 CC9.2, ISO 27001 A.15.1, A.14.2 |
| Default severity | High |
| Data source | Workflow YAML (static analysis) |

**Rules:**
- **FAIL (High):** Action pinned to mutable tag (`v1`, `main`, `latest`) instead of 40-char hex SHA
- **FAIL (High):** Action version in KnownRiskyVersions map
- **PASS:** Action pinned to full 40-character hex SHA
- Local and Docker actions skipped

**SHA detection:** version is SHA iff `len == 40` AND all chars are `[0-9a-fA-F]`.

### 5.4 Secure Development — Scan Coverage (`securedev.scan_coverage`)

| Field | Value |
|-------|-------|
| Controls | ISO 27001 A.14.2, SOC2 CC7.2 |
| Default severity | High |
| Data source | Workflow YAML (static analysis) |

**Rules:**
- **FAIL (High):** PR workflow contains no step matching knownScanners map
- **WARN (Medium):** No `pull_request` triggered workflows found
- **PASS:** At least one scanner step in PR workflow

**knownScanners (built-in, extensible):**

| Action | Type |
|--------|------|
| `github/codeql-action/analyze` | SAST (CodeQL) |
| `aquasecurity/trivy-action` | SCA/Container (Trivy) |
| `snyk/actions` | SCA (Snyk) |
| `semgrep/semgrep-action` | SAST (Semgrep) |
| `gitleaks/gitleaks-action` | Secrets (Gitleaks) |
| `trufflesecurity/trufflehog` | Secrets (TruffleHog) |

### 5.5 Change Trail — Deploy Approval (`changetrail.deploy_approval`)

| Field | Value |
|-------|-------|
| Controls | SOC2 CC8.1, ISO 27001 A.12.1 |
| Default severity | Critical |
| Data source | Workflow YAML + GitHub API run history |

**Static rules (YAML):**
- **FAIL (Critical):** Production job (environment matches prodEnvironments OR job name contains deploy/release/prod) has no `environment:` key
- **WARN (High):** Workflow triggers on push without pull_request — deploys may bypass PR review
- **PASS:** Production job has `environment:` key configured

**Run history rules (GitHub API):**
- **PASS:** Production run linked to PR with approver
- **WARN:** Run linked to PR but no approver determined
- **FAIL (High):** Run triggered by direct push (no PR linkage)

**prodEnvironments:** `production`, `prod`, `live`, `release`, `prd`, `main`, `master` — configurable.

## 6. Data Models

### 6.1 Finding

| Field | Type | Description |
|-------|------|-------------|
| CheckID | string | e.g. `permissions.workflow_overage` |
| CheckTitle | string | Human-readable name |
| Controls | []ControlID | Framework controls evidenced |
| Status | Status | pass / fail / warn / skipped |
| Severity | Severity | critical / high / medium / low / info |
| Target | string | Repo/workflow path, job name |
| Message | string | One-line explanation |
| Detail | string | Technical detail + remediation |
| Evidence | []Evidence | Raw artifacts backing the finding |
| EvaluatedAt | time.Time | Evaluation timestamp |

### 6.2 Evidence

| Field | Type | Description |
|-------|------|-------------|
| Type | string | workflow_file / run_url / pr_url / api_response / environment_config |
| Description | string | What this evidence shows |
| URL | string | Direct link to raw artifact |
| Ref | string | SHA, run_id, PR number |
| CollectedAt | time.Time | When gathered |
| Raw | string | JSON excerpt or snippet |

### 6.3 AuditReport

| Field | Type | Description |
|-------|------|-------------|
| ID | string | `audit-{unix_timestamp}` |
| Org | string | GitHub org audited |
| Repos | []string | Repos in scope |
| Frameworks | []Framework | soc2 / iso27001 / both |
| Period | Period | From/To time range |
| GeneratedAt | time.Time | Generation timestamp |
| Summary | ReportSummary | Scorecard: counts by status/severity, per-control status |
| CheckResults | []CheckResult | One per check, containing all findings |

## 7. CLI Specification

### 7.1 Commands

| Command | Description |
|---------|-------------|
| `comply audit [flags]` | Run compliance audit |
| `comply bom [flags]` | Print action BOM as CSV |
| `comply diff --from DATE --to DATE` | Compare two audit reports |
| `comply version` | Print version |
| `comply help` | Show usage |

### 7.2 Audit Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--org` | string | `GITHUB_REPOSITORY_OWNER` | GitHub org to audit |
| `--repos` | string | (all) | Comma-separated repo list |
| `--framework` | string | `soc2,iso27001` | Frameworks |
| `--period` | int | 90 | Lookback days for run history |
| `--output` | string | `text` | Format: text/json/summary |
| `--out` | string | stdout | Output file path |
| `--fail-on` | string | `critical` | Exit 1 if finding >= severity |
| `--workflow-dir` | string | (none) | Local dir for offline mode |
| `--config` | string | (none) | Config file path |

### 7.3 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at/above `--fail-on` severity |
| 1 | Findings at/above `--fail-on` severity |
| 2 | Tool error |

### 7.4 Environment Variables

- `GITHUB_TOKEN` — API access token
- `GITHUB_REPOSITORY_OWNER` — Default org
- `ACTIONS_COMPLY_CONFIG` — Default config path

## 8. Output Formats

- **Text** — Terminal output with scorecard, per-control status, finding details
- **JSON** — Full `AuditReport` as indented JSON (stable schema)
- **GitHub Step Summary** — Markdown for `$GITHUB_STEP_SUMMARY`
- **CSV BOM** — Columns: repo, workflow_path, job_id, step_name, action_ref, owner, name, version, is_sha_pinned, risk_note
- **Evidence package** — Structured directory/ZIP organized by control ID

## 9. GitHub Actions Integration

```yaml
- uses: automationpi/actions-comply@v1
  with:
    framework: soc2,iso27001
    period: 90
    output: summary
    fail-on: critical
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Action outputs:** `total-findings`, `failed-findings`, `critical-count`, `report-path`, `passed`

## 10. Configuration File

`actions-comply.yml` at repo root or `--config` path:

```yaml
version: 1

step-usage-map:
  myorg/deploy-action: ["deployments:write", "environments:write"]

scanners:
  myorg/internal-sast: "SAST (internal)"

prod-environments:
  - production
  - prod-eu
  - prod-us

exclude:
  repos: ["org/sandbox"]
  workflows: [".github/workflows/experimental.yml"]
```

## 11. YAML Parser Specification

Stdlib-only line-by-line state machine (no third-party YAML libraries).

### 11.1 Required Fields

- `name:`, `on:` (triggers), `permissions:` (top-level)
- `jobs.<id>.name`, `.runs-on`, `.environment`, `.permissions`, `.needs`
- `jobs.<id>.steps[].uses`, `.run`, `.name`, `.if`

### 11.2 Action Reference Parsing

`ParseActionRef(raw)` handles:
- `owner/name@version` — standard
- `owner/name@40hexchars` — SHA-pinned (`IsSHA: true`)
- `./local/path` — local (`IsLocal: true`)
- `docker://image:tag` — Docker
- `owner/name` (no version) — unpinned

## 12. Testing

- Table-driven tests for all checks and parser
- Fixtures in `testdata/workflows/`
- 80% minimum line coverage for `internal/`
- No network calls in unit tests

### Test Fixtures

| File | Purpose |
|------|---------|
| `clean-ci.yml` | Ideal: explicit perms, SHA-pinned, CodeQL |
| `write-all.yml` | `permissions: write-all` (critical fail) |
| `unpinned.yml` | All mutable tags |
| `no-scanner.yml` | PR workflow, no scanner |
| `deploy-no-env.yml` | Prod deploy, no environment key |
| `deploy-with-env.yml` | Prod deploy with `environment: production` |

## 13. Milestones

| # | Deliverable | Success Criteria |
|---|-------------|-----------------|
| M1 | YAML parser + models + tests | All parser tests pass. ParseActionRef handles all 4 shapes. |
| M2 | Permissions + supply chain checks | write-all fails, SHA-pinned passes, unpinned fails. 80%+ coverage. |
| M3 | Secure dev + change trail checks | PR without scanner fails. Deploy without env fails. |
| M4 | Engine + report generator | Full audit on fixtures produces correct summary. Text + JSON + summary render. |
| M5 | CLI + GitHub Action | `comply audit --workflow-dir` works e2e. Exit codes correct. |
| M6 | Config file + BOM CSV + evidence package | stepUsageMap extensible. BOM exports. Evidence generates. |
| M7 | Self-audit pass | actions-comply passes its own audit with zero critical/high failures. |

## 14. Future (v2 — AI Layer)

Out of scope for v1 but architecture must not foreclose:
- Pluggable `AIProvider` interface (Anthropic, OpenAI, Google, Ollama)
- Remediation suggestions, narrative reports, intent classification
- SaaS product with continuous monitoring
