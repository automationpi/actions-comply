# actions-comply

**GitHub Actions Compliance Auditor for SOC2 and ISO 27001**

[![CI](https://github.com/automationpi/actions-comply/actions/workflows/ci.yml/badge.svg)](https://github.com/automationpi/actions-comply/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](go.mod)

**actions-comply** audits your GitHub Actions workflows for SOC2 Trust Services Criteria and ISO 27001 Annex A compliance. It produces auditor-ready PDF reports, evidence packages, and GitHub Step Summaries — replacing weeks of manual spreadsheet work with a single command.

---

## The Problem

Full GRC platforms (Vanta, Drata, Tugboat Logic) integrate with GitHub at the surface level: branch protection on/off, repository visibility, user access counts. They **do not look inside workflow files**, do not track action versions, and cannot produce a deploy chain linking a production deployment to the PR and approver that authorised it.

This leaves a layer of **CI/CD-specific evidence** that every company using GitHub Actions must assemble manually — typically costing a DevOps lead **2-4 weeks per audit cycle**.

### Who needs this

| Persona | Pain |
|---------|------|
| **Startup CTO** (Series A/B) | First SOC2 needed to close enterprise deals. No GRC team. GitHub Actions is the entire CI/CD stack. |
| **DevOps Lead** (mid-size SaaS) | Annual SOC2 renewal. Vanta covers 80% but CI/CD layer requires manual evidence gathering every time. |
| **Platform Engineer** (100+ teams) | Needs continuous compliance posture across hundreds of repos. No tooling exists at org level. |
| **Compliance Engineer** | Owns evidence package assembly. Currently: spreadsheets, screenshots, and Slack messages. |

## What It Does

actions-comply runs **5 compliance checks** that map directly to SOC2 and ISO 27001 controls:

| Check | What It Finds | Controls |
|-------|--------------|----------|
| **Workflow Permissions** | Over-provisioned GITHUB_TOKEN scopes, missing permission blocks, `write-all` declarations | SOC2 CC6.1, ISO 27001 A.9.4 |
| **Action SHA Pinning** | Third-party actions using mutable tags (`@v4`) instead of immutable SHA references | SOC2 CC9.2, ISO 27001 A.15.1 |
| **Security Scan Coverage** | PR workflows missing security scanners (CodeQL, Trivy, Semgrep, Gitleaks) | SOC2 CC7.2, ISO 27001 A.14.2 |
| **Deploy Approval Gates** | Production deploy jobs without environment protection rules or PR requirements | SOC2 CC8.1, ISO 27001 A.12.1 |
| **Action Bill of Materials** | Complete inventory of every third-party action across all workflows | SOC2 CC9.2, ISO 27001 A.15.1 |

Every finding is **backed by evidence** — a direct link to the workflow file, job, or step that triggered it. No inference, no AI, no guessing.

## Quick Start

### As a GitHub Action (recommended)

```yaml
- name: Compliance Audit
  uses: automationpi/actions-comply@main
  with:
    framework: soc2,iso27001
    output: summary
    fail-on: critical
```

The step summary renders directly in the GitHub Actions UI with pass/fail status for every control.

### With PDF Report as Artifact

```yaml
- name: Compliance Audit
  uses: automationpi/actions-comply@main
  with:
    output: summary
    fail-on: high

- name: Generate PDF Report
  if: always()
  uses: automationpi/actions-comply@main
  with:
    output: pdf
    fail-on: critical

- name: Upload Compliance Report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: compliance-report
    path: ${{ runner.temp }}/comply-report.pdf
```

### As a CLI

```bash
# Install
go install github.com/automationpi/actions-comply/cmd/comply@latest

# Audit local workflow files
comply audit --workflow-dir .github/workflows --org myorg --repos myrepo

# Generate PDF report
comply audit --workflow-dir .github/workflows --org myorg --repos myrepo \
  --output pdf --out compliance-report.pdf

# Export action BOM as CSV
comply bom --workflow-dir .github/workflows --repos myrepo

# JSON output for CI/CD integration
comply audit --workflow-dir .github/workflows --output json --out report.json
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| **Text** | `--output text` | Terminal output, human-readable |
| **JSON** | `--output json` | Machine-readable, CI/CD integration, Vanta/Drata ingestion |
| **GitHub Summary** | `--output summary` | Renders in GitHub Actions UI with emoji status indicators |
| **PDF** | `--output pdf` | Auditor-ready report with executive summary, control status, findings |
| **CSV BOM** | `comply bom` | Action bill of materials for supply chain review |
| **Evidence Package** | `--evidence-dir` | Structured directory organized by control ID for evidence lockers |

## PDF Report

The PDF report is designed to be handed directly to auditors or shared with non-technical stakeholders:

- **Dashboard** — Metric cards showing pass/fail/warn counts at a glance
- **Scope & Methodology** — What was audited, how, and explicit limitations
- **Executive Summary** — Prioritized action items in plain English
- **What's Working Well** — Passing controls with evidence (auditors want to see this)
- **Control Explanations** — WHY IT MATTERS / RISK / HOW TO FIX for each check
- **Detailed Findings** — Grouped by severity with color-coded cards and remediation guidance

See sample reports in the [`samples/`](samples/) directory.

## Configuration

Create `actions-comply.yml` in your repo root to customize:

```yaml
version: 1

# Add org-specific actions to the permission mapping
step-usage-map:
  myorg/deploy-action: ["deployments:write", "environments:write"]

# Add custom security scanners
scanners:
  myorg/internal-sast: "SAST (internal)"

# Customize production environment names
prod-environments:
  - production
  - prod-eu
  - prod-us

# Exclude repos or workflows from checks
exclude:
  repos: ["org/sandbox"]
  workflows: [".github/workflows/experimental.yml"]
```

```bash
comply audit --config actions-comply.yml --workflow-dir .github/workflows
```

## Action Inputs & Outputs

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `framework` | `soc2,iso27001` | Frameworks to audit |
| `period` | `90` | Lookback days for run history |
| `output` | `summary` | Output format: `text`, `json`, `summary`, `pdf` |
| `fail-on` | `critical` | Exit code 1 if finding at or above this severity |
| `config` | | Path to `actions-comply.yml` config file |
| `evidence-dir` | | Generate evidence package in this directory |

### Outputs

| Output | Description |
|--------|-------------|
| `total-findings` | Total number of findings |
| `failed-findings` | Number of FAIL status findings |
| `critical-count` | Number of critical severity findings |
| `report-path` | Path to generated report file |
| `passed` | `true` if no findings at or above `fail-on` severity |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Audit completed, no findings at or above `--fail-on` severity |
| `1` | Audit completed, findings at or above `--fail-on` severity |
| `2` | Tool error (config error, invalid flags) |

## Architecture

```
cmd/comply/              CLI entry point
internal/yaml/           GitHub Actions YAML parser (stdlib-only, any indentation)
internal/checks/         Check implementations
  permissions/           Workflow permission overage detection
  supplychain/           Action BOM + SHA pinning analysis
  securedev/             Security scan coverage verification
  changetrail/           Deploy approval gate enforcement
internal/engine/         Check orchestration and result aggregation
internal/report/         Output renderers (text, JSON, markdown, PDF, CSV, evidence)
internal/config/         Configuration file loader
pkg/models/              Domain types (Finding, CheckResult, AuditReport, Evidence)
testdata/workflows/      Test fixtures
```

**Zero third-party dependencies.** The entire tool — including the PDF renderer and YAML parser — is built using only the Go standard library.

## How It Works

1. **Parse** — Reads workflow YAML files using a line-by-line state machine that supports any indentation style (2-space, 4-space, tabs)
2. **Analyze** — Runs each check against parsed workflow data. Checks never call the GitHub API directly — they consume pre-loaded data
3. **Report** — Aggregates findings by control and severity, generates grouped output with evidence links
4. **Decide** — Exits with code 1 if any finding meets or exceeds the `--fail-on` threshold

Every check implements a single interface:

```go
type Check interface {
    ID()          string
    Title()       string
    Description() string
    Controls()    []ControlID
    Severity()    Severity
    Run(ctx *CheckContext) (*CheckResult, error)
}
```

## Tested Against Real-World Repos

actions-comply has been validated against production workflows from major open-source SaaS products:

| Repo | Workflows | Findings | Key Issues Found |
|------|-----------|----------|-----------------|
| PostHog/posthog | 70 | 769 | 543 unpinned actions, 50 missing scanners |
| metabase/metabase | 101 | 674 | 467 unpinned actions, 96 missing permissions |
| calcom/cal.com | 59 | 247 | 117 unpinned actions, 15 unprotected deploys |
| supabase/supabase | 44 | 271 | 157 unpinned actions, 22 missing scanners |
| novuhq/novu | 33 | 229 | 124 unpinned actions, 7 unprotected deploys |

## Comparison with Other Tools

| Feature | actions-comply | Vanta/Drata | StepSecurity | Scorecard |
|---------|---------------|-------------|--------------|-----------|
| Looks inside workflow files | Yes | No | Partial | Yes |
| SOC2/ISO 27001 control mapping | Yes | Yes (surface) | No | No |
| Auditor-ready PDF reports | Yes | Yes | No | No |
| Evidence packages | Yes | Yes | No | No |
| Deploy approval chain | Yes | No | No | No |
| Action BOM/inventory | Yes | No | No | Partial |
| Permission analysis | Yes | No | Yes | Partial |
| SHA pinning check | Yes | No | Yes | Yes |
| Zero dependencies | Yes | N/A | No | No |
| Self-hosted / air-gapped | Yes | No | No | No |
| Free & open source | Yes | No | Yes | Yes |

## Contributing

```bash
# Clone and build
git clone https://github.com/automationpi/actions-comply.git
cd actions-comply
go build -o comply ./cmd/comply

# Run tests
go test ./...

# Self-audit
./comply audit --workflow-dir .github/workflows --org automationpi --repos actions-comply
```

## License

MIT

---

**actions-comply** is built by [automationpi](https://github.com/automationpi). If it saves you time during your next SOC2 or ISO 27001 audit, give it a star.
