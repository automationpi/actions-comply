# actions-comply

GitHub Actions Compliance Auditor — Go CLI & GitHub Action for SOC2/ISO 27001 CI/CD compliance.

## Project Overview

- **Language:** Go 1.23+ (stdlib only — no third-party dependencies)
- **License:** MIT
- **Version:** 1.0 — Deterministic Core (no AI)

## Architecture

```
cmd/comply/         — CLI entry point, sub-commands, flag parsing
internal/yaml/      — GitHub Actions YAML parser (stdlib line-by-line state machine)
internal/checks/    — Check implementations (one sub-package per check group)
internal/engine/    — Check orchestration, result aggregation, summary
internal/report/    — Output rendering: text, JSON, GitHub Step Summary, CSV BOM
internal/github/    — GitHub API client abstraction (interface-based, mockable)
pkg/models/         — Domain types: Finding, CheckResult, AuditReport, Evidence
```

## Key Principles

- **Zero third-party deps** — use only Go stdlib (including `encoding/json`, `strings`, `bufio` for YAML)
- **Evidence-backed findings** — every Finding must carry at least one Evidence with a URL
- **Check interface** — all checks implement `Check` with `ID()`, `Title()`, `Description()`, `Controls()`, `Severity()`, `Run()`
- **Checks never call GitHub API directly** — they consume data from `CheckContext`
- **Deterministic** — pass/fail is rule-based, never probabilistic

## Check Groups (v1)

| ID | Package | Severity |
|----|---------|----------|
| `permissions.workflow_overage` | `internal/checks/permissions` | High/Critical |
| `supplychain.action_bom` | `internal/checks/supplychain` | Info |
| `supplychain.unpinned_actions` | `internal/checks/supplychain` | High |
| `securedev.scan_coverage` | `internal/checks/securedev` | High |
| `changetrail.deploy_approval` | `internal/checks/changetrail` | Critical |

## Commands

```
go build -o comply ./cmd/comply
go test ./...
go test -coverprofile=coverage.out ./...
```

## Testing

- Table-driven tests for all checks and parser
- Test fixtures in `testdata/workflows/`
- 80% minimum line coverage for `internal/` packages
- No network calls in unit tests — use mock GitHub client

## Conventions

- Follow standard Go project layout
- Use `go fmt` and `go vet`
- Commit messages follow conventional commits: `feat:`, `fix:`, `test:`, `docs:`
- Exit codes: 0 = pass, 1 = findings above threshold, 2 = tool error
