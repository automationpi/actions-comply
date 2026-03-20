// Package main is the entry point for the actions-comply CLI.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/automationpi/actions-comply/internal/checks/changetrail"
	"github.com/automationpi/actions-comply/internal/checks/permissions"
	"github.com/automationpi/actions-comply/internal/checks/securedev"
	"github.com/automationpi/actions-comply/internal/checks/supplychain"
	"github.com/automationpi/actions-comply/internal/config"
	"github.com/automationpi/actions-comply/internal/engine"
	"github.com/automationpi/actions-comply/internal/report"
	"github.com/automationpi/actions-comply/pkg/models"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}

	switch args[0] {
	case "audit":
		return runAudit(args[1:])
	case "bom":
		return runBOM(args[1:])
	case "version":
		fmt.Printf("actions-comply %s\n", version)
		return 0
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printUsage()
		return 2
	}
}

func runAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	org := fs.String("org", envOrDefault("GITHUB_REPOSITORY_OWNER", ""), "GitHub organisation")
	repo := fs.String("repos", "", "Comma-separated repo list")
	framework := fs.String("framework", "soc2,iso27001", "Frameworks: soc2|iso27001|both")
	period := fs.Int("period", 90, "Lookback days for run history")
	output := fs.String("output", "text", "Output format: text|json|summary")
	outFile := fs.String("out", "", "Write report to file")
	failOn := fs.String("fail-on", "critical", "Exit 1 if finding >= severity")
	workflowDir := fs.String("workflow-dir", "", "Local dir of .yml files (offline mode)")
	configPath := fs.String("config", envOrDefault("ACTIONS_COMPLY_CONFIG", ""), "Path to actions-comply.yml config file")
	evidenceDir := fs.String("evidence-dir", "", "Generate evidence package in this directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *workflowDir == "" {
		fmt.Fprintln(os.Stderr, "Error: --workflow-dir is required (GitHub API mode not yet implemented)")
		return 2
	}

	// Load config
	cfg := config.Default()
	if *configPath != "" {
		var err error
		cfg, err = config.Load(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 2
		}
	}

	// Parse frameworks
	var frameworks []models.Framework
	for _, f := range strings.Split(*framework, ",") {
		switch strings.TrimSpace(f) {
		case "soc2":
			frameworks = append(frameworks, models.FrameworkSOC2)
		case "iso27001":
			frameworks = append(frameworks, models.FrameworkISO27001)
		}
	}

	now := time.Now()
	opts := engine.RunOptions{
		Org:         *org,
		Repo:        *repo,
		Frameworks:  frameworks,
		WorkflowDir: *workflowDir,
		Period: models.Period{
			From: now.AddDate(0, 0, -*period),
			To:   now,
		},
	}

	// Build checks with config overrides
	permCheck := &permissions.WorkflowOverage{}
	if len(cfg.StepUsageMap) > 0 {
		merged := make(map[string][]string)
		for k, v := range permissions.DefaultStepUsageMap {
			merged[k] = v
		}
		for k, v := range cfg.StepUsageMap {
			merged[k] = v
		}
		permCheck.StepUsageMap = merged
	}

	scanCheck := &securedev.ScanCoverage{}
	if len(cfg.Scanners) > 0 {
		merged := make(map[string]string)
		for k, v := range securedev.DefaultKnownScanners {
			merged[k] = v
		}
		for k, v := range cfg.Scanners {
			merged[k] = v
		}
		scanCheck.KnownScanners = merged
	}

	deployCheck := &changetrail.DeployApproval{}
	if len(cfg.ProdEnvironments) > 0 {
		deployCheck.ProdEnvironments = cfg.ProdEnvironments
	}

	e := engine.New(
		permCheck,
		&supplychain.ActionBOM{},
		&supplychain.UnpinnedActions{},
		scanCheck,
		deployCheck,
	)

	auditReport, err := e.Run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	// Render report
	var buf bytes.Buffer
	switch *output {
	case "json":
		if err := report.RenderJSON(&buf, auditReport); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering JSON: %v\n", err)
			return 2
		}
	case "summary":
		if err := report.RenderSummary(&buf, auditReport); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering summary: %v\n", err)
			return 2
		}
	default:
		if err := report.RenderText(&buf, auditReport); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering text: %v\n", err)
			return 2
		}
	}

	// Output
	if *outFile != "" {
		if err := os.WriteFile(*outFile, buf.Bytes(), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to %s: %v\n", *outFile, err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *outFile)
	} else {
		fmt.Print(buf.String())
	}

	// Generate evidence package
	if *evidenceDir != "" {
		if err := report.GenerateEvidencePackage(*evidenceDir, auditReport); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating evidence package: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "Evidence package written to %s\n", *evidenceDir)
	}

	// Exit code based on --fail-on
	threshold := models.Severity(*failOn)
	if engine.HasFindingsAtOrAbove(auditReport, threshold) {
		return 1
	}
	return 0
}

func runBOM(args []string) int {
	fs := flag.NewFlagSet("bom", flag.ContinueOnError)
	org := fs.String("org", envOrDefault("GITHUB_REPOSITORY_OWNER", ""), "GitHub organisation")
	repo := fs.String("repos", "", "Comma-separated repo list")
	workflowDir := fs.String("workflow-dir", "", "Local dir of .yml files")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *workflowDir == "" {
		fmt.Fprintln(os.Stderr, "Error: --workflow-dir is required")
		return 2
	}

	// Load workflows via engine
	e := engine.New()
	opts := engine.RunOptions{
		Org:         *org,
		Repo:        *repo,
		WorkflowDir: *workflowDir,
	}

	ctx, err := e.LoadWorkflowContext(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	if err := report.RenderBOMCSV(os.Stdout, ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	return 0
}

func printUsage() {
	fmt.Println(`actions-comply — GitHub Actions Compliance Auditor

Usage:
  comply audit [flags]    Run a compliance audit
  comply bom [flags]      Print action BOM as CSV
  comply version          Print version
  comply help             Show this help

Audit flags:
  --org string            GitHub organisation
  --repos string          Comma-separated repo list
  --framework string      Frameworks: soc2,iso27001 (default: soc2,iso27001)
  --period int            Lookback days (default: 90)
  --output string         Format: text|json|summary (default: text)
  --out string            Write report to file
  --fail-on string        Exit 1 if finding >= severity (default: critical)
  --workflow-dir string   Local dir of .yml files (offline mode)
  --config string         Path to actions-comply.yml config file
  --evidence-dir string   Generate evidence package in this directory`)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
