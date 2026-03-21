// Package yaml provides a stdlib-only parser for GitHub Actions workflow files.
// It uses a line-by-line state machine rather than a full YAML parser.
// Supports any consistent indentation (2-space, 4-space, tabs).
package yaml

import (
	"bufio"
	"strings"

	"github.com/automationpi/actions-comply/pkg/models"
)

// Parse parses a GitHub Actions workflow YAML from its raw content.
func Parse(path, content string) (*models.WorkflowFile, error) {
	wf := &models.WorkflowFile{
		Path: path,
		Raw:  content,
		Jobs: make(map[string]*models.Job),
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	p := &parser{
		wf:      wf,
		scanner: scanner,
	}
	p.parse()
	return wf, nil
}

type parserState int

const (
	stateRoot parserState = iota
	stateOn
	statePermissions
	stateJobs
	stateJob
	stateJobPermissions
	stateJobSteps
	stateStep
	stateJobEnvironment
)

type parser struct {
	wf      *models.WorkflowFile
	scanner *bufio.Scanner

	state    parserState
	curJob   *models.Job
	curJobID string
	curStep  *models.Step

	// Dynamic indent tracking — set when we first see each level
	jobsIndent    int // indent of jobs: key (always 0)
	jobIDIndent   int // indent of job IDs under jobs:
	jobBodyIndent int // indent of job body keys (name, steps, etc.)
	stepsIndent   int // indent of steps: key
	stepItemIndent int // indent of step list items (- uses:)
}

func (p *parser) parse() {
	for p.scanner.Scan() {
		line := p.scanner.Text()
		p.processLine(line)
	}
	p.flushStep()
	p.flushJob()
}

func (p *parser) processLine(line string) {
	trimmed := strings.TrimSpace(line)

	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return
	}

	indent := countIndent(line)

	// Top-level keys (indent 0)
	if indent == 0 {
		p.flushStep()
		p.flushJob()
		p.state = stateRoot

		if key, val := splitKV(trimmed); key != "" {
			switch key {
			case "name":
				p.wf.Name = unquote(val)
			case "on":
				p.state = stateOn
				if val != "" {
					p.wf.Triggers = parseTriggerValue(val)
				}
			case "permissions":
				p.state = statePermissions
				if val != "" {
					p.wf.Permissions = &models.PermissionBlock{All: val}
				} else {
					p.wf.Permissions = &models.PermissionBlock{
						Scopes: make(map[string]string),
					}
				}
			case "jobs":
				p.state = stateJobs
				p.jobsIndent = 0
				p.jobIDIndent = 0 // will be set on first job ID
			}
		}
		return
	}

	switch p.state {
	case stateOn:
		p.processOn(trimmed, indent)
	case statePermissions:
		p.processPermissions(trimmed, indent)
	case stateJobs:
		p.processJobs(trimmed, indent)
	case stateJob:
		p.processJob(trimmed, indent)
	case stateJobPermissions:
		p.processJobPermissions(trimmed, indent)
	case stateJobSteps:
		p.processJobSteps(trimmed, indent)
	case stateStep:
		p.processStepFields(trimmed, indent)
	case stateJobEnvironment:
		p.processJobEnvironment(trimmed, indent)
	}
}

func (p *parser) processOn(trimmed string, indent int) {
	if indent <= 0 {
		return
	}
	key, _ := splitKV(trimmed)
	if key != "" {
		p.wf.Triggers = append(p.wf.Triggers, key)
	}
}

func (p *parser) processPermissions(trimmed string, indent int) {
	if indent <= 0 {
		p.state = stateRoot
		return
	}
	if p.wf.Permissions != nil && p.wf.Permissions.Scopes != nil {
		key, val := splitKV(trimmed)
		if key != "" && val != "" {
			p.wf.Permissions.Scopes[key] = val
		}
	}
}

func (p *parser) processJobs(trimmed string, indent int) {
	if indent > p.jobsIndent {
		p.flushStep()
		p.flushJob()
		key, _ := splitKV(trimmed)
		if key != "" {
			p.jobIDIndent = indent
			p.jobBodyIndent = 0 // will detect on first body key
			p.curJobID = key
			p.curJob = &models.Job{ID: key}
			p.state = stateJob
		}
	}
}

func (p *parser) processJob(trimmed string, indent int) {
	// New job at same level as current job ID
	if p.jobIDIndent > 0 && indent == p.jobIDIndent {
		p.flushStep()
		p.flushJob()
		key, _ := splitKV(trimmed)
		if key != "" {
			p.curJobID = key
			p.curJob = &models.Job{ID: key}
		}
		return
	}

	// Back to jobs level or root
	if indent <= p.jobsIndent {
		return
	}

	// Detect job body indent on first body key
	if p.jobBodyIndent == 0 && indent > p.jobIDIndent {
		p.jobBodyIndent = indent
	}

	// Only process at job body level
	if indent != p.jobBodyIndent {
		return
	}

	key, val := splitKV(trimmed)
	switch key {
	case "name":
		if p.curJob != nil {
			p.curJob.Name = unquote(val)
		}
	case "runs-on":
		if p.curJob != nil {
			p.curJob.RunsOn = unquote(val)
		}
	case "environment":
		if p.curJob != nil {
			if val != "" {
				p.curJob.Environment = unquote(val)
			} else {
				p.state = stateJobEnvironment
			}
		}
	case "permissions":
		if p.curJob != nil {
			if val != "" {
				p.curJob.Permissions = &models.PermissionBlock{All: val}
			} else {
				p.curJob.Permissions = &models.PermissionBlock{
					Scopes: make(map[string]string),
				}
			}
			p.state = stateJobPermissions
		}
	case "needs":
		if p.curJob != nil {
			p.curJob.Needs = parseList(val)
		}
	case "steps":
		p.stepsIndent = indent
		p.stepItemIndent = 0 // will detect on first step item
		p.state = stateJobSteps
	}
}

func (p *parser) processJobPermissions(trimmed string, indent int) {
	if indent <= p.jobBodyIndent {
		p.state = stateJob
		p.processJob(trimmed, indent)
		return
	}
	if p.curJob != nil && p.curJob.Permissions != nil && p.curJob.Permissions.Scopes != nil {
		key, val := splitKV(trimmed)
		if key != "" && val != "" {
			p.curJob.Permissions.Scopes[key] = val
		}
	}
}

func (p *parser) processJobEnvironment(trimmed string, indent int) {
	if indent <= p.jobBodyIndent {
		p.state = stateJob
		p.processJob(trimmed, indent)
		return
	}
	key, val := splitKV(trimmed)
	if key == "name" && p.curJob != nil {
		p.curJob.Environment = unquote(val)
	}
}

func (p *parser) processJobSteps(trimmed string, indent int) {
	// If we've gone back to job body level or above, exit steps
	if indent <= p.jobBodyIndent && !strings.HasPrefix(trimmed, "- ") {
		p.flushStep()
		p.state = stateJob
		p.processJob(trimmed, indent)
		return
	}
	// Back to job ID level or above
	if indent <= p.jobIDIndent {
		p.flushStep()
		p.state = stateJob
		p.processJob(trimmed, indent)
		return
	}

	// Step list item starts with -
	if strings.HasPrefix(trimmed, "- ") {
		p.flushStep()
		if p.stepItemIndent == 0 {
			p.stepItemIndent = indent
		}
		p.curStep = &models.Step{}
		rest := strings.TrimPrefix(trimmed, "- ")
		key, val := splitKV(rest)
		p.applyStepField(key, val)
		p.state = stateStep
		return
	}

	// Continuation of step fields
	if p.curStep != nil {
		p.processStepFields(trimmed, indent)
	}
}

func (p *parser) processStepFields(trimmed string, indent int) {
	// Back to job ID level or root
	if indent <= p.jobIDIndent {
		p.flushStep()
		p.state = stateJob
		p.processJob(trimmed, indent)
		return
	}

	// At job body level, check if it's a job key
	if indent == p.jobBodyIndent && !strings.HasPrefix(trimmed, "- ") {
		key, _ := splitKV(trimmed)
		if isJobKey(key) {
			p.flushStep()
			p.state = stateJob
			p.processJob(trimmed, indent)
			return
		}
	}

	// New step item
	if strings.HasPrefix(trimmed, "- ") {
		p.flushStep()
		p.curStep = &models.Step{}
		rest := strings.TrimPrefix(trimmed, "- ")
		key, val := splitKV(rest)
		p.applyStepField(key, val)
		return
	}

	key, val := splitKV(trimmed)
	p.applyStepField(key, val)
}

// isJobKey returns true if the key is a known job-level field.
func isJobKey(key string) bool {
	switch key {
	case "name", "runs-on", "environment", "permissions", "needs", "steps",
		"if", "strategy", "concurrency", "timeout-minutes", "services",
		"container", "defaults", "env", "outputs":
		return true
	}
	return false
}

func (p *parser) applyStepField(key, val string) {
	if p.curStep == nil {
		return
	}
	switch key {
	case "name":
		p.curStep.Name = unquote(val)
	case "uses":
		p.curStep.Uses = stripInlineComment(unquote(val))
		p.curStep.ActionRef = ParseActionRef(p.curStep.Uses)
	case "run":
		p.curStep.Run = unquote(val)
	case "if":
		p.curStep.If = val
	}
}

// stripInlineComment removes trailing YAML inline comments (# ...).
// Handles: "actions/checkout@abc123 # v4" → "actions/checkout@abc123"
func stripInlineComment(s string) string {
	if idx := strings.Index(s, " #"); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return s
}

func (p *parser) flushStep() {
	if p.curStep != nil && p.curJob != nil {
		p.curJob.Steps = append(p.curJob.Steps, *p.curStep)
		p.curStep = nil
	}
}

func (p *parser) flushJob() {
	if p.curJob != nil {
		p.wf.Jobs[p.curJobID] = p.curJob
		p.curJob = nil
		p.curJobID = ""
	}
}

// countIndent returns the number of leading spaces.
func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		switch {
		case ch == ' ':
			count++
		case ch == '\t':
			count += 4
		default:
			return count
		}
	}
	return count
}

// splitKV splits "key: value" into key and value.
func splitKV(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return s, ""
	}
	key := strings.TrimSpace(s[:idx])
	val := strings.TrimSpace(s[idx+1:])
	return key, val
}

// unquote removes surrounding single or double quotes.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// parseTriggerValue parses inline trigger values.
func parseTriggerValue(val string) []string {
	val = strings.Trim(val, "[]")
	parts := strings.Split(val, ",")
	var triggers []string
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			triggers = append(triggers, t)
		}
	}
	return triggers
}

// parseList parses inline list values: "[a, b]" or "a"
func parseList(val string) []string {
	val = strings.Trim(val, "[]")
	parts := strings.Split(val, ",")
	var result []string
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			result = append(result, t)
		}
	}
	return result
}
