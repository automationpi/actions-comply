package models

// WorkflowFile represents a parsed GitHub Actions workflow.
type WorkflowFile struct {
	Path        string           // File path relative to repo root
	Name        string           // Workflow name from name: field
	Triggers    []string         // Trigger events: push, pull_request, etc.
	Permissions *PermissionBlock // Top-level permissions block (nil if absent)
	Jobs        map[string]*Job  // Jobs keyed by job ID
	Raw         string           // Original file content
}

// PermissionBlock represents a permissions declaration.
type PermissionBlock struct {
	All    string            // "read-all", "write-all", or "" if per-scope
	Scopes map[string]string // e.g. {"contents": "read", "packages": "write"}
}

// Job represents a single job within a workflow.
type Job struct {
	ID          string           // Job key in YAML
	Name        string           // Display name
	RunsOn      string           // Runner label
	Environment string           // Environment name
	Permissions *PermissionBlock // Job-level permissions (nil if absent)
	Needs       []string         // Job dependencies
	Steps       []Step           // Steps in execution order
}

// Step represents a single step within a job.
type Step struct {
	Name      string     // Step display name
	Uses      string     // Action reference (raw string)
	Run       string     // Inline script
	If        string     // Condition expression
	ActionRef *ActionRef // Parsed action reference (nil if step has no uses:)
}

// ActionRef is a parsed action reference from a uses: field.
type ActionRef struct {
	Raw      string // Original string
	Owner    string // e.g. "actions"
	Name     string // e.g. "checkout"
	Version  string // e.g. "v4" or full SHA
	IsSHA    bool   // True if version is a 40-char hex SHA
	IsLocal  bool   // True if ./path reference
	IsDocker bool   // True if docker:// reference
	Path     string // For local: the path. For docker: image:tag
}
