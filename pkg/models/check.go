package models

// CheckContext carries the data needed by checks. Checks consume this
// rather than calling the GitHub API directly.
type CheckContext struct {
	Org       string
	Repo      string
	Workflows []*WorkflowFile
	// RunHistory will be added when GitHub client is implemented
}

// Check is the interface every compliance check must implement.
type Check interface {
	ID() string
	Title() string
	Description() string
	Controls() []ControlID
	Severity() Severity
	Run(ctx *CheckContext) (*CheckResult, error)
}
