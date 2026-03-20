package yaml

import (
	"os"
	"testing"
)

func TestParseCleanCI(t *testing.T) {
	content := readFixture(t, "clean-ci.yml")
	wf, err := Parse(".github/workflows/clean-ci.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	if wf.Name != "CI" {
		t.Errorf("name: got %q, want %q", wf.Name, "CI")
	}

	assertContains(t, wf.Triggers, "pull_request")
	assertContains(t, wf.Triggers, "push")

	if wf.Permissions == nil {
		t.Fatal("expected top-level permissions block")
	}
	if wf.Permissions.Scopes["contents"] != "read" {
		t.Errorf("permissions.contents: got %q, want %q", wf.Permissions.Scopes["contents"], "read")
	}
	if wf.Permissions.Scopes["security-events"] != "write" {
		t.Errorf("permissions.security-events: got %q, want %q", wf.Permissions.Scopes["security-events"], "write")
	}

	if len(wf.Jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(wf.Jobs))
	}

	testJob := wf.Jobs["test"]
	if testJob == nil {
		t.Fatal("expected job 'test'")
	}
	if testJob.Name != "Run Tests" {
		t.Errorf("job name: got %q, want %q", testJob.Name, "Run Tests")
	}
	if len(testJob.Steps) != 2 {
		t.Fatalf("expected 2 steps in test job, got %d", len(testJob.Steps))
	}
	if testJob.Steps[0].Uses != "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29" {
		t.Errorf("step uses: got %q", testJob.Steps[0].Uses)
	}
	if testJob.Steps[0].ActionRef == nil || !testJob.Steps[0].ActionRef.IsSHA {
		t.Error("expected SHA-pinned ActionRef for checkout step")
	}

	scanJob := wf.Jobs["scan"]
	if scanJob == nil {
		t.Fatal("expected job 'scan'")
	}
	if len(scanJob.Steps) != 3 {
		t.Fatalf("expected 3 steps in scan job, got %d", len(scanJob.Steps))
	}
}

func TestParseWriteAll(t *testing.T) {
	content := readFixture(t, "write-all.yml")
	wf, err := Parse(".github/workflows/write-all.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	if wf.Permissions == nil {
		t.Fatal("expected permissions block")
	}
	if wf.Permissions.All != "write-all" {
		t.Errorf("permissions.All: got %q, want %q", wf.Permissions.All, "write-all")
	}
}

func TestParseUnpinned(t *testing.T) {
	content := readFixture(t, "unpinned.yml")
	wf, err := Parse(".github/workflows/unpinned.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	build := wf.Jobs["build"]
	if build == nil {
		t.Fatal("expected job 'build'")
	}
	if len(build.Steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(build.Steps))
	}

	// All steps should have non-SHA versions
	for _, step := range build.Steps {
		if step.ActionRef == nil {
			continue
		}
		if step.ActionRef.IsSHA {
			t.Errorf("step %q should not be SHA-pinned", step.Name)
		}
	}
}

func TestParseDeployNoEnv(t *testing.T) {
	content := readFixture(t, "deploy-no-env.yml")
	wf, err := Parse(".github/workflows/deploy-no-env.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	job := wf.Jobs["deploy-prod"]
	if job == nil {
		t.Fatal("expected job 'deploy-prod'")
	}
	if job.Environment != "" {
		t.Errorf("expected empty environment, got %q", job.Environment)
	}
	if job.Name != "Deploy to Production" {
		t.Errorf("job name: got %q, want %q", job.Name, "Deploy to Production")
	}
}

func TestParseDeployWithEnv(t *testing.T) {
	content := readFixture(t, "deploy-with-env.yml")
	wf, err := Parse(".github/workflows/deploy-with-env.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	job := wf.Jobs["deploy-prod"]
	if job == nil {
		t.Fatal("expected job 'deploy-prod'")
	}
	if job.Environment != "production" {
		t.Errorf("environment: got %q, want %q", job.Environment, "production")
	}
}

func TestParseNoScanner(t *testing.T) {
	content := readFixture(t, "no-scanner.yml")
	wf, err := Parse(".github/workflows/no-scanner.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	assertContains(t, wf.Triggers, "pull_request")

	testJob := wf.Jobs["test"]
	if testJob == nil {
		t.Fatal("expected job 'test'")
	}
	// Should have steps but no scanner actions
	for _, step := range testJob.Steps {
		if step.ActionRef != nil {
			if step.ActionRef.Owner == "github" && step.ActionRef.Name == "codeql-action" {
				t.Error("should not have codeql action in no-scanner fixture")
			}
		}
	}
}

func TestParseEmptyContent(t *testing.T) {
	wf, err := Parse("empty.yml", "")
	if err != nil {
		t.Fatal(err)
	}
	if wf.Name != "" {
		t.Errorf("expected empty name, got %q", wf.Name)
	}
	if len(wf.Jobs) != 0 {
		t.Errorf("expected 0 jobs, got %d", len(wf.Jobs))
	}
}

func TestParseJobPermissions(t *testing.T) {
	content := readFixture(t, "job-permissions.yml")
	wf, err := Parse(".github/workflows/job-permissions.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	// Should parse inline trigger list
	assertContains(t, wf.Triggers, "push")
	assertContains(t, wf.Triggers, "pull_request")

	// Top-level permissions should be nil
	if wf.Permissions != nil {
		t.Error("expected no top-level permissions")
	}

	build := wf.Jobs["build"]
	if build == nil {
		t.Fatal("expected job 'build'")
	}
	if build.Permissions == nil {
		t.Fatal("expected job-level permissions")
	}
	if build.Permissions.Scopes["contents"] != "read" {
		t.Errorf("job perms contents: got %q", build.Permissions.Scopes["contents"])
	}
	if build.Permissions.Scopes["packages"] != "write" {
		t.Errorf("job perms packages: got %q", build.Permissions.Scopes["packages"])
	}
	if len(build.Needs) != 1 || build.Needs[0] != "lint" {
		t.Errorf("needs: got %v, want [lint]", build.Needs)
	}

	// Check if condition parsed
	if len(build.Steps) < 2 {
		t.Fatal("expected at least 2 steps")
	}
	if build.Steps[1].If != "github.event_name == 'push'" {
		t.Errorf("if: got %q", build.Steps[1].If)
	}
}

func TestParseEnvironmentMap(t *testing.T) {
	content := readFixture(t, "env-map.yml")
	wf, err := Parse(".github/workflows/env-map.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	deploy := wf.Jobs["deploy"]
	if deploy == nil {
		t.Fatal("expected job 'deploy'")
	}
	if deploy.Environment != "staging" {
		t.Errorf("environment: got %q, want %q", deploy.Environment, "staging")
	}
}

func TestParseCompactSteps(t *testing.T) {
	content := readFixture(t, "compact-steps.yml")
	wf, err := Parse(".github/workflows/compact-steps.yml", content)
	if err != nil {
		t.Fatal(err)
	}

	analyze := wf.Jobs["analyze"]
	if analyze == nil {
		t.Fatal("expected job 'analyze'")
	}
	if analyze.Permissions == nil {
		t.Fatal("expected job-level permissions")
	}
	if analyze.Permissions.Scopes["security-events"] != "write" {
		t.Errorf("job perms security-events: got %q", analyze.Permissions.Scopes["security-events"])
	}
	if len(analyze.Steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(analyze.Steps))
	}
	// Verify CodeQL actions are parsed
	if analyze.Steps[1].Uses != "github/codeql-action/init@b611370bb5703a7efb587f9d136a52ea24c5c38c" {
		t.Errorf("step 1 uses: got %q", analyze.Steps[1].Uses)
	}
	if analyze.Steps[3].Uses != "github/codeql-action/analyze@b611370bb5703a7efb587f9d136a52ea24c5c38c" {
		t.Errorf("step 3 uses: got %q", analyze.Steps[3].Uses)
	}
	// Step with only run: and no name
	if analyze.Steps[2].Run != "npm ci" {
		t.Errorf("step 2 run: got %q", analyze.Steps[2].Run)
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../../testdata/workflows/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(data)
}

func assertContains(t *testing.T, slice []string, want string) {
	t.Helper()
	for _, s := range slice {
		if s == want {
			return
		}
	}
	t.Errorf("slice %v does not contain %q", slice, want)
}
