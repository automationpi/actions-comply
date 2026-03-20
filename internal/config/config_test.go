package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

func TestLoad(t *testing.T) {
	cfg, err := Load(filepath.Join(testdataDir(), "actions-comply.yml"))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Version != 1 {
		t.Errorf("version: got %d, want 1", cfg.Version)
	}

	// Step usage map
	if perms, ok := cfg.StepUsageMap["myorg/deploy-action"]; !ok {
		t.Error("missing myorg/deploy-action in step-usage-map")
	} else {
		if len(perms) != 2 {
			t.Errorf("expected 2 permissions for deploy-action, got %d", len(perms))
		}
	}

	if perms, ok := cfg.StepUsageMap["myorg/publish-action"]; !ok {
		t.Error("missing myorg/publish-action")
	} else if len(perms) != 1 || perms[0] != "packages:write" {
		t.Errorf("unexpected permissions for publish-action: %v", perms)
	}

	// Scanners
	if scanType, ok := cfg.Scanners["myorg/internal-sast"]; !ok {
		t.Error("missing myorg/internal-sast in scanners")
	} else if scanType != "SAST (internal)" {
		t.Errorf("scanner type: got %q", scanType)
	}

	// Prod environments
	if len(cfg.ProdEnvironments) != 3 {
		t.Fatalf("expected 3 prod environments, got %d", len(cfg.ProdEnvironments))
	}
	expected := []string{"production", "prod-eu", "prod-us"}
	for i, want := range expected {
		if cfg.ProdEnvironments[i] != want {
			t.Errorf("prod env %d: got %q, want %q", i, cfg.ProdEnvironments[i], want)
		}
	}

	// Exclude
	if len(cfg.Exclude.Repos) != 2 {
		t.Errorf("expected 2 excluded repos, got %d", len(cfg.Exclude.Repos))
	}
	if len(cfg.Exclude.Workflows) != 1 {
		t.Errorf("expected 1 excluded workflow, got %d", len(cfg.Exclude.Workflows))
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load("/nonexistent/path.yml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Version != 1 {
		t.Errorf("version: got %d", cfg.Version)
	}
	if len(cfg.StepUsageMap) != 0 {
		t.Error("default should have empty step-usage-map")
	}
}

func TestLoadMinimal(t *testing.T) {
	// Write a minimal config
	dir := t.TempDir()
	path := filepath.Join(dir, "minimal.yml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 {
		t.Errorf("version: got %d", cfg.Version)
	}
}
