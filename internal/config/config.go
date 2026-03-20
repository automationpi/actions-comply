// Package config handles loading and merging actions-comply configuration.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config represents the actions-comply configuration file.
type Config struct {
	Version         int               `json:"version"`
	StepUsageMap    map[string][]string `json:"step_usage_map"`
	Scanners        map[string]string  `json:"scanners"`
	ProdEnvironments []string          `json:"prod_environments"`
	Exclude         ExcludeConfig      `json:"exclude"`
}

// ExcludeConfig defines repos and workflows to exclude from checks.
type ExcludeConfig struct {
	Repos     []string `json:"repos"`
	Workflows []string `json:"workflows"`
}

// Load reads a config file from the given path.
// The format is a simple YAML-like key-value parser (stdlib only).
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer f.Close()

	cfg := &Config{
		Version:      1,
		StepUsageMap: make(map[string][]string),
		Scanners:     make(map[string]string),
	}

	scanner := bufio.NewScanner(f)
	var section string
	var currentMapKey string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := countIndent(line)

		// Top-level keys
		if indent == 0 {
			key, val := splitKV(trimmed)
			switch key {
			case "version":
				if val == "1" {
					cfg.Version = 1
				}
			case "step-usage-map":
				section = "step-usage-map"
			case "scanners":
				section = "scanners"
			case "prod-environments":
				section = "prod-environments"
			case "exclude":
				section = "exclude"
			}
			currentMapKey = ""
			continue
		}

		switch section {
		case "step-usage-map":
			if indent == 2 {
				key, val := splitKV(trimmed)
				if key != "" {
					if val != "" {
						// Inline list: myorg/action: ["perm1", "perm2"]
						cfg.StepUsageMap[key] = parseStringList(val)
					} else {
						currentMapKey = key
					}
				}
			} else if indent >= 4 && currentMapKey != "" {
				// List item under map key
				if strings.HasPrefix(trimmed, "- ") {
					item := unquote(strings.TrimPrefix(trimmed, "- "))
					cfg.StepUsageMap[currentMapKey] = append(cfg.StepUsageMap[currentMapKey], item)
				}
			}

		case "scanners":
			if indent == 2 {
				key, val := splitKV(trimmed)
				if key != "" && val != "" {
					cfg.Scanners[key] = unquote(val)
				}
			}

		case "prod-environments":
			if strings.HasPrefix(trimmed, "- ") {
				item := unquote(strings.TrimPrefix(trimmed, "- "))
				cfg.ProdEnvironments = append(cfg.ProdEnvironments, item)
			}

		case "exclude":
			if indent == 2 {
				key, _ := splitKV(trimmed)
				switch key {
				case "repos":
					currentMapKey = "repos"
				case "workflows":
					currentMapKey = "workflows"
				}
			} else if indent >= 4 && strings.HasPrefix(trimmed, "- ") {
				item := unquote(strings.TrimPrefix(trimmed, "- "))
				switch currentMapKey {
				case "repos":
					cfg.Exclude.Repos = append(cfg.Exclude.Repos, item)
				case "workflows":
					cfg.Exclude.Workflows = append(cfg.Exclude.Workflows, item)
				}
			}
		}
	}

	return cfg, scanner.Err()
}

// Default returns a config with no overrides.
func Default() *Config {
	return &Config{
		Version:      1,
		StepUsageMap: make(map[string][]string),
		Scanners:     make(map[string]string),
	}
}

func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else {
			break
		}
	}
	return count
}

func splitKV(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return s, ""
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:])
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// parseStringList parses ["a", "b"] inline format.
func parseStringList(val string) []string {
	val = strings.Trim(val, "[]")
	parts := strings.Split(val, ",")
	var result []string
	for _, p := range parts {
		item := unquote(strings.TrimSpace(p))
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}
