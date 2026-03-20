package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/automationpi/actions-comply/pkg/models"
)

// GenerateEvidencePackage creates a structured directory of evidence organized by control ID.
func GenerateEvidencePackage(dir string, report *models.AuditReport) error {
	// Create base directory
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating evidence dir: %w", err)
	}

	// Write report metadata
	metaPath := filepath.Join(dir, "audit-metadata.json")
	meta := map[string]interface{}{
		"id":           report.ID,
		"org":          report.Org,
		"repos":        report.Repos,
		"frameworks":   report.Frameworks,
		"generated_at": report.GeneratedAt,
		"summary":      report.Summary,
	}
	if err := writeJSON(metaPath, meta); err != nil {
		return err
	}

	// Group findings by control
	controlFindings := make(map[models.ControlID][]models.Finding)
	for _, cr := range report.CheckResults {
		for _, f := range cr.Findings {
			for _, ctrl := range f.Controls {
				controlFindings[ctrl] = append(controlFindings[ctrl], f)
			}
		}
	}

	// Write per-control evidence
	for ctrl, findings := range controlFindings {
		ctrlDir := filepath.Join(dir, sanitizePath(string(ctrl)))
		if err := os.MkdirAll(ctrlDir, 0755); err != nil {
			return fmt.Errorf("creating control dir %s: %w", ctrl, err)
		}

		// Write findings for this control
		findingsPath := filepath.Join(ctrlDir, "findings.json")
		if err := writeJSON(findingsPath, findings); err != nil {
			return err
		}

		// Write individual evidence files
		for i, f := range findings {
			for j, ev := range f.Evidence {
				evPath := filepath.Join(ctrlDir, fmt.Sprintf("evidence-%d-%d.json", i, j))
				evData := map[string]interface{}{
					"finding_check_id": f.CheckID,
					"finding_status":   f.Status,
					"finding_severity": f.Severity,
					"finding_target":   f.Target,
					"finding_message":  f.Message,
					"evidence":         ev,
				}
				if err := writeJSON(evPath, evData); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func writeJSON(path string, v interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func sanitizePath(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}
