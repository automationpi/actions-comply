package yaml

import (
	"strings"

	"github.com/automationpi/actions-comply/pkg/models"
)

// ParseActionRef parses a raw action reference string from a uses: field.
// It handles four shapes:
//   - owner/name@version (standard third-party)
//   - owner/name@40hexSHA (SHA-pinned)
//   - ./local/path (local action)
//   - docker://image:tag (Docker action)
//   - owner/name (no version — unpinned)
func ParseActionRef(raw string) *models.ActionRef {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	ref := &models.ActionRef{Raw: raw}

	// Local action
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		ref.IsLocal = true
		ref.Path = raw
		return ref
	}

	// Docker action
	if strings.HasPrefix(raw, "docker://") {
		ref.IsDocker = true
		ref.Path = strings.TrimPrefix(raw, "docker://")
		return ref
	}

	// Split on @ to separate action path from version
	var actionPath, version string
	if idx := strings.LastIndex(raw, "@"); idx >= 0 {
		actionPath = raw[:idx]
		version = raw[idx+1:]
	} else {
		actionPath = raw
	}

	// Parse owner/name (may include sub-path like owner/name/sub)
	parts := strings.SplitN(actionPath, "/", 3)
	if len(parts) >= 2 {
		ref.Owner = parts[0]
		ref.Name = parts[1]
	} else if len(parts) == 1 {
		ref.Name = parts[0]
	}

	ref.Version = version
	ref.IsSHA = isSHA(version)

	return ref
}

// isSHA returns true if s is exactly 40 hex characters.
func isSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
