package yaml

import (
	"testing"
)

func TestParseActionRef(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantNil  bool
		owner    string
		aName    string
		version  string
		isSHA    bool
		isLocal  bool
		isDocker bool
		path     string
	}{
		{
			name:  "standard action with tag",
			raw:   "actions/checkout@v4",
			owner: "actions", aName: "checkout",
			version: "v4",
		},
		{
			name:  "SHA-pinned action",
			raw:   "actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
			owner: "actions", aName: "checkout",
			version: "a5ac7e51b41094c92402da3b24376905380afc29",
			isSHA:   true,
		},
		{
			name:    "local action",
			raw:     "./my-action",
			isLocal: true,
			path:    "./my-action",
		},
		{
			name:    "local action nested",
			raw:     "./.github/actions/my-action",
			isLocal: true,
			path:    "./.github/actions/my-action",
		},
		{
			name:     "docker action",
			raw:      "docker://alpine:3.18",
			isDocker: true,
			path:     "alpine:3.18",
		},
		{
			name:  "action with sub-path",
			raw:   "github/codeql-action/analyze@v2",
			owner: "github", aName: "codeql-action",
			version: "v2",
		},
		{
			name:  "action without version (unpinned)",
			raw:   "actions/checkout",
			owner: "actions", aName: "checkout",
		},
		{
			name:    "empty string",
			raw:     "",
			wantNil: true,
		},
		{
			name:  "mutable tag main",
			raw:   "actions/upload-artifact@main",
			owner: "actions", aName: "upload-artifact",
			version: "main",
		},
		{
			name:  "short hash not SHA",
			raw:   "actions/checkout@abc1234",
			owner: "actions", aName: "checkout",
			version: "abc1234",
			isSHA:   false,
		},
		{
			name:  "uppercase SHA",
			raw:   "actions/checkout@A5AC7E51B41094C92402DA3B24376905380AFC29",
			owner: "actions", aName: "checkout",
			version: "A5AC7E51B41094C92402DA3B24376905380AFC29",
			isSHA:   true,
		},
		{
			name:  "40 chars but not hex",
			raw:   "actions/checkout@a5ac7e51b41094c92402da3b24376905380afczz",
			owner: "actions", aName: "checkout",
			version: "a5ac7e51b41094c92402da3b24376905380afczz",
			isSHA:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseActionRef(tt.raw)
			if tt.wantNil {
				if ref != nil {
					t.Fatalf("expected nil, got %+v", ref)
				}
				return
			}
			if ref == nil {
				t.Fatal("expected non-nil ActionRef")
			}
			if ref.Owner != tt.owner {
				t.Errorf("owner: got %q, want %q", ref.Owner, tt.owner)
			}
			if ref.Name != tt.aName {
				t.Errorf("name: got %q, want %q", ref.Name, tt.aName)
			}
			if ref.Version != tt.version {
				t.Errorf("version: got %q, want %q", ref.Version, tt.version)
			}
			if ref.IsSHA != tt.isSHA {
				t.Errorf("isSHA: got %v, want %v", ref.IsSHA, tt.isSHA)
			}
			if ref.IsLocal != tt.isLocal {
				t.Errorf("isLocal: got %v, want %v", ref.IsLocal, tt.isLocal)
			}
			if ref.IsDocker != tt.isDocker {
				t.Errorf("isDocker: got %v, want %v", ref.IsDocker, tt.isDocker)
			}
			if tt.path != "" && ref.Path != tt.path {
				t.Errorf("path: got %q, want %q", ref.Path, tt.path)
			}
		})
	}
}

func TestIsSHA(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"a5ac7e51b41094c92402da3b24376905380afc29", true},
		{"A5AC7E51B41094C92402DA3B24376905380AFC29", true},
		{"v4", false},
		{"main", false},
		{"abc1234", false},
		{"", false},
		{"a5ac7e51b41094c92402da3b24376905380afczz", false},
		{"0000000000000000000000000000000000000000", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isSHA(tt.input)
			if got != tt.want {
				t.Errorf("isSHA(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
