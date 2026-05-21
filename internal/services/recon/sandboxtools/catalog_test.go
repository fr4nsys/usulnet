// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package sandboxtools

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestManifestInSync guards against drift between the canonical manifest
// at images/recon-toolkit/tools.list (read by the Dockerfile and by the
// in-image list-tools.sh) and the embedded copy at
// internal/services/recon/sandboxtools/tools.list (used by Catalog()).
//
// If this test fails, run:
//
//	cp images/recon-toolkit/tools.list internal/services/recon/sandboxtools/tools.list
//
// or update the canonical manifest if the package copy is the one
// that's right. The check is byte-exact: any whitespace or comment
// edit on one side must land on the other.
func TestManifestInSync(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot resolve repo root")
	}
	// Walk up from internal/services/recon/sandboxtools/ to the repo root.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
	canonical := filepath.Join(repoRoot, "images", "recon-toolkit", "tools.list")
	embedded := filepath.Join(filepath.Dir(thisFile), "tools.list")

	a, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatalf("read canonical manifest at %s: %v", canonical, err)
	}
	b, err := os.ReadFile(embedded)
	if err != nil {
		t.Fatalf("read embedded manifest at %s: %v", embedded, err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("tools.list copies have drifted.\nCanonical: %s\nEmbedded:  %s\n"+
			"Fix: cp %s %s",
			canonical, embedded, canonical, embedded)
	}
}

// TestCatalog_NonEmpty asserts the package actually parsed something —
// catches a regression where the embedded file ended up empty or the
// parser threw everything away. The lower bound starts low for the
// v26.5.2 initial landing (arch+pip subset) and will be tightened
// when BlackArch + Go-binary tools restore the full set.
func TestCatalog_NonEmpty(t *testing.T) {
	c := Catalog()
	if len(c) == 0 {
		t.Fatal("Catalog() returned empty slice; manifest probably missing or unparseable")
	}
	if len(c) < 3 {
		t.Errorf("Catalog() returned only %d tools; expected at least 3 — manifest may have lost entries", len(c))
	}
}

// TestCatalog_RequiredToolsPresent pins the tools the Go-side recon
// wrappers actually invoke through pacman. Removing any of them from
// the manifest without first updating
// internal/services/recon/engine/toolkit and internal/services/metadata
// is a regression.
//
// Python OSINT tools (holehe, h8mail, oletools, pdfid) live in /opt/venv
// and are installed by the Dockerfile via pip; they intentionally do
// NOT appear in tools.list so the catalog only surfaces what pacman
// manages. Adding BlackArch + restoring Go-binary tools is a follow-up
// PR; this test will be extended in lockstep.
func TestCatalog_RequiredToolsPresent(t *testing.T) {
	required := []string{
		// Metadata extractor + stripper (arch extra).
		"mat2",
		"perl-image-exiftool", // exiftool
		"yara",
	}
	got := Catalog()
	have := make(map[string]bool, len(got))
	for _, t := range got {
		have[t.Name] = true
	}
	for _, name := range required {
		if !have[name] {
			t.Errorf("required tool %q missing from manifest; check internal/services/recon/engine/toolkit before removing", name)
		}
	}
}

// TestCatalog_SupportPackagesSuppressed asserts the `# nocatalog`
// marker actually keeps support packages out of the UI.
func TestCatalog_SupportPackagesSuppressed(t *testing.T) {
	suppressed := []string{
		// "support" category — pacman bookkeeping deps.
		"coreutils", "ca-certificates", "curl", "jq", "shadow", "which", "file",
		// "runtime" category — needed only because pip lives in venv.
		"python", "python-pip",
	}
	have := make(map[string]bool)
	for _, tool := range Catalog() {
		have[tool.Name] = true
	}
	for _, s := range suppressed {
		if have[s] {
			t.Errorf("support package %q leaked into Catalog(); should carry # nocatalog", s)
		}
	}
}

// TestCategories_Ordered confirms Categories() returns a sorted set.
func TestCategories_Ordered(t *testing.T) {
	got := Categories()
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("Categories() not sorted: %v", got)
		}
	}
	// At minimum we expect the categories the v26.5.2 initial-landing
	// manifest currently uses. BlackArch + Go-binary tools restore the
	// osint-* categories in a follow-up.
	wantSubset := map[string]bool{
		"metadata": false,
	}
	for _, c := range got {
		if _, ok := wantSubset[c]; ok {
			wantSubset[c] = true
		}
	}
	for c, ok := range wantSubset {
		if !ok {
			t.Errorf("expected category %q in Categories(); got %v", c, got)
		}
	}
}

// TestParseManifest_Edges exercises parseManifest with synthetic inputs
// so the parser is covered without depending on the canonical manifest.
func TestParseManifest_Edges(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []Tool
	}{
		{
			name: "empty",
			in:   "",
			want: []Tool{},
		},
		{
			name: "only comments",
			in:   "# foo\n# bar\n",
			want: []Tool{},
		},
		{
			name: "single category",
			in:   "# category: alpha\nfoo\nbar\n",
			want: []Tool{{Name: "foo", Category: "alpha"}, {Name: "bar", Category: "alpha"}},
		},
		{
			name: "nocatalog suppression",
			in:   "# category: alpha\nfoo                 # nocatalog\nbar\n",
			want: []Tool{{Name: "bar", Category: "alpha"}},
		},
		{
			name: "category switch",
			in:   "# category: a\nfoo\n# category: b\nbar\n",
			want: []Tool{{Name: "foo", Category: "a"}, {Name: "bar", Category: "b"}},
		},
		{
			name: "inline comment stripped",
			in:   "foo   # bar baz\n",
			want: []Tool{{Name: "foo", Category: ""}},
		},
		{
			name: "whitespace tolerant",
			in:   "   \n\t\n  foo  \n",
			want: []Tool{{Name: "foo", Category: ""}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseManifest([]byte(tc.in))
			if len(got) != len(tc.want) {
				t.Fatalf("parseManifest len=%d want=%d. got=%v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("entry %d: got %+v want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
