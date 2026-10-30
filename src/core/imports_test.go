package core

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanImportsSplitsProductionFromTests(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "backend", "app.py"), "import json, requests as r\nfrom dotenv import load_dotenv\nfrom . import local\n")
	write(t, filepath.Join(root, "tests", "test_app.py"), "import pytest\nimport requests\n")
	write(t, filepath.Join(root, ".venv", "lib", "site.py"), "import shouldnotcount\n")

	imports, err := ScanImports(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range []string{"json", "requests", "dotenv"} {
		if !imports.Production[m] {
			t.Errorf("production imports missing %q", m)
		}
	}

	if imports.Production["pytest"] || !imports.Test["pytest"] {
		t.Error("pytest should only be a test import")
	}

	if imports.Production["shouldnotcount"] || imports.Production["local"] {
		t.Error("virtualenv or relative imports counted as production imports")
	}
}

func TestModuleOwnersMapsModulesToTheirPackage(t *testing.T) {
	site := t.TempDir()
	write(t, filepath.Join(site, "python_dotenv-1.2.4.dist-info", "METADATA"), "Metadata-Version: 2.1\nName: python-dotenv\n")
	write(t, filepath.Join(site, "python_dotenv-1.2.4.dist-info", "top_level.txt"), "dotenv\n")
	write(t, filepath.Join(site, "certifi-1.dist-info", "METADATA"), "Name: certifi\n")
	write(t, filepath.Join(site, "certifi-1.dist-info", "RECORD"), "certifi/__init__.py,sha256=x,1\ncertifi-1.dist-info/METADATA,,\n")

	owners := ModuleOwners(site)

	if owners["dotenv"] != "python-dotenv" || owners["certifi"] != "certifi" {
		t.Errorf("owners = %v", owners)
	}

	got := PackagesForModules(map[string]bool{"dotenv": true, "Unknown_Mod": true}, owners)
	if !got["python-dotenv"] || !got["unknown-mod"] {
		t.Errorf("PackagesForModules = %v", got)
	}
}
