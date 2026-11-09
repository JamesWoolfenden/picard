package core

import (
	"reflect"
	"testing"
)

func TestReadUVLockFindsProjectAndProductionClosure(t *testing.T) {
	lock, err := ReadUVLock("testdata/pan-uv.lock")
	if err != nil {
		t.Fatal(err)
	}

	if lock.Project != "pan" {
		t.Fatalf("project = %q, want pan", lock.Project)
	}

	prod := lock.Closure(lock.Direct)

	if got := prod["filelock"]; !reflect.DeepEqual(got, []string{"torch", "filelock"}) {
		t.Errorf("filelock via %v, want [torch filelock]", got)
	}

	if _, ok := prod["pytest"]; ok {
		t.Error("pytest is dev-only but landed in the production closure")
	}

	dev := lock.Closure(lock.DevDirect)
	if _, ok := dev["pytest"]; !ok {
		t.Error("pytest missing from the dev closure")
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Python_Dotenv":         "python-dotenv",
		"zope.interface":        "zope-interface",
		"sentence-transformers": "sentence-transformers",
	} {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.2.1", "4.1.0", 1},
		{"2026.7.22", "2026.10.18", -1},
		{"2.15.0+cpu", "2.15.0", 0},
		{"1.0", "1.0.0", 0},
	}

	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// cybernova-poc in November 2026: each service installs the project with its own extra
// (.[recon]), so mcp - and pyjwt under it - came in only through extras and were reported
// as dev-only.
func TestReadUVLockCountsTheProjectsExtrasAsRuntime(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"uv.lock": `version = 1
requires-python = ">=3.12"

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]

[package.optional-dependencies]
recon = [{ name = "mcp", extra = ["cli"] }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "requests"
version = "2.32.5"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mcp"
version = "1.28.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pyjwt", extra = ["crypto"] }]

[package.optional-dependencies]
cli = [{ name = "typer" }]

[[package]]
name = "pyjwt"
version = "2.13.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "typer"
version = "0.15.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.3.4"
source = { registry = "https://pypi.org/simple" }
`})

	lock, err := ReadUVLock(dir + "/uv.lock")
	if err != nil {
		t.Fatal(err)
	}

	prod := lock.Closure(lock.Direct)

	for name, want := range map[string][]string{
		"mcp":   {"mcp"},
		"pyjwt": {"mcp", "pyjwt"},
		"typer": {"mcp", "typer"}, // mcp[cli], requested by the extra
	} {
		if got := prod[name]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s via %v, want %v", name, got, want)
		}
	}

	if _, ok := prod["pytest"]; ok {
		t.Error("pytest is dev-only but landed in the production closure")
	}
}
