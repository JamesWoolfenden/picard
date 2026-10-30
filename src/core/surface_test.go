package core

import (
	"path/filepath"
	"reflect"
	"testing"
)

func panSurface(t *testing.T) SurfaceReport {
	t.Helper()

	lock, err := ReadUVLock("testdata/pan-uv.lock")
	if err != nil {
		t.Fatal(err)
	}

	return AnalyzeSurface(SurfaceEvidence{
		Lock: lock,
		Imports: &Imports{
			Production:      map[string]bool{"sentence_transformers": true, "httpx": true, "numpy": true, "fastapi": true},
			ProductionNames: map[string]bool{"sentence_transformers.SentenceTransformer": true, "httpx": true},
		},
		Owners:   map[string]string{"sentence_transformers": "sentence-transformers"},
		Commands: map[string]bool{"uvicorn": true},
		History:  map[string]int{"filelock": 22, "torch": 43},
	}, Target{OS: "linux", Arch: "x86_64", Python: "3.12"})
}

func entry(r SurfaceReport, dep string) Surface {
	for _, s := range r.Entries {
		if s.Dependency == dep {
			return s
		}
	}

	return Surface{}
}

func names(s Surface) map[string]bool {
	m := map[string]bool{}
	for _, p := range s.Packages {
		m[p.Name] = true
	}

	return m
}

func TestSurfaceGroupsDirectDependenciesThatOnlyGoTogether(t *testing.T) {
	r := panSurface(t)

	st := entry(r, "sentence-transformers")
	if !reflect.DeepEqual(st.Also, []string{"torch"}) {
		t.Errorf("sentence-transformers also = %v, want [torch] (pan lists torch directly)", st.Also)
	}

	got := names(st)
	for _, want := range []string{"torch", "filelock", "huggingface-hub", "transformers"} {
		if !got[want] {
			t.Errorf("sentence-transformers group missing %s", want)
		}
	}

	if got["numpy"] {
		t.Error("numpy is shared with librosa, so it can't be attributed to sentence-transformers alone")
	}

	if st.AdvisoryHistory() != 65 {
		t.Errorf("history = %d, want 65 (filelock 22 + torch 43)", st.AdvisoryHistory())
	}

	if torch := entry(r, "torch"); len(torch.Packages) != 0 || !reflect.DeepEqual(torch.SharedWith, []string{"sentence-transformers"}) {
		t.Errorf("torch alone = %+v, want nothing, shared with sentence-transformers", torch)
	}
}

func TestSurfaceFollowsRequestedExtras(t *testing.T) {
	uvicorn := names(entry(panSurface(t), "uvicorn"))

	for _, want := range []string{"httptools", "uvloop", "watchfiles", "websockets"} {
		if !uvicorn[want] {
			t.Errorf("uvicorn[standard] extra %s not attributed to uvicorn", want)
		}
	}

	if !entry(panSurface(t), "uvicorn").Command {
		t.Error("uvicorn run from the command line not marked as used")
	}
}

func TestSurfaceNativeCodeAndWheelChoice(t *testing.T) {
	st := entry(panSurface(t), "sentence-transformers")

	for _, p := range st.Packages {
		switch p.Name {
		case "torch":
			// Linux uses the +cpu build from PyTorch's index, which reports no sizes.
			if p.Version != "2.15.0+cpu" || p.Native != "yes" || p.Size != 0 {
				t.Errorf("torch = %+v", p)
			}
		case "filelock":
			if p.Native != "no" || p.Size == 0 {
				t.Errorf("filelock = %+v, want pure Python with a size", p)
			}
		}
	}

	if _, complete := st.Size(); complete {
		t.Error("size should be marked incomplete when a wheel size is unknown")
	}
}

func TestSurfaceFindsUndeclaredImports(t *testing.T) {
	r := panSurface(t)

	found := map[string]Undeclared{}
	for _, u := range r.Undeclared {
		found[u.Module] = u
	}

	if u, ok := found["httpx"]; !ok || u.DevOnly || u.Via[0] != "sentence-transformers" {
		t.Errorf("httpx = %+v, want undeclared, provided via sentence-transformers", u)
	}

	if _, ok := found["numpy"]; !ok {
		t.Error("numpy imported without being declared")
	}

	if _, ok := found["fastapi"]; ok {
		t.Error("fastapi is a direct dependency, not undeclared")
	}
}

func TestBestWheel(t *testing.T) {
	wheels := []Wheel{
		{Filename: "pkg-1-cp312-cp312-win_amd64.whl", Size: 1},
		{Filename: "pkg-1-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", Size: 2},
		{Filename: "pkg-1-cp312-cp312-manylinux_2_17_aarch64.whl", Size: 3},
		{Filename: "pkg-1-py3-none-any.whl", Size: 4},
	}

	cases := []struct {
		target Target
		want   int64
	}{
		{Target{OS: "linux", Arch: "x86_64", Python: "3.12"}, 2},   // abi3 beats py3
		{Target{OS: "linux", Arch: "arm64", Python: "3.12"}, 3},    // exact build
		{Target{OS: "windows", Arch: "x86_64", Python: "3.12"}, 1}, // exact build
		{Target{OS: "macos", Arch: "arm64", Python: "3.12"}, 4},    // only the pure wheel fits
		{Target{OS: "linux", Arch: "x86_64", Python: "3.10"}, 4},   // abi3 needs cp311+
	}

	for _, c := range cases {
		w, ok := bestWheel(wheels, c.target)
		if !ok || w.Size != c.want {
			t.Errorf("%+v: got %+v, want size %d", c.target, w, c.want)
		}
	}
}

func TestImportedNamesHandlesParensAliasesAndComments(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "app.py"),
		"from fastapi.responses import (  # noqa\n    FileResponse,\n    HTMLResponse as H,  # used\n)\nfrom x import *\nimport numpy as np\n")

	imports, err := ScanImports(root)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"fastapi.responses.FileResponse": true,
		"fastapi.responses.HTMLResponse": true,
		"numpy":                          true,
	}

	if !reflect.DeepEqual(imports.ProductionNames, want) {
		t.Errorf("names = %v, want %v", imports.ProductionNames, want)
	}
}

func TestCommandsUsedReadsConsoleScripts(t *testing.T) {
	site := t.TempDir()
	write(t, filepath.Join(site, "uvicorn-0.32.dist-info", "METADATA"), "Name: uvicorn\n")
	write(t, filepath.Join(site, "uvicorn-0.32.dist-info", "entry_points.txt"), "[console_scripts]\nuvicorn = uvicorn.main:main\n")
	write(t, filepath.Join(site, "tqdm-4.dist-info", "METADATA"), "Name: tqdm\n")
	write(t, filepath.Join(site, "tqdm-4.dist-info", "entry_points.txt"), "[console_scripts]\ntqdm = tqdm.cli:main\n")

	root := t.TempDir()
	write(t, filepath.Join(root, "Dockerfile"), `CMD ["uv", "run", "uvicorn", "backend.app:app"]`+"\n")

	used := CommandsUsed(root, ScriptOwners(site))
	if !used["uvicorn"] || used["tqdm"] {
		t.Errorf("used = %v, want uvicorn only", used)
	}
}
