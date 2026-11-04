package core

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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
		History: map[string][]PastAdvisory{
			// filelock's audit: 17 in one week, then 5 older ones.
			"filelock": append(pastAdvisories(17, testNow.AddDate(0, -2, 0), time.Hour, "moderate"),
				pastAdvisories(5, testNow.AddDate(-5, 0, 0), 30*24*time.Hour, "low")...),
			// torch: a steady trickle, a month apart, the last three high.
			"torch": append(pastAdvisories(40, testNow.AddDate(-8, 0, 0), 60*24*time.Hour, "moderate"),
				pastAdvisories(3, testNow.AddDate(0, -6, 0), 30*24*time.Hour, "high")...),
		},
		Now: testNow,
	}, Target{OS: "linux", Arch: "x86_64", Python: "3.12"})
}

var testNow = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// pastAdvisories makes n advisories published every gap from start.
func pastAdvisories(n int, start time.Time, gap time.Duration, severity string) []PastAdvisory {
	out := make([]PastAdvisory, n)
	for i := range out {
		out[i] = PastAdvisory{ID: fmt.Sprintf("GHSA-%s-%d", severity, i), Published: start.Add(time.Duration(i) * gap), Severity: severity}
	}

	return out
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

	if st.Churn.Total != 65 {
		t.Errorf("history = %d, want 65 (filelock 22 + torch 43)", st.Churn.Total)
	}

	if torch := entry(r, "torch"); len(torch.Packages) != 0 || !reflect.DeepEqual(torch.SharedWith, []string{"sentence-transformers"}) {
		t.Errorf("torch alone = %+v, want nothing, shared with sentence-transformers", torch)
	}
}

// Recent advisories count per event: filelock's 17-in-a-week audit is one, torch's three a
// month apart are three; torch's trickle from 8 years ago mostly falls outside the window.
func TestSurfaceChurnCountsBurstsOnce(t *testing.T) {
	c := entry(panSurface(t), "sentence-transformers").Churn

	// torch's trickle: 40 every 60 days from 8 years back reaches the window for its last
	// few; count them rather than hard-code the calendar.
	trickle := 0
	for i := range 40 {
		if !testNow.AddDate(-8, 0, 0).Add(time.Duration(i) * 60 * 24 * time.Hour).Before(testNow.AddDate(-3, 0, 0)) {
			trickle++
		}
	}

	want := Churn{Total: 65, Recent: 17 + 3 + trickle, Events: 1 + 3 + trickle, Severe: 3}
	if c != want {
		t.Errorf("churn = %+v, want %+v", c, want)
	}
}

// sentence-transformers: one name used, dozens of packages, native code, a heavy record -
// flagged to replace. uvicorn runs as a command, so it isn't; a dependency nothing uses is
// flagged unused.
func TestSurfaceReviewsLittleUsedHeavyDependencies(t *testing.T) {
	r := panSurface(t)

	st := entry(r, "sentence-transformers")
	if st.Review == nil || st.Review.Kind != "replace" {
		t.Fatalf("sentence-transformers review = %+v, want replace", st.Review)
	}

	reasons := strings.Join(st.Review.Reasons, "; ")
	// httpx counts: only sentence-transformers brings it in (see the undeclared imports).
	for _, want := range []string{"uses 2 names (httpx, sentence_transformers.SentenceTransformer)", "alone brings in",
		"native code", "high or critical"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("reasons %q missing %q", reasons, want)
		}
	}

	if u := entry(r, "uvicorn"); u.Review != nil {
		t.Errorf("uvicorn is run as a command: review = %+v", u.Review)
	}

	unused := 0

	for _, s := range r.Entries {
		if s.Review != nil && s.Review.Kind == "unused" {
			unused++

			if len(s.UsedNames) != 0 || s.Command {
				t.Errorf("%s flagged unused but used", s.Dependency)
			}
		}
	}

	if unused == 0 {
		t.Error("pan's test imports name only a few dependencies - the rest should be flagged unused")
	}
}

// Light use alone isn't enough: a small dependency with a quiet record isn't flagged.
func TestReviewNeedsAHeavyCost(t *testing.T) {
	s := Surface{
		Dependency: "tiny",
		Packages:   []SurfacePackage{{Name: "tiny", Native: "no", Size: 1e4}},
		UsedNames:  []string{"tiny.f"},
	}

	if r := review(s, true); r != nil {
		t.Errorf("review = %+v, want none", r)
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

// `import x` counts the x.names the code uses, through an alias too; a.b.c's own dots and
// another object's attribute (self.np.x) don't count.
func TestImportedNamesCountsAttributesOfBareImports(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "audio.py"), "import librosa\nimport numpy as np\nimport os.path\n\n"+
		"y, sr = librosa.load(p)\ntempo = librosa.beat.beat_track(y=y)\nz = np.zeros(3)\nself.np.ignored\nos.path.join(a)\n")

	imports, err := ScanImports(root)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"librosa.load": true, "librosa.beat": true, "numpy.zeros": true, "os.path": true}
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

func TestGoSurfaceFollowsModuleEdges(t *testing.T) {
	lock := &Lock{
		Project:   "example.com/app",
		Ecosystem: EcosystemGo,
		Direct:    []string{"example.com/heavy", "example.com/light"},
		Compiled: map[string]bool{
			"example.com/heavy": true, "example.com/heavy/sub": true, "example.com/dep": true,
			"example.com/light": true,
		},
		Packages: map[string]*Package{
			"example.com/heavy": {Name: "example.com/heavy", Version: "v1.0.0", Deps: []string{"example.com/dep"}},
			"example.com/dep":   {Name: "example.com/dep", Version: "v1.0.0"},
			"example.com/light": {Name: "example.com/light", Version: "v1.0.0"},
		},
	}

	report := AnalyzeSurface(SurfaceEvidence{
		Lock:   lock,
		UsedBy: map[string][]string{"example.com/heavy": {"example.com/heavy/sub"}},
	}, Target{})

	if report.Ecosystem != EcosystemGo || report.Total != 3 {
		t.Fatalf("ecosystem/total = %q/%d, want Go/3", report.Ecosystem, report.Total)
	}

	var heavy, light *Surface

	for i := range report.Entries {
		switch report.Entries[i].Dependency {
		case "example.com/heavy":
			heavy = &report.Entries[i]
		case "example.com/light":
			light = &report.Entries[i]
		}
	}

	if heavy == nil || len(heavy.Packages) != 2 || heavy.CompiledPackages() != 3 {
		t.Errorf("heavy = %+v, want 2 modules and 3 compiled packages", heavy)
	}

	if !reflect.DeepEqual(heavy.UsedNames, []string{"example.com/heavy/sub"}) {
		t.Errorf("heavy used = %v", heavy.UsedNames)
	}

	if light == nil || light.Review == nil || light.Review.Kind != "unused" {
		t.Errorf("light = %+v, want flagged unused (nothing imports it)", light)
	}

	if heavy.Packages[0].Native != "" {
		t.Errorf("native = %q, want blank for Go", heavy.Packages[0].Native)
	}
}

func TestApplyGoEdgesSetsDeps(t *testing.T) {
	lock := &Lock{Packages: map[string]*Package{"a": {Name: "a"}, "b": {Name: "b"}}}
	ApplyGoEdges(lock, map[string][]string{"a": {"b"}, "missing": {"a"}})

	if !reflect.DeepEqual(lock.Packages["a"].Deps, []string{"b"}) {
		t.Errorf("a deps = %v", lock.Packages["a"].Deps)
	}
}

func TestNPMSurfaceHasNoWheelColumns(t *testing.T) {
	lock := &Lock{
		Project:   "app",
		Ecosystem: EcosystemNPM,
		Direct:    []string{"big", "unused"},
		Packages: map[string]*Package{
			"big":    {Name: "big", Version: "1.0.0", Deps: []string{"inner"}},
			"inner":  {Name: "inner", Version: "1.0.0"},
			"unused": {Name: "unused", Version: "1.0.0"},
		},
	}

	report := AnalyzeSurface(SurfaceEvidence{Lock: lock, UsedBy: map[string][]string{"big": {"big/sub"}}}, Target{})

	var out strings.Builder
	if err := report.WriteTable(&out, false); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	if strings.Contains(text, "NATIVE") || strings.Contains(text, "SIZE") || strings.Contains(text, "Python") {
		t.Errorf("npm table has Python-only columns:\n%s", text)
	}

	for _, e := range report.Entries {
		if e.Dependency == "unused" && (e.Review == nil || e.Review.Kind != "unused") {
			t.Errorf("unused = %+v, want flagged unused", e.Review)
		}

		for _, p := range e.Packages {
			if p.Native != "" {
				t.Errorf("%s native = %q, want blank", p.Name, p.Native)
			}
		}
	}
}
