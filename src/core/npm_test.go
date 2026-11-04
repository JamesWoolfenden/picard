package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestReadNPMLockSplitsProductionFromDev(t *testing.T) {
	lock, err := ReadNPMLock("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	if lock.Project != "demo-ui" || lock.Ecosystem != EcosystemNPM {
		t.Fatalf("project/ecosystem = %q/%q", lock.Project, lock.Ecosystem)
	}

	prod := lock.Closure(lock.Direct)

	if got := prod["loose-envify"]; !reflect.DeepEqual(got, []string{"react", "loose-envify"}) {
		t.Errorf("loose-envify via %v", got)
	}

	// Scoped names are kept as they are, not normalized.
	if _, ok := prod["@scope/kit"]; !ok {
		t.Error("@scope/kit missing from the production closure")
	}

	for _, devOnly := range []string{"vitest", "uuid"} {
		if _, ok := prod[devOnly]; ok {
			t.Errorf("%s is dev-only but landed in the production closure", devOnly)
		}
	}

	if got := lock.Closure(lock.DevDirect)["uuid"]; !reflect.DeepEqual(got, []string{"vitest", "uuid"}) {
		t.Errorf("uuid via %v in the dev closure", got)
	}

	if _, ok := lock.Packages["local-ws"]; ok {
		t.Error("a workspace link was treated as an installed package")
	}
}

func TestReadNPMLockKeepsEveryVersionOfANestedPackage(t *testing.T) {
	lock, err := ReadNPMLock("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	ms := lock.Packages["ms"]
	if ms == nil {
		t.Fatal("ms missing")
	}

	// The hoisted copy is the primary; the copy nested under @scope/kit is a variant.
	if ms.Version != "2.1.3" {
		t.Errorf("primary version = %s, want the shallowest install 2.1.3", ms.Version)
	}

	var versions []string
	for _, v := range ms.Variants {
		versions = append(versions, v.Version)
	}

	sort.Strings(versions)

	if !reflect.DeepEqual(versions, []string{"2.0.0", "2.1.3"}) {
		t.Errorf("variants = %v", versions)
	}
}

func TestReadNPMLockRejectsTheOldFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(path, []byte(`{"lockfileVersion": 1, "dependencies": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadNPMLock(path); err == nil {
		t.Error("lockfileVersion 1 should be rejected")
	}
}

func TestNPMPackageOf(t *testing.T) {
	for spec, want := range map[string]string{
		"react":              "react",
		"react/jsx-runtime":  "react",
		"@scope/kit":         "@scope/kit",
		"@scope/kit/sub":     "@scope/kit",
		"lodash.merge":       "lodash.merge",
		"./local":            "",
		"../up":              "",
		"/abs":               "",
		"node:fs":            "",
		"https://x.dev/m.js": "",
		"@/lib/x":            "",
		"@scope":             "",
	} {
		if got := npmPackageOf(spec); got != want {
			t.Errorf("npmPackageOf(%q) = %q, want %q", spec, got, want)
		}
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()

	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanJSImportsSplitsProductionFromTests(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"src/App.jsx": `import React from 'react';
import { v4 } from "uuid";
import local from './local';
import alias from '@/lib/x';
import {
  a,
} from "@scope/kit/sub";
const y = require('left-pad');
const lazy = () => import('lazy-pkg');
export * from "re-exported";
`,
		"src/__tests__/App.test.jsx": `import { it } from 'vitest';`,
		"src/App.spec.js":            `import 'spec-only';`,
		"vite.config.js":             `import react from '@vitejs/plugin-react';`,
		"node_modules/dep/index.js":  `require('never-scanned');`,
		"dist/bundle.js":             `require('never-scanned-either');`,
	})

	got, err := ScanJSImports(root)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"react": true, "uuid": true, "@scope/kit": true, "left-pad": true, "lazy-pkg": true, "re-exported": true,
	}
	if !reflect.DeepEqual(got.Production, want) {
		t.Errorf("production = %v, want %v", got.Production, want)
	}

	wantTest := map[string]bool{"vitest": true, "spec-only": true, "@vitejs/plugin-react": true}
	if !reflect.DeepEqual(got.Test, wantTest) {
		t.Errorf("test = %v, want %v", got.Test, wantTest)
	}
}

func TestOSVQueryLooksUpEveryNPMVersion(t *testing.T) {
	var asked []osvQuery

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var body struct {
				Queries []osvQuery `json:"queries"`
			}

			_ = json.NewDecoder(r.Body).Decode(&body)
			asked = body.Queries

			results := make([]any, len(asked))
			for i, q := range asked {
				results[i] = map[string]any{}
				if q.Version == "2.0.0" {
					results[i] = map[string]any{"vulns": []any{map[string]string{"id": "GHSA-ms"}}}
				}
			}

			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/GHSA-ms":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                "GHSA-ms",
				"summary":           "ReDoS in ms",
				"database_specific": map[string]string{"severity": "MODERATE"},
				"affected": []any{map[string]any{
					"package": map[string]string{"name": "ms", "ecosystem": "npm"},
					"ranges":  []any{map[string]any{"events": []map[string]string{{"introduced": "0"}, {"fixed": "2.1.3"}}}},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	osv := &OSV{BaseURL: server.URL, Client: server.Client()}
	ms := &Package{Name: "ms", Version: "2.1.3", Variants: []Variant{{Version: "2.1.3"}, {Version: "2.0.0"}}}

	got, err := osv.Query(EcosystemNPM, []*Package{ms})
	if err != nil {
		t.Fatal(err)
	}

	if len(asked) != 2 || asked[0].Package.Ecosystem != "npm" {
		t.Fatalf("queries = %+v, want both versions of ms in the npm ecosystem", asked)
	}

	if advs := got["ms"]; len(advs) != 1 || advs[0].Fixed != "2.1.3" {
		t.Errorf("advisories = %+v", got)
	}
}

// A dev-only vulnerable package - the shape of Dependabot's uuid alert - comes out as not
// shipped, and the VEX names it by its npm purl.
func TestScanNPMProjectJudgesDevOnlyAdvisoryNotShipped(t *testing.T) {
	root := t.TempDir()

	lock, err := os.ReadFile("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	writeFiles(t, root, map[string]string{
		"package-lock.json": string(lock),
		"src/index.jsx":     `import React from 'react';`,
	})

	server := uuidOSV()
	defer server.Close()

	report, err := Scan(Options{Directory: root, OSV: &OSV{BaseURL: server.URL, Client: server.Client()}})
	if err != nil {
		t.Fatal(err)
	}

	if report.Ecosystem != EcosystemNPM || len(report.Findings) != 1 {
		t.Fatalf("report = %+v", report)
	}

	f := report.Findings[0]
	if f.Package != "uuid" || f.Shipped || f.Verdict != VerdictNotShipped || f.FixVersion != "11.1.1" {
		t.Errorf("finding = %+v", f)
	}

	if !reflect.DeepEqual(f.Via, []string{"vitest", "uuid"}) {
		t.Errorf("via = %v", f.Via)
	}

	if got := report.purl("@scope/kit", "1.2.0"); got != "pkg:npm/%40scope/kit@1.2.0" {
		t.Errorf("purl = %s", got)
	}
}

func TestScanRejectsCoverageForAnNPMLock(t *testing.T) {
	root := t.TempDir()

	lock, err := os.ReadFile("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	writeFiles(t, root, map[string]string{"package-lock.json": string(lock)})

	if _, err := Scan(Options{Directory: root, Coverage: "coverage.json"}); err == nil {
		t.Error("a coverage.py report with an npm lock should be an error")
	}
}

// With a bundler, a dev-only package ships exactly when the code's imports reach it: the
// bundle carries what's imported, however it was declared.
func TestScanNPMProjectWithABundlerShipsWhatTheCodeImports(t *testing.T) {
	lock, err := os.ReadFile("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	bundled := strings.Replace(string(lock), `"devDependencies": { "vitest": "^1.0.0" }`,
		`"devDependencies": { "vitest": "^1.0.0", "esbuild": "^0.24.0" }`, 1)

	server := uuidOSV()
	defer server.Close()

	for _, tc := range []struct {
		name, code string
		want       Verdict
	}{
		{"imported", `import { v4 } from 'uuid';`, VerdictReachable},
		{"not imported", `import React from 'react';`, VerdictNotShipped},
	} {
		root := t.TempDir()
		writeFiles(t, root, map[string]string{"package-lock.json": bundled, "src/index.js": tc.code})

		report, err := Scan(Options{Directory: root, OSV: &OSV{BaseURL: server.URL, Client: server.Client()}})
		if err != nil {
			t.Fatal(err)
		}

		if len(report.Findings) != 1 {
			t.Fatalf("%s: report = %+v", tc.name, report)
		}

		f := report.Findings[0]
		if f.Verdict != tc.want || f.Bundler != "esbuild" || f.Bundled != (tc.want == VerdictReachable) {
			t.Errorf("%s: finding = %+v", tc.name, f)
		}
	}
}

// vite run by a script counts, even when only a plugin or vitest brings it in.
func TestReadNPMLockFindsABundlerRunByAScript(t *testing.T) {
	root := t.TempDir()

	lock, err := os.ReadFile("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	writeFiles(t, root, map[string]string{
		"package-lock.json": string(lock),
		"package.json":      `{"scripts": {"test": "vitest run", "build": "tsc && vite build"}}`,
	})

	got, err := ReadNPMLock(filepath.Join(root, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}

	if got.Bundler != "vite" {
		t.Errorf("bundler = %q, want vite", got.Bundler)
	}
}

func TestFindBundlerOnlyCountsDirectDependencies(t *testing.T) {
	// The fixture's vitest would pull in vite in real life; only direct ones count.
	lock, err := ReadNPMLock("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	if lock.Bundler != "" {
		t.Errorf("bundler = %q, want none", lock.Bundler)
	}

	if got := findBundler([]string{"react", "next"}); got != "next" {
		t.Errorf("findBundler = %q, want next", got)
	}
}

// uuidOSV is an OSV stub with one advisory, against uuid.
func uuidOSV() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var body struct {
				Queries []osvQuery `json:"queries"`
			}

			_ = json.NewDecoder(r.Body).Decode(&body)

			results := make([]any, len(body.Queries))
			for i, q := range body.Queries {
				results[i] = map[string]any{}
				if q.Package.Name == "uuid" {
					results[i] = map[string]any{"vulns": []any{map[string]string{"id": "GHSA-uuid"}}}
				}
			}

			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/GHSA-uuid":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                "GHSA-uuid",
				"summary":           "Missing buffer bounds check",
				"database_specific": map[string]string{"severity": "MODERATE"},
				"affected": []any{map[string]any{
					"package": map[string]string{"name": "uuid", "ecosystem": "npm"},
					"ranges":  []any{map[string]any{"events": []map[string]string{{"introduced": "0"}, {"fixed": "11.1.1"}}}},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

// A package installed twice - a dev-only copy hoisted to the top, a runtime copy nested under
// the dependency that needs a different range - ships only if the copy with the advisory does.
func TestTriageJudgesNestedNPMCopiesIndependently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package-lock.json")
	lockJSON := `{"name":"app","lockfileVersion":3,"packages":{
	 "":{"name":"app","dependencies":{"client":"^9"},"devDependencies":{"vsce":"^3"}},
	 "node_modules/client":{"version":"9.0.1","dependencies":{"minimatch":"^5"}},
	 "node_modules/client/node_modules/minimatch":{"version":"5.1.9"},
	 "node_modules/vsce":{"version":"3.0.0","dependencies":{"minimatch":"^10"}},
	 "node_modules/minimatch":{"version":"10.2.6","dev":true}}}`

	if err := os.WriteFile(path, []byte(lockJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	lock, err := ReadNPMLock(path)
	if err != nil {
		t.Fatal(err)
	}

	adv := func(version string) map[string][]Advisory {
		return map[string][]Advisory{"minimatch": {{ID: "GHSA-x", Severity: "high", Versions: []string{version}}}}
	}

	devCopy := Triage(adv("10.2.6"), Evidence{Lock: lock})
	if len(devCopy) != 1 || devCopy[0].Shipped || devCopy[0].Verdict != VerdictNotShipped {
		t.Errorf("advisory on the dev-only copy: %+v", devCopy)
	}

	runtimeCopy := Triage(adv("5.1.9"), Evidence{Lock: lock})
	if len(runtimeCopy) != 1 || !runtimeCopy[0].Shipped ||
		!reflect.DeepEqual(runtimeCopy[0].Via, []string{"client", "minimatch"}) {
		t.Errorf("advisory on the runtime copy: %+v", runtimeCopy)
	}
}

func TestVersionInRange(t *testing.T) {
	for _, c := range []struct {
		v, rng string
		want   bool
	}{
		{"5.0.9", ">= 4.0.0, < 5.0.10", true},
		{"2.1.4", ">= 4.0.0, < 5.0.10", false},
		{"2.1.4", ">= 2.0.0, < 2.1.7", true},
		{"5.1.9", "< 11.0.1", true},
		{"11.0.1", "< 11.0.1", false},
		{"1.0.0", "<= 1.0.0", true},
		{"1.0.1", "= 1.0.0", false},
	} {
		if got := VersionInRange(c.v, c.rng); got != c.want {
			t.Errorf("VersionInRange(%s, %q) = %v", c.v, c.rng, got)
		}
	}
}

// Dependabot raises an alert per installed copy; each gets the verdict of the copy its
// vulnerable range covers, and an alert covering both gets the more serious one.
func TestFindAdvisoryPicksTheCopyByRange(t *testing.T) {
	report := &Report{Ecosystem: EcosystemNPM, Findings: []Finding{
		{Package: "brace-expansion", Version: "5.0.9", Advisories: []Advisory{{ID: "GHSA-a", Verdict: VerdictNotShipped}}},
		{Package: "brace-expansion", Version: "2.1.4", Advisories: []Advisory{{ID: "GHSA-a", Verdict: VerdictShipped}}},
	}}

	alert := func(rng string) Alert {
		var a Alert
		a.Dependency.Package.Name = "brace-expansion"
		a.SecurityAdvisory.GHSAID = "GHSA-a"
		a.SecurityVulnerability.VulnerableVersionRange = rng

		return a
	}

	for rng, want := range map[string]Verdict{
		">= 4.0.0, < 5.0.10": VerdictNotShipped,
		">= 2.0.0, < 2.1.7":  VerdictShipped,
		"< 11.0.1":           VerdictShipped,
	} {
		if d := decide(alert(rng), report); d.Verdict != want {
			t.Errorf("range %q: verdict %s, want %s", rng, d.Verdict, want)
		}
	}
}
