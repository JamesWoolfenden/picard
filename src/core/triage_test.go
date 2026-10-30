package core

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLock() *Lock {
	return &Lock{
		Project: "app",
		Packages: map[string]*Package{
			"web":     {Name: "web", Version: "1", Deps: []string{"certs", "locks"}},
			"certs":   {Name: "certs", Version: "1"},
			"locks":   {Name: "locks", Version: "1"},
			"testlib": {Name: "testlib", Version: "1"},
		},
		Direct:    []string{"web"},
		DevDirect: []string{"testlib"},
	}
}

func advisory(id, severity, fixed string) []Advisory {
	return []Advisory{{ID: id, Severity: severity, Fixed: fixed}}
}

func byPackage(findings []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range findings {
		m[f.Package] = f
	}

	return m
}

func TestTriageVerdictsFromCoverage(t *testing.T) {
	findings := Triage(map[string][]Advisory{
		"certs":   advisory("A", "critical", "2"),
		"locks":   append(advisory("B", "high", "2"), advisory("C", "low", "3")...),
		"web":     advisory("D", "moderate", "2"),
		"testlib": advisory("E", "high", "2"),
	}, Evidence{
		Lock:     testLock(),
		Imported: map[string]bool{"web": true},
		Executed: map[string]*ModuleUse{
			"web":   {Loaded: true, FunctionData: true, Called: []string{"web/api.py:get"}},
			"certs": {Loaded: true, FunctionData: true},
		},
		Owners: map[string]string{},
	})

	got := byPackage(findings)

	if got["web"].Verdict != VerdictReachable {
		t.Errorf("web: %s", got["web"].Verdict)
	}

	if got["certs"].Verdict != VerdictImportOnly {
		t.Errorf("certs: %s", got["certs"].Verdict)
	}

	if got["locks"].Verdict != VerdictNotExecuted {
		t.Errorf("locks: %s", got["locks"].Verdict)
	}

	// Both of its advisories are one upgrade, to the higher of the two fixes.
	if got["locks"].FixVersion != "3" || got["locks"].Severity != "high" {
		t.Errorf("locks fix %s severity %s", got["locks"].FixVersion, got["locks"].Severity)
	}

	if got["testlib"].Verdict != VerdictNotShipped {
		t.Errorf("testlib: %s", got["testlib"].Verdict)
	}

	if findings[0].Package != "web" {
		t.Errorf("reachable findings should sort first, got %s", findings[0].Package)
	}
}

func TestTriageWithoutCoverageOnlyKnowsShipped(t *testing.T) {
	got := byPackage(Triage(map[string][]Advisory{
		"locks": advisory("B", "high", "2"),
		"web":   advisory("D", "moderate", "2"),
	}, Evidence{Lock: testLock(), Imported: map[string]bool{"web": true}}))

	if got["locks"].Verdict != VerdictShipped || got["locks"].Executed != UseUnknown {
		t.Errorf("locks: %s / %s", got["locks"].Verdict, got["locks"].Executed)
	}

	if got["web"].Verdict != VerdictReachable {
		t.Errorf("web: %s", got["web"].Verdict)
	}
}

func TestReadCoverageSeparatesImportFromCalls(t *testing.T) {
	modules, err := ReadCoverage(filepath.Join("testdata", "coverage.json"))
	if err != nil {
		t.Fatal(err)
	}

	certifi := modules["certifi"]
	if certifi == nil || !certifi.Loaded || len(certifi.Called) != 0 {
		t.Errorf("certifi = %+v, want loaded with no calls", certifi)
	}

	filelock := modules["filelock"]
	if filelock == nil || len(filelock.Called) != 1 || filelock.Called[0] != "filelock/_api.py:BaseFileLock.acquire" {
		t.Errorf("filelock = %+v", filelock)
	}

	if _, ok := modules["app"]; ok {
		t.Error("project code outside site-packages counted as third-party")
	}
}

func TestWriteVEXMapsVerdictsToStatuses(t *testing.T) {
	judged := func(id string, v Verdict) []Advisory {
		a := advisory(id, "high", "2")
		a[0].Verdict = v

		return a
	}

	report := Report{Project: "app", Findings: []Finding{
		{Package: "testlib", Version: "1", Advisories: judged("E", VerdictNotShipped)},
		{Package: "locks", Version: "1", Advisories: judged("B", VerdictImportOnly)},
		{Package: "web", Version: "1", FixVersion: "2", Advisories: judged("D", VerdictReachable)},
	}}

	var buf bytes.Buffer
	if err := report.WriteVEX(&buf, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}

	var doc vexDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	want := map[string][2]string{
		"E": {"not_affected", "component_not_present"},
		"B": {"not_affected", "vulnerable_code_not_in_execute_path"},
		"D": {"affected", ""},
	}

	for _, s := range doc.Statements {
		if w := want[s.Vulnerability.Name]; s.Status != w[0] || s.Justification != w[1] {
			t.Errorf("%s: %s/%s, want %s/%s", s.Vulnerability.Name, s.Status, s.Justification, w[0], w[1])
		}

		if s.Status == "affected" && !strings.Contains(s.ActionStatement, "upgrade web to 2") {
			t.Errorf("affected statement without an upgrade action: %q", s.ActionStatement)
		}
	}
}
