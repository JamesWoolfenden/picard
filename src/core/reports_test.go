package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGatherReports(t *testing.T) {
	old := time.Now().AddDate(0, 0, -10).Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/security-advisories":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"ghsa_id": "GHSA-aaaa-aaaa-aaaa", "state": "triage", "severity": "high", "created_at": old,
					"summary": "RCE in parser", "author": map[string]string{"login": "rep"},
					"description": "Steps to reproduce: call `parse_header()` in src/app/parse.py with a long value. " +
						"See https://evil.example/poc.zip - disclosure in 90 days unless a bounty is paid.\n```diff\n-a\n+b\n```"},
				{"ghsa_id": "GHSA-bbbb-bbbb-bbbb", "state": "triage", "severity": "critical", "created_at": old,
					"summary": "Bogus", "author": map[string]string{"login": "rep"},
					"description": "The function `no_such_fn()` in nothing/here.py is broken."},
				{"ghsa_id": "GHSA-cccc-cccc-cccc", "state": "published", "severity": "low", "created_at": old,
					"summary": "old one", "author": map[string]string{"login": "rep"}, "description": "x"},
			})
		case "/users/rep":
			_ = json.NewEncoder(w).Encode(map[string]any{"created_at": old, "public_repos": 3})
		case "/repos/o/r/dependabot/alerts":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"src/app/parse.py": "def parse_header(v):\n    pass\n"})

	reports, err := GatherReports(&GitHub{BaseURL: server.URL, Client: server.Client()}, ReportsOptions{Repo: "o/r", Directory: dir})
	if err != nil {
		t.Fatal(err)
	}

	if len(reports) != 2 {
		t.Fatalf("got %d reports, want the 2 in triage: %+v", len(reports), reports)
	}

	// The report whose claims match the code outranks a critical one that names nothing real.
	if reports[0].GHSA != "GHSA-aaaa-aaaa-aaaa" {
		t.Errorf("queue order: %s first, want the one that matches the code (scores %d, %d)",
			reports[0].GHSA, reports[0].Score, reports[1].Score)
	}

	r := reports[0]
	for _, want := range []string{"reproduction", "external-link", "attachment", "patch", "pressure"} {
		if !hasShape(r.Shape, want) {
			t.Errorf("shape %v missing %q", r.Shape, want)
		}
	}

	if len(r.Claim.Files) != 1 || len(r.Claim.Symbols) != 1 || len(r.Claim.FilesMissing)+len(r.Claim.SymbolsMissing) != 0 {
		t.Errorf("claim = %+v", r.Claim)
	}

	if r.Reporter.PriorPublished != 1 || !r.Reporter.Known {
		t.Errorf("reporter = %+v", r.Reporter)
	}

	bogus := reports[1].Claim
	if len(bogus.FilesMissing) != 1 || len(bogus.SymbolsMissing) != 1 {
		t.Errorf("bogus claim = %+v", bogus)
	}

	var sb strings.Builder

	WriteReports(&sb, "o/r", reports)

	if !strings.Contains(sb.String(), "GHSA-aaaa-aaaa-aaaa") {
		t.Errorf("table missing report: %s", sb.String())
	}
}

func TestGatherReportsScopeError(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	_, err := GatherReports(&GitHub{BaseURL: server.URL, Client: server.Client()}, ReportsOptions{Repo: "o/r"})
	if err == nil || !strings.Contains(err.Error(), "scope problem") {
		t.Errorf("err = %v, want the scope hint", err)
	}
}
