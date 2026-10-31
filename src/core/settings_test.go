package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDependabotBranchUpdates(t *testing.T) {
	for _, tc := range []struct {
		branch, pkg string
		want        bool
	}{
		{"dependabot/npm_and_yarn/ui/firebase-13.1.0", "firebase", true},
		{"dependabot/npm_and_yarn/ui/firebase-tools-15.0.0", "firebase", false},
		{"dependabot/pip/tzdata-gte-2026.6", "tzdata", true},
		{"dependabot/npm_and_yarn/@scope/kit-1.2.1", "@scope/kit", true},
		{"dependabot/pip/ruff-0.17.3", "uuid", false},
	} {
		if got := dependabotBranchUpdates(tc.branch, tc.pkg); got != tc.want {
			t.Errorf("dependabotBranchUpdates(%q, %q) = %v", tc.branch, tc.pkg, got)
		}
	}
}

// garmin-mcp-gt's setup in October 2026: alerts on, security updates off, version updates
// on - and one Dependabot PR that does fix an open alert.
func TestCheckDependabotSettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/vulnerability-alerts":
			w.WriteHeader(http.StatusNoContent)
		case "/repos/o/r/automated-security-fixes":
			_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": false, "paused": false})
		case "/repos/o/r/pulls":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"number": 38, "title": "Bump firebase", "user": map[string]string{"login": "dependabot[bot]"},
					"head": map[string]string{"ref": "dependabot/npm_and_yarn/ui/firebase-13.1.0"}},
				{"number": 41, "title": "Bump uuid", "user": map[string]string{"login": "dependabot[bot]"},
					"head": map[string]string{"ref": "dependabot/npm_and_yarn/ui/uuid-11.1.1"}},
				{"number": 42, "title": "a feature", "user": map[string]string{"login": "someone"},
					"head": map[string]string{"ref": "feature"}},
			})
		case "/repos/o/r/dependabot/alerts":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"number": 10, "dependency": map[string]any{"package": map[string]string{"name": "uuid"}}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{".github/dependabot.yml": `version: 2
updates:
  - package-ecosystem: pip
    directory: /
    schedule: {interval: weekly}
  - package-ecosystem: npm
    directory: /ui
    open-pull-requests-limit: 0
    schedule: {interval: weekly}
`})

	gh := &GitHub{BaseURL: server.URL, Client: server.Client()}

	s, err := CheckDependabotSettings(gh, "o/r", dir)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"Dependabot alerts": true, "Dependabot security updates": false, "Dependabot version updates": false}
	for _, c := range s.Checks {
		if ok, known := want[c.Check]; !known || ok != c.OK {
			t.Errorf("check %q ok=%v (%s)", c.Check, c.OK, c.Problem)
		}
	}

	if len(s.PRs) != 2 || s.PRs[0].Security || !s.PRs[1].Security {
		t.Errorf("PRs = %+v, want #38 a version bump and #41 a security fix", s.PRs)
	}

	// Only the pip entry opens version PRs; the npm one is limited to 0.
	for _, c := range s.Checks {
		if c.Check == "Dependabot version updates" && c.Problem[:10] != "on for pip" {
			t.Errorf("problem = %q", c.Problem)
		}
	}
}
