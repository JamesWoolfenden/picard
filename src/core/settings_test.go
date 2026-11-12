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
		case "/repos/o/r/contents/.github/dependabot.yml":
			_ = json.NewEncoder(w).Encode(map[string]string{"name": "dependabot.yml"})
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

	// The repo endpoint isn't served here, so malware alerts can't be told: unknown, not ok.
	want := map[string]bool{"Dependabot alerts": true, "Dependabot security updates": false, "Dependabot version updates": false, "Malware alerts": false, "Dependabot config": true}
	for _, c := range s.Checks {
		if c.Check == "Malware alerts" && !c.Unknown {
			t.Errorf("malware alerts should be unknown: %+v", c)
		}

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

func TestCheckSecurityAndAnalysis(t *testing.T) {
	for _, tc := range []struct {
		name    string
		block   map[string]any
		malware string // "ok", "fix" or "unknown"
		extra   []string
	}{
		{"no malware field, push protection off", map[string]any{
			"secret_scanning_push_protection": map[string]string{"status": "disabled"},
			"secret_scanning_validity_checks": map[string]string{"status": "disabled"},
			"dependabot_security_updates":     map[string]string{"status": "enabled"},
		}, "unknown", []string{"Secret scanning push protection", "Secret scanning validity checks"}},
		{"malware on", map[string]any{
			"dependabot_malware_alerts":       map[string]string{"status": "enabled"},
			"secret_scanning_push_protection": map[string]string{"status": "enabled"},
		}, "ok", nil},
		{"malware off", map[string]any{
			"dependabot_malware_alerts": map[string]string{"status": "disabled"},
		}, "fix", nil},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/o/r" {
				_ = json.NewEncoder(w).Encode(map[string]any{"security_and_analysis": tc.block})

				return
			}

			http.NotFound(w, r)
		}))

		s := &DependabotSettings{}
		s.checkSecurityAndAnalysis(&GitHub{BaseURL: server.URL, Client: server.Client()}, server.URL+"/repos/o/r", "o/r")
		server.Close()

		got := map[string]SettingCheck{}
		for _, c := range s.Checks {
			got[c.Check] = c
		}

		m := got["Malware alerts"]

		switch tc.malware {
		case "ok":
			if !m.OK {
				t.Errorf("%s: malware %+v, want ok", tc.name, m)
			}
		case "fix":
			if m.OK || m.Unknown || m.Fix == "" {
				t.Errorf("%s: malware %+v, want a fix", tc.name, m)
			}
		case "unknown":
			if m.OK || !m.Unknown {
				t.Errorf("%s: malware %+v, want unknown", tc.name, m)
			}
		}

		if len(s.Checks) != 1+len(tc.extra) {
			t.Errorf("%s: %d checks %+v, want malware plus %v", tc.name, len(s.Checks), s.Checks, tc.extra)
		}

		for _, name := range tc.extra {
			if c, ok := got[name]; !ok || c.OK {
				t.Errorf("%s: want a failing %q", tc.name, name)
			}
		}
	}
}

// The file is looked up on GitHub, not in the directory picard is pointed at, so a bare -d
// directory doesn't flag every repository.
func TestCheckConfigPresent(t *testing.T) {
	for _, tc := range []struct {
		name        string
		paths       map[string]int // path -> status; anything else 404
		wantOK      bool
		wantUnknown bool
	}{
		{"yml", map[string]int{"/repos/o/r/contents/.github/dependabot.yml": 200}, true, false},
		{"yaml", map[string]int{"/repos/o/r/contents/.github/dependabot.yaml": 200}, true, false},
		{"missing", map[string]int{}, false, false},
		{"forbidden", map[string]int{"/repos/o/r/contents/.github/dependabot.yml": 403}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if code, ok := tc.paths[r.URL.Path]; ok {
					w.WriteHeader(code)

					return
				}

				http.NotFound(w, r)
			}))
			defer server.Close()

			s := &DependabotSettings{}
			s.checkConfigPresent(&GitHub{BaseURL: server.URL, Client: server.Client()}, server.URL+"/repos/o/r")

			if len(s.Checks) != 1 {
				t.Fatalf("checks = %+v", s.Checks)
			}

			c := s.Checks[0]
			if c.Check != "Dependabot config" || c.OK != tc.wantOK || c.Unknown != tc.wantUnknown {
				t.Errorf("check = %+v", c)
			}

			if !tc.wantOK && !tc.wantUnknown && c.Fix == "" {
				t.Error("a missing file should come with a fix")
			}
		})
	}
}
