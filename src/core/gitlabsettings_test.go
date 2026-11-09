package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gitlabServer(t *testing.T, enabled, available []string, counts map[string]int) *GitLab {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Variables map[string]string `json:"variables"`
		}

		_ = json.NewDecoder(r.Body).Decode(&req)

		if r.URL.Path != "/api/graphql" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unexpected", http.StatusBadRequest)

			return
		}

		var project any
		if req.Variables["path"] == "team/project" {
			project = map[string]any{
				"securityScanners":             map[string]any{"enabled": enabled, "available": available},
				"vulnerabilitySeveritiesCount": counts,
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"project": project}})
	}))
	t.Cleanup(server.Close)

	return &GitLab{BaseURL: server.URL, Token: "tok", Client: server.Client()}
}

func TestCheckGitLabSettings(t *testing.T) {
	ultimate := []string{"SAST", "DEPENDENCY_SCANNING", "CONTAINER_SCANNING"}

	for _, tc := range []struct {
		name               string
		enabled, available []string
		ci                 string
		ok                 bool
		problem            string
	}{
		{"running", []string{"SAST", "DEPENDENCY_SCANNING"}, ultimate, "", true, ""},
		{"not licensed", nil, []string{"SAST", "SECRET_DETECTION"}, "", false, "not available"},
		{"configured, not run", []string{"SAST"}, ultimate,
			"include:\n  - template: Jobs/Dependency-Scanning.gitlab-ci.yml\n", false, "in .gitlab-ci.yml but hasn't run"},
		{"off", nil, ultimate, "stages: [test]\n", false, "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.ci != "" {
				writeFiles(t, dir, map[string]string{".gitlab-ci.yml": tc.ci})
			}

			gl := gitlabServer(t, tc.enabled, tc.available, map[string]int{"critical": 0, "high": 2, "low": 1})

			s, err := CheckGitLabSettings(gl, "team/project", dir)
			if err != nil {
				t.Fatal(err)
			}

			c := s.Checks[0]
			if c.OK != tc.ok || !strings.HasPrefix(c.Problem, tc.problem) {
				t.Errorf("check = %+v, want ok=%v problem %q...", c, tc.ok, tc.problem)
			}

			if len(s.OpenFindings) != 2 || s.OpenFindings["high"] != 2 || s.OpenFindings["low"] != 1 {
				t.Errorf("open findings = %v, want high 2, low 1", s.OpenFindings)
			}
		})
	}
}

func TestCheckGitLabSettingsMissingProject(t *testing.T) {
	gl := gitlabServer(t, nil, nil, nil)

	if _, err := CheckGitLabSettings(gl, "team/other", t.TempDir()); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v, want not found", err)
	}
}
