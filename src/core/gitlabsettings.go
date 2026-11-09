package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
)

// GitLabSettings is the result of checking a GitLab project's dependency scanning setup,
// the GitLab counterpart of DependabotSettings.
type GitLabSettings struct {
	Checks []SettingCheck `json:"checks"`
	// OpenFindings counts the project's open (detected or confirmed) dependency scanning
	// vulnerabilities by severity.
	OpenFindings map[string]int `json:"open_findings"`
}

const dependencyScanningInclude = "include: [{template: Jobs/Dependency-Scanning.gitlab-ci.yml}]"

// ciDependencyScanningRe spots dependency scanning in a .gitlab-ci.yml: the template, or a
// gemnasium analyzer job of its own.
var ciDependencyScanningRe = regexp.MustCompile(`(?i)Dependency-Scanning\.gitlab-ci\.yml|gemnasium`)

// CheckGitLabSettings checks that GitLab reports vulnerable dependencies: dependency scanning
// licensed and running on the default branch. GitLab counts a scanner as enabled when it
// ran in the default branch's latest pipeline.
func CheckGitLabSettings(gl *GitLab, project, dir string) (*GitLabSettings, error) {
	var data struct {
		Project *struct {
			SecurityScanners struct {
				Enabled   []string `json:"enabled"`
				Available []string `json:"available"`
			} `json:"securityScanners"`
			Counts map[string]int `json:"vulnerabilitySeveritiesCount"`
		} `json:"project"`
	}

	const query = `query($path: ID!) { project(fullPath: $path) {
  securityScanners { enabled available }
  vulnerabilitySeveritiesCount(reportType: [DEPENDENCY_SCANNING], state: [DETECTED, CONFIRMED]) {
    critical high medium low info unknown }
} }`

	if err := gl.graphql(query, map[string]any{"path": project}, &data); err != nil {
		return nil, err
	}

	if data.Project == nil {
		return nil, fmt.Errorf("GitLab project %s not found on %s, or no access to it", project, gl.BaseURL)
	}

	s := &GitLabSettings{OpenFindings: map[string]int{}}

	for sev, n := range data.Project.Counts {
		if n > 0 {
			s.OpenFindings[sev] = n
		}
	}

	scanners := data.Project.SecurityScanners
	check := SettingCheck{Check: "GitLab dependency scanning"}

	switch {
	case slices.Contains(scanners.Enabled, "DEPENDENCY_SCANNING"):
		check.OK = true
	case !slices.Contains(scanners.Available, "DEPENDENCY_SCANNING"):
		check.Problem = "not available on this instance's license (it needs Ultimate) - nothing in GitLab reports vulnerable dependencies"
		check.Fix = "run `picard scan` in a CI job instead"
	case ciConfigured(dir):
		check.Problem = "in .gitlab-ci.yml but hasn't run in the default branch's latest pipeline - " +
			"its job may be failing, skipped by rules, or no pipeline has run since it was added"
		check.Fix = "run a pipeline on the default branch and check the dependency scanning job"
	default:
		check.Problem = "off - nothing in GitLab reports vulnerable dependencies"
		check.Fix = "add to .gitlab-ci.yml: " + dependencyScanningInclude
	}

	s.add(check)

	return s, nil
}

func (s *GitLabSettings) add(c SettingCheck) {
	if c.OK {
		c.Problem, c.Fix = "", ""
	}

	s.Checks = append(s.Checks, c)
}

// ciConfigured reports whether the checkout's .gitlab-ci.yml mentions dependency scanning.
// Pipelines built from includes elsewhere aren't followed; GitLab's own view decides OK.
func ciConfigured(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, ".gitlab-ci.yml"))

	return err == nil && ciDependencyScanningRe.Match(data)
}

// WriteGitLabSettings writes the checks and the open findings.
func WriteGitLabSettings(w io.Writer, project string, s *GitLabSettings) {
	fmt.Fprintf(w, "%s: GitLab dependency scanning setup\n", project)
	writeChecks(w, s.Checks)

	total := 0
	for _, n := range s.OpenFindings {
		total += n
	}

	if total > 0 {
		fmt.Fprintf(w, "\n  %s open:", plural(total, "dependency scanning finding"))

		for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
			if n := s.OpenFindings[sev]; n > 0 {
				fmt.Fprintf(w, " %d %s", n, sev)
			}
		}

		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
}
