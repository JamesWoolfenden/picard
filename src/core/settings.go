package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SettingCheck is one finding about how a repository's Dependabot is set up.
type SettingCheck struct {
	// OK: nothing to do. Otherwise Problem says what's wrong and Fix how to fix it.
	OK bool `json:"ok"`
	// Unknown: the API doesn't say, so picard can't tell. Not OK, but not a failure either.
	Unknown bool   `json:"unknown,omitempty"`
	Check   string `json:"check"`
	Problem string `json:"problem,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// PullRequest is an open pull request, as far as the settings check needs it.
type PullRequest struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	User   struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		SHA string `json:"sha"`
	} `json:"base"`
	// Security: it updates a package with an open alert, rather than being a routine
	// version bump.
	Security bool `json:"security"`
}

// DependabotSettings is the result of checking a repository's Dependabot setup.
type DependabotSettings struct {
	Checks []SettingCheck `json:"checks"`
	// PRs are Dependabot's open pull requests.
	PRs []PullRequest `json:"pull_requests"`
}

type dependabotConfig struct {
	Updates []struct {
		Ecosystem   string   `yaml:"package-ecosystem"`
		Directory   string   `yaml:"directory"`
		Directories []string `yaml:"directories"`
		Limit       *int     `yaml:"open-pull-requests-limit"`
	} `yaml:"updates"`
}

// CheckDependabotSettings checks what makes Dependabot useful rather than noisy: alerts on,
// security updates on (so real alerts get fix PRs) and version updates off (routine bumps
// that fix nothing). Pinning is ghat's job, not checked here.
func CheckDependabotSettings(gh *GitHub, repo, dir string) (*DependabotSettings, error) {
	s := &DependabotSettings{}
	api := fmt.Sprintf("%s/repos/%s", gh.BaseURL, repo)

	// 204 when enabled, 404 when not.
	code, err := gh.status(api + "/vulnerability-alerts")
	if err != nil {
		return nil, err
	}

	s.add(SettingCheck{
		OK: code == http.StatusNoContent, Check: "Dependabot alerts",
		Problem: "disabled - nothing reports vulnerable dependencies",
		Fix:     "gh api -X PUT repos/" + repo + "/vulnerability-alerts",
	})

	var fixes struct {
		Enabled bool `json:"enabled"`
		Paused  bool `json:"paused"`
	}

	if err := gh.getJSON(api+"/automated-security-fixes", &fixes); err != nil {
		return nil, err
	}

	s.add(SettingCheck{
		OK: fixes.Enabled && !fixes.Paused, Check: "Dependabot security updates",
		Problem: "disabled - alerts that matter get no fix PR",
		Fix:     "gh api -X PUT repos/" + repo + "/automated-security-fixes",
	})

	s.checkSecurityAndAnalysis(gh, api, repo)

	if err := s.loadPRs(gh, api); err != nil {
		return nil, err
	}

	s.checkVersionUpdates(dir)

	return s, nil
}

// checkSecurityAndAnalysis reads the repository's security_and_analysis block: Malware alerts
// (reported as unknown when the API doesn't expose it) and, when present and off, secret
// scanning push protection and validity checks. A repository the token can't see the block
// of (it needs admin access) gets unknown for malware alerts and nothing for the others.
func (s *DependabotSettings) checkSecurityAndAnalysis(gh *GitHub, api, repo string) {
	var r struct {
		SecurityAndAnalysis map[string]struct {
			Status string `json:"status"`
		} `json:"security_and_analysis"`
	}

	// An error here (no access, or the endpoint is unavailable) just means we can't tell.
	_ = gh.getJSON(api, &r)

	malware := ""

	for key := range r.SecurityAndAnalysis {
		if strings.Contains(key, "malware") {
			malware = key
		}
	}

	if malware == "" {
		s.add(SettingCheck{
			Unknown: true, Check: "Malware alerts",
			Problem: "the API doesn't say whether they're on (no malware field in security_and_analysis); " +
				"the Dependabot page shows \"Malware alerts are disabled\" when off",
			Fix: gitHubHost(gh) + "/" + repo + "/settings/security_analysis - enable Malware alerts if off",
		})
	} else {
		s.add(SettingCheck{
			OK: r.SecurityAndAnalysis[malware].Status == "enabled", Check: "Malware alerts",
			Problem: "disabled - malicious packages in the lock go unreported",
			Fix:     "enable Malware alerts at " + gitHubHost(gh) + "/" + repo + "/settings/security_analysis",
		})
	}

	for _, c := range []struct{ key, check string }{
		{"secret_scanning_push_protection", "Secret scanning push protection"},
		{"secret_scanning_validity_checks", "Secret scanning validity checks"},
	} {
		if v, ok := r.SecurityAndAnalysis[c.key]; ok && v.Status != "enabled" {
			s.add(SettingCheck{
				Check: c.check, Problem: "disabled",
				Fix: "gh api -X PATCH repos/" + repo + " -f security_and_analysis[" + c.key + "][status]=enabled",
			})
		}
	}
}

// gitHubHost is the web address of the GitHub the client talks to.
func gitHubHost(gh *GitHub) string {
	if gh.BaseURL == DefaultGitHubURL {
		return "https://github.com"
	}

	return strings.TrimSuffix(strings.TrimSuffix(gh.BaseURL, "/api/v3"), "/")
}

func (s *DependabotSettings) add(c SettingCheck) {
	if c.OK {
		c.Problem, c.Fix = "", ""
	}

	s.Checks = append(s.Checks, c)
}

// loadPRs lists Dependabot's open PRs, marking those for a package with an open alert.
func (s *DependabotSettings) loadPRs(gh *GitHub, api string) error {
	var pulls []PullRequest
	if err := gh.getJSON(api+"/pulls?state=open&per_page=100", &pulls); err != nil {
		return err
	}

	var alerts []Alert
	if err := gh.getJSON(api+"/dependabot/alerts?state=open&per_page=100", &alerts); err != nil {
		return err
	}

	for _, pr := range pulls {
		if pr.User.Login != "dependabot[bot]" {
			continue
		}

		for _, a := range alerts {
			if dependabotBranchUpdates(pr.Head.Ref, a.Dependency.Package.Name) {
				pr.Security = true
			}
		}

		s.PRs = append(s.PRs, pr)
	}

	return nil
}

// dependabotBranchUpdates reports whether a Dependabot branch
// (dependabot/<ecosystem>/[<dir>/]<package>-<version>) updates the package.
func dependabotBranchUpdates(branch, pkg string) bool {
	last := branch[strings.LastIndex(branch, "/")+1:]
	if strings.HasPrefix(pkg, "@") { // scoped: dependabot/npm_and_yarn/@scope/name-1.0.0
		last = branch[strings.LastIndex(branch, "/"+pkg[:strings.Index(pkg, "/")])+1:]
	}

	rest, ok := strings.CutPrefix(NormalizeName(last), NormalizeName(pkg)+"-")

	// What follows the name is a version (1.2.0) or a requirement (gte-2026.6), so
	// firebase-tools-15.0.0 isn't firebase.
	return ok && branchVersionRe.MatchString(rest)
}

var branchVersionRe = regexp.MustCompile(`^((gte|gt|lte|lt|eq|tw)-)?v?\d`)

// checkVersionUpdates flags dependabot.yml entries that open routine version-bump PRs.
func (s *DependabotSettings) checkVersionUpdates(dir string) {
	var cfg dependabotConfig

	path := ""

	for _, name := range []string{"dependabot.yml", "dependabot.yaml"} {
		if p := filepath.Join(dir, ".github", name); Exists(p) {
			path = p
		}
	}

	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = yaml.Unmarshal(data, &cfg)
		}
	}

	var noisy []string

	for _, u := range cfg.Updates {
		if u.Limit != nil && *u.Limit == 0 {
			continue
		}

		dirs := u.Directories
		if u.Directory != "" {
			dirs = append(dirs, u.Directory)
		}

		noisy = append(noisy, u.Ecosystem+" "+strings.Join(dirs, ","))
	}

	version := 0

	for _, pr := range s.PRs {
		if !pr.Security {
			version++
		}
	}

	problem := ""
	if len(noisy) > 0 {
		problem = fmt.Sprintf("on for %s - %s open now. They're routine bumps, not fixes for alerts; "+
			"`picard scan` finds the rare one that does fix an advisory", strings.Join(noisy, "; "),
			plural(version, "PR"))
	}

	s.add(SettingCheck{
		OK: len(noisy) == 0, Check: "Dependabot version updates",
		Problem: problem,
		Fix:     "set open-pull-requests-limit: 0 on each entry in .github/dependabot.yml (security updates are unaffected)",
	})
}

// WriteSettings writes the checks: problems with their fix, then the open PRs.
func WriteSettings(w io.Writer, repo string, s *DependabotSettings) {
	width := textWidth()

	fmt.Fprintf(w, "%s: Dependabot setup\n", repo)
	writeChecks(w, s.Checks)

	if len(s.PRs) > 0 {
		fmt.Fprintln(w, "\n  Open Dependabot PRs:")

		for _, pr := range s.PRs {
			kind := "version bump"
			if pr.Security {
				kind = "security fix"
			}

			fmt.Fprintf(w, "  #%-4d %-13s %s\n", pr.Number, kind, clip(pr.Title, width-22))
		}
	}

	fmt.Fprintln(w)
}

// writeChecks writes one line per check, with the problem and fix under each that fails.
func writeChecks(w io.Writer, checks []SettingCheck) {
	width := textWidth()

	for _, c := range checks {
		if c.OK {
			fmt.Fprintf(w, "  ok    %s\n", c.Check)

			continue
		}

		if c.Unknown {
			fmt.Fprintf(w, "  ?     %s\n", c.Check)
			fmt.Fprint(w, wrap(c.Problem, "        ", width))
			fmt.Fprint(w, wrap("check: "+c.Fix, "        ", width))

			continue
		}

		fmt.Fprintf(w, "  FIX   %s\n", c.Check)
		fmt.Fprint(w, wrap(c.Problem, "        ", width))
		fmt.Fprint(w, wrap("fix: "+c.Fix, "        ", width))
	}
}

// getJSON GETs a URL and decodes the JSON response into v.
func (g *GitHub) getJSON(url string, v any) error {
	resp, err := g.do(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("decoding %s: %w", url, err)
	}

	return nil
}

// status GETs a URL for its status code alone, for endpoints that answer yes/no with
// 204/404.
func (g *GitHub) status(url string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+g.Token)

	resp, err := g.Client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", url, err)
	}

	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return resp.StatusCode, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	return resp.StatusCode, nil
}
