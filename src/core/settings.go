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
	"time"

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
	s.checkConfigPresent(gh, api)
	s.checkRuns(gh, api, dir)

	return s, nil
}

// dependabotRun is one of Dependabot's own workflow runs (event=dynamic).
type dependabotRun struct {
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
}

// lockFiles are the manifests and locks whose last commit is compared with the dependency
// graph's last update.
var lockFiles = []string{
	"uv.lock", "poetry.lock", "requirements.txt", "package-lock.json", "yarn.lock", "go.mod",
}

// checkRuns reads Dependabot's recent runs (they appear as workflow runs with event=dynamic when
// it uses Actions runners) and flags a failed run, and a dependency graph older than the lock.
// No runs is reported as unknown, never as "never ran": legacy runners don't show up here.
func (s *DependabotSettings) checkRuns(gh *GitHub, api, dir string) {
	var r struct {
		WorkflowRuns []dependabotRun `json:"workflow_runs"`
	}

	if err := gh.getJSON(api+"/actions/runs?event=dynamic&per_page=50", &r); err != nil {
		s.add(SettingCheck{
			Check: "Dependabot runs", Unknown: true,
			Problem: "couldn't read Dependabot's runs: " + err.Error(),
		})

		return
	}

	if len(r.WorkflowRuns) == 0 {
		s.add(SettingCheck{
			Check: "Dependabot runs", Unknown: true,
			Problem: "no runs visible - Dependabot may be on legacy runners; " +
				"see Insights > Dependency graph > Dependabot for when it last checked",
		})

		return
	}

	// The newest run of each kind, and the newest successful graph update.
	latest := map[string]dependabotRun{}

	var graphOK time.Time

	for _, run := range r.WorkflowRuns {
		kind := dependabotRunKind(run.Name)
		if cur, ok := latest[kind]; !ok || run.CreatedAt.After(cur.CreatedAt) {
			latest[kind] = run
		}

		if kind == "graph update" && run.Conclusion == "success" && run.CreatedAt.After(graphOK) {
			graphOK = run.CreatedAt
		}
	}

	var failed []string

	for _, kind := range []string{"version update", "security update", "graph update"} {
		if run, ok := latest[kind]; ok && run.Conclusion != "" && run.Conclusion != "success" {
			failed = append(failed, fmt.Sprintf("%s %s (%s)", kind, run.Conclusion, run.CreatedAt.Format("2006-01-02")))
		}
	}

	s.add(SettingCheck{
		OK: len(failed) == 0, Check: "Dependabot runs",
		Problem: "last run failed: " + strings.Join(failed, "; ") + " - alerts or PRs may be missing",
		Fix:     "re-run it from the repository's Actions tab, then check Insights > Dependency graph > Dependabot",
	})

	s.checkGraphFresh(gh, api, dir, graphOK)
}

// dependabotRunKind classifies a run by its workflow name.
func dependabotRunKind(name string) string {
	switch {
	case strings.HasPrefix(name, "Graph Update"):
		return "graph update"
	case name == "Dependabot Updates":
		return "version update"
	default:
		return "security update"
	}
}

// checkGraphFresh flags a lock or manifest committed to the default branch after the dependency
// graph last updated successfully: alerts are matched against the graph, so they may be stale.
func (s *DependabotSettings) checkGraphFresh(gh *GitHub, api, dir string, graphOK time.Time) {
	if graphOK.IsZero() {
		return
	}

	var changed time.Time

	changedFile := ""

	for _, name := range lockFiles {
		if !Exists(filepath.Join(dir, name)) {
			continue
		}

		var commits []struct {
			Commit struct {
				Committer struct {
					Date time.Time `json:"date"`
				} `json:"committer"`
			} `json:"commit"`
		}

		if err := gh.getJSON(api+"/commits?per_page=1&path="+name, &commits); err != nil || len(commits) == 0 {
			continue
		}

		if d := commits[0].Commit.Committer.Date; d.After(changed) {
			changed, changedFile = d, name
		}
	}

	s.add(SettingCheck{
		OK: changedFile == "" || !changed.After(graphOK), Check: "Dependency graph",
		Problem: fmt.Sprintf("%s changed %s, after the graph last updated (%s) - alerts may not reflect the current lock",
			changedFile, changed.Format("2006-01-02 15:04"), graphOK.Format("2006-01-02 15:04")),
		Fix: "wait for the next graph update, or re-run \"Graph Update\" from the Actions tab",
	})
}

// checkConfigPresent flags a repository with no .github/dependabot.yml. It asks GitHub rather
// than the checkout, so it gives the same answer when picard is pointed at a bare directory.
// A file whose entries all have open-pull-requests-limit: 0 is the intended setup: Dependabot
// is configured but only security updates open PRs.
func (s *DependabotSettings) checkConfigPresent(gh *GitHub, api string) {
	found := false

	for _, name := range []string{"dependabot.yml", "dependabot.yaml"} {
		code, err := gh.exists(api + "/contents/.github/" + name)
		if err != nil {
			s.add(SettingCheck{
				Check: "Dependabot config", Unknown: true,
				Problem: "couldn't tell whether .github/dependabot.yml exists: " + err.Error(),
			})

			return
		}

		if code == http.StatusOK {
			found = true

			break
		}
	}

	s.add(SettingCheck{
		OK: found, Check: "Dependabot config",
		Problem: "no .github/dependabot.yml",
		Fix: "add .github/dependabot.yml with an entry per ecosystem and open-pull-requests-limit: 0, " +
			"so only security updates open PRs",
	})
}

// exists reports whether a GET returns 200 (found) or 404 (not found); anything else is an error.
func (g *GitHub) exists(url string) (int, error) {
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

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return resp.StatusCode, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	return resp.StatusCode, nil
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
