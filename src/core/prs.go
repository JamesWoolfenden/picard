package core

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
)

// What a Dependabot PR does, from the advisories its lock change removes and adds.
const (
	PRFixesShipped = "fixes-shipped" // removes an advisory against something that ships
	PRFixesDevOnly = "fixes-dev-only"
	PRFixesNothing = "fixes-nothing"
	PRAddsAdvisory = "adds-advisory" // the new versions have advisories the old didn't
	// PRNoInstallChange: a manifest change that can't change what's installed - a floor
	// raised in an unpinned requirements file (resolution already picks the newest), or a
	// manifest whose lock the PR leaves as it was.
	PRNoInstallChange = "no-install-change"
	PRUnknown         = "unknown" // changes nothing picard can read
)

// PRAdvisory is an advisory a PR removes or adds, with its verdict in the version that
// has it.
type PRAdvisory struct {
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	ID       string  `json:"id"`
	Summary  string  `json:"summary"`
	Severity string  `json:"severity"`
	Verdict  Verdict `json:"verdict"`
}

// PRTriage is picard's reading of one Dependabot PR - facts only: whether it's safe to
// merge (breaking changes, release notes) is left to whoever reviews it.
type PRTriage struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	URL    string `json:"url"`
	// Package, From and To are parsed from the title; Major is a change of major version.
	Package string `json:"package"`
	From    string `json:"from"`
	To      string `json:"to"`
	Major   bool   `json:"major"`
	// Files the PR changes; Locks the ones picard compared.
	Files []string `json:"files"`
	Locks []string `json:"locks"`
	// CI is the head commit's checks: passing, failing, pending or none.
	CI      string       `json:"ci"`
	Class   string       `json:"class"`
	Reason  string       `json:"reason"`
	Removes []PRAdvisory `json:"removes,omitempty"`
	Adds    []PRAdvisory `json:"adds,omitempty"`
}

var prTitleRe = regexp.MustCompile(`^(?:Bump|Update) (\S+)(?: requirement)? from (\S+) to (\S+)`)

// TriagePRs reads each Dependabot PR: which lock files it changes, and - scanning the lock
// at the PR's base and head - which advisories it removes or adds.
func TriagePRs(gh *GitHub, repo, dir string, prs []PullRequest, scan Options) ([]PRTriage, error) {
	api := fmt.Sprintf("%s/repos/%s", gh.BaseURL, repo)

	// Every scan is lock facts only - no coverage, no assessment.
	scan.Coverage, scan.Assessor = "", nil

	out := make([]PRTriage, 0, len(prs))

	for _, pr := range prs {
		t := PRTriage{Number: pr.Number, Title: pr.Title, URL: fmt.Sprintf("https://github.com/%s/pull/%d", repo, pr.Number)}

		if m := prTitleRe.FindStringSubmatch(pr.Title); m != nil {
			t.Package, t.From, t.To = m[1], m[2], m[3]
			t.Major = majorOf(t.From) != majorOf(t.To)
		}

		var files []struct {
			Filename string `json:"filename"`
		}

		if err := gh.getJSON(fmt.Sprintf("%s/pulls/%d/files?per_page=100", api, pr.Number), &files); err != nil {
			return nil, err
		}

		for _, f := range files {
			t.Files = append(t.Files, f.Filename)
		}

		t.CI = gh.checks(api, pr.Head.SHA)

		if err := t.compare(gh, api, dir, pr, scan); err != nil {
			t.Class, t.Reason = PRUnknown, "scan failed: "+err.Error()
		}

		out = append(out, t)
	}

	return out, nil
}

// compare scans each lock the PR changes, at its base and head, and classifies the PR.
func (t *PRTriage) compare(gh *GitHub, api, dir string, pr PullRequest, scan Options) error {
	locks, unread, stale := prLocks(dir, t.Files)
	t.Locks = locks

	if len(locks) == 0 {
		switch {
		case len(unread) == 0:
			t.Class = PRNoInstallChange
			t.Reason = "changes " + strings.Join(stale, ", ") + " but not the lock beside it, so what's installed doesn't change"
		case len(stale) == 0 && floorsOnly(t, unread):
			t.Class = PRNoInstallChange
			t.Reason = "raises a >= floor in " + strings.Join(unread, ", ") +
				", which isn't pinned: builds already install the newest, so nothing installed changes"
		default:
			t.Class = PRUnknown
			t.Reason = "changes " + strings.Join(append(unread, stale...), ", ") + " - no lock file picard can compare"
		}

		return nil
	}

	unread = append(unread, stale...)

	for _, lock := range locks {
		before, err := scanAt(gh, api, dir, lock, pr.Base.SHA, scan)
		if err != nil {
			return err
		}

		after, err := scanAt(gh, api, dir, lock, pr.Head.SHA, scan)
		if err != nil {
			return err
		}

		t.Removes = append(t.Removes, advisoryDiff(before, after)...)
		t.Adds = append(t.Adds, advisoryDiff(after, before)...)
	}

	shipped := 0

	for _, a := range t.Removes {
		if a.Verdict != VerdictNotShipped {
			shipped++
		}
	}

	switch {
	case len(t.Adds) > 0:
		t.Class = PRAddsAdvisory
		t.Reason = fmt.Sprintf("the new versions have %s the old ones didn't", plural(len(t.Adds), "advisory"))
	case shipped > 0:
		t.Class = PRFixesShipped
		t.Reason = fmt.Sprintf("removes %s against shipped packages: %s", plural(shipped, "advisory"), describeRemoved(t.Removes, true))
	case len(t.Removes) > 0:
		t.Class = PRFixesDevOnly
		t.Reason = "removes only advisories against packages that don't ship: " + describeRemoved(t.Removes, false)
	default:
		t.Class = PRFixesNothing
		t.Reason = "a routine bump: removes no known advisory"
	}

	if len(unread) > 0 {
		t.Reason += " (also changes " + strings.Join(unread, ", ") + ", not compared)"
	}

	return nil
}

// prLocks maps the files a PR changes to the locks picard can compare (repo-relative), and
// the changed files it can't read.
// stale are manifests changed while the lock beside them isn't, so nothing installed changes.
func prLocks(dir string, files []string) (locks, unread, stale []string) {
	for _, f := range files {
		switch path.Base(f) {
		case "uv.lock", "package-lock.json":
			locks = append(locks, f)
		case "pyproject.toml", "package.json":
			lock := path.Join(path.Dir(f), map[string]string{"pyproject.toml": "uv.lock", "package.json": "package-lock.json"}[path.Base(f)])

			switch {
			case containsFile(files, lock): // compared through the lock
			case Exists(filepath.Join(dir, filepath.FromSlash(lock))):
				stale = append(stale, f)
			default:
				unread = append(unread, f)
			}
		default:
			unread = append(unread, f)
		}
	}

	sort.Strings(locks)

	return locks, unread, stale
}

func containsFile(files []string, want string) bool {
	for _, f := range files {
		if f == want {
			return true
		}
	}

	return false
}

// floorsOnly: the PR raises a >= floor ("from >=1.13.0 to >=2.3.0") and only touches
// requirements files.
func floorsOnly(t *PRTriage, files []string) bool {
	if !strings.HasPrefix(t.From, ">=") || !strings.HasPrefix(t.To, ">=") {
		return false
	}

	for _, f := range files {
		if !strings.HasPrefix(path.Base(f), "requirements") {
			return false
		}
	}

	return true
}

// scanAt scans a lock as it is at a commit, against the checkout's code for imports.
func scanAt(gh *GitHub, api, dir, lock, sha string, scan Options) (*Report, error) {
	body, err := gh.raw(fmt.Sprintf("%s/contents/%s?ref=%s", api, lock, sha))
	if err != nil {
		return nil, err
	}

	tmp, err := os.MkdirTemp("", "picard-pr-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	// Same file name: scan picks the lock format from it.
	file := filepath.Join(tmp, path.Base(lock))
	if err := os.WriteFile(file, body, 0o600); err != nil {
		return nil, err
	}

	scan.LockFile = file
	scan.Directory = filepath.Join(dir, filepath.FromSlash(path.Dir(lock)))

	return Scan(scan)
}

// advisoryDiff is the advisories in a that b doesn't have (by package and id).
func advisoryDiff(a, b *Report) []PRAdvisory {
	have := map[string]bool{}

	for _, f := range b.Findings {
		for _, adv := range f.Advisories {
			have[f.Package+"\x00"+adv.ID] = true
		}
	}

	var out []PRAdvisory

	for _, f := range a.Findings {
		for _, adv := range f.Advisories {
			if have[f.Package+"\x00"+adv.ID] {
				continue
			}

			out = append(out, PRAdvisory{
				Package: f.Package, Version: f.Version, ID: adv.ID, Summary: adv.Summary,
				Severity: adv.Severity, Verdict: adv.Verdict,
			})
		}
	}

	return out
}

func describeRemoved(advs []PRAdvisory, shippedOnly bool) string {
	var parts []string

	for _, a := range advs {
		if shippedOnly && a.Verdict == VerdictNotShipped {
			continue
		}

		parts = append(parts, fmt.Sprintf("%s %s %s (%s)", a.Package, a.Version, a.ID, a.Severity))
	}

	return strings.Join(parts, ", ")
}

// majorOf is a version's major component, ignoring requirement operators (>=1.13.0 -> 1).
func majorOf(v string) string {
	v = strings.TrimLeft(v, "=<>~^!v ")
	if i := strings.IndexAny(v, ".,"); i >= 0 {
		return v[:i]
	}

	return v
}

// checks summarizes a commit's check runs: passing, failing, pending or none.
func (g *GitHub) checks(api, sha string) string {
	var runs struct {
		CheckRuns []struct {
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
		} `json:"check_runs"`
	}

	if sha == "" || g.getJSON(fmt.Sprintf("%s/commits/%s/check-runs?per_page=100", api, sha), &runs) != nil {
		return "unknown"
	}

	if len(runs.CheckRuns) == 0 {
		return "none"
	}

	result := "passing"

	for _, r := range runs.CheckRuns {
		switch {
		case r.Status != "completed":
			result = "pending"
		case r.Conclusion == "failure" || r.Conclusion == "timed_out" || r.Conclusion == "cancelled":
			return "failing"
		}
	}

	return result
}

// raw GETs a file's raw contents from the contents API.
func (g *GitHub) raw(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.raw+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+g.Token)

	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// WritePRs writes the PR triage: a row per PR, then each reason.
func WritePRs(w io.Writer, repo string, prs []PRTriage) error {
	if len(prs) == 0 {
		_, err := fmt.Fprintf(w, "%s: no open Dependabot PRs\n", repo)

		return err
	}

	width := textWidth()

	fmt.Fprintf(w, "%s: %s from Dependabot\n\n", repo, plural(len(prs), "open PR"))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PR\tPACKAGE\tCHANGE\tCI\tWHAT IT DOES")

	for _, p := range prs {
		change := p.From + " → " + p.To
		if p.Major {
			change += " (major)"
		}

		fmt.Fprintf(tw, "#%d\t%s\t%s\t%s\t%s\n", p.Number, p.Package, change, p.CI, p.Class)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	for _, p := range prs {
		fmt.Fprintf(w, "\n#%d %s\n", p.Number, p.Title)
		fmt.Fprint(w, wrap(p.Reason, "  ", width))

		for _, a := range p.Adds {
			fmt.Fprint(w, wrap(fmt.Sprintf("adds %s %s %s (%s, %s): %s", a.Package, a.Version, a.ID, a.Severity, a.Verdict, a.Summary), "  ", width))
		}
	}

	return nil
}
