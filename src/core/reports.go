package core

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PrivateReport is one private vulnerability report (a repository security advisory in state
// triage) with the facts picard can gather about it. The report's text is untrusted data:
// it is only matched against patterns, never followed or executed.
type PrivateReport struct {
	GHSA     string    `json:"ghsa_id"`
	URL      string    `json:"url"`
	Summary  string    `json:"summary"`
	Severity string    `json:"severity"`
	Created  time.Time `json:"created_at"`
	AgeDays  int       `json:"age_days"`

	Reporter ReporterFacts `json:"reporter"`
	Claim    ClaimCheck    `json:"claim"`
	// Shape: what the report contains - "reproduction", "external-link", "attachment",
	// "patch", "pressure" (a deadline, payment or disclosure threat).
	Shape []string `json:"shape,omitempty"`
	// Overlap: other advisories or Dependabot alerts the report names or shares a file with.
	Overlap []string `json:"overlap,omitempty"`

	// Score orders the queue (higher = look sooner). It says how urgently to look, not
	// whether the report is real: the reproduction decides that.
	Score   int      `json:"score"`
	Reasons []string `json:"reasons,omitempty"`
}

// ReporterFacts is what GitHub says about the account that filed the report.
type ReporterFacts struct {
	Login       string `json:"login"`
	Known       bool   `json:"known"` // false: the account couldn't be read
	AccountDays int    `json:"account_age_days,omitempty"`
	PublicRepos int    `json:"public_repos,omitempty"`
	// Prior: other advisories on this repository from the same account, by outcome.
	PriorPublished int `json:"prior_published"`
	PriorClosed    int `json:"prior_closed"`
	PriorOpen      int `json:"prior_open"`
}

// ClaimCheck compares what the report names with the checkout. It does not check the
// affected versions: it looks at the files as checked out.
type ClaimCheck struct {
	Files        []string `json:"files,omitempty"`
	FilesMissing []string `json:"files_missing,omitempty"`
	Symbols      []string `json:"symbols,omitempty"`
	// SymbolsMissing are named functions found nowhere in the checkout's source.
	SymbolsMissing []string `json:"symbols_missing,omitempty"`
}

type repoAdvisory struct {
	GHSA        string    `json:"ghsa_id"`
	HTMLURL     string    `json:"html_url"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	Author      *struct {
		Login string `json:"login"`
	} `json:"author"`
}

var (
	reportFileRe   = regexp.MustCompile("[A-Za-z0-9_./-]+\\.(?:go|py|js|jsx|ts|tsx|rs|java|rb|php|c|h|cc|cpp|cs|yml|yaml|json|toml)\\b")
	reportSymbolRe = regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_.]*)\\(\\)?`")
	reportURLRe    = regexp.MustCompile(`https?://[^\s)>\]"']+`)
	reportGHSARe   = regexp.MustCompile(`GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}`)

	reproRe      = regexp.MustCompile(`(?i)reproduc|steps to|proof.of.concept|\bpoc\b`)
	attachmentRe = regexp.MustCompile(`(?i)\.(zip|exe|tar|tgz|gz|7z|bin|dll|so|jar|whl)\b|user-attachments`)
	patchRe      = regexp.MustCompile("(?m)diff --git|^\\+\\+\\+ |```diff")
	pressureRe   = regexp.MustCompile(`(?i)\b(\d+|ninety)[- ]day|disclos\w+ (on|in|publicly|after)|bounty|payment|reward|bitcoin|\$\d|deadline|or i will`)
)

// ReportsOptions are the inputs to GatherReports.
type ReportsOptions struct {
	Repo string
	// Directory is a checkout of the repository, for checking what a report names.
	Directory string
}

// GatherReports lists the repository's security advisories in state triage and gathers the
// facts about each. It is read-only. Needs admin or security manager access.
func GatherReports(gh *GitHub, opts ReportsOptions) ([]PrivateReport, error) {
	api := fmt.Sprintf("%s/repos/%s", gh.BaseURL, opts.Repo)

	all, err := getAll[repoAdvisory](gh, api+"/security-advisories?per_page=100")
	if err != nil {
		var he *HTTPError
		if errors.As(err, &he) && (he.Status == http.StatusNotFound || he.Status == http.StatusForbidden) {
			return nil, fmt.Errorf("%w - reading security advisories needs admin or security manager "+
				"access to %s and a token with the repo scope (classic) or \"Repository security "+
				"advisories: read\" (fine-grained); a 404 here is usually a scope problem", err, opts.Repo)
		}

		return nil, err
	}

	files, symbols := sourceIndex(opts.Directory)

	var alerts []Alert

	// Alerts are optional context: an error just means no overlap with them is reported.
	if a, err := gh.Alerts(opts.Repo, "open"); err == nil {
		alerts = a
	}

	var out []PrivateReport

	for _, a := range all {
		if a.State != "triage" {
			continue
		}

		out = append(out, buildReport(gh, a, all, alerts, files, symbols, opts.Directory))
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })

	return out, nil
}

func buildReport(gh *GitHub, a repoAdvisory, all []repoAdvisory, alerts []Alert, files map[string]bool,
	symbols func(string) bool, dir string) PrivateReport {
	text := a.Summary + "\n" + a.Description

	r := PrivateReport{
		GHSA: a.GHSA, URL: a.HTMLURL, Summary: a.Summary, Severity: a.Severity, Created: a.CreatedAt,
		AgeDays: int(time.Since(a.CreatedAt).Hours() / 24),
		Shape:   reportShape(text),
	}

	if a.Author != nil {
		r.Reporter = reporterFacts(gh, a.Author.Login, a.GHSA, all)
	}

	r.Claim = checkClaim(text, dir, files, symbols)
	r.Overlap = reportOverlap(a, all, alerts, r.Claim.Files)
	r.Score, r.Reasons = scoreReport(r)

	return r
}

// reportShape lists what the report contains, by pattern match alone.
func reportShape(text string) []string {
	var shape []string

	if reproRe.MatchString(text) {
		shape = append(shape, "reproduction")
	}

	for _, u := range reportURLRe.FindAllString(text, -1) {
		if p, err := url.Parse(u); err == nil && p.Host != "github.com" && p.Host != "" {
			shape = append(shape, "external-link")

			break
		}
	}

	if attachmentRe.MatchString(text) {
		shape = append(shape, "attachment")
	}

	if patchRe.MatchString(text) {
		shape = append(shape, "patch")
	}

	if pressureRe.MatchString(text) {
		shape = append(shape, "pressure")
	}

	return shape
}

func reporterFacts(gh *GitHub, login, self string, all []repoAdvisory) ReporterFacts {
	f := ReporterFacts{Login: login}

	var u struct {
		CreatedAt   time.Time `json:"created_at"`
		PublicRepos int       `json:"public_repos"`
	}

	if err := gh.getJSON(gh.BaseURL+"/users/"+login, &u); err == nil {
		f.Known = true
		f.AccountDays = int(time.Since(u.CreatedAt).Hours() / 24)
		f.PublicRepos = u.PublicRepos
	}

	for _, o := range all {
		if o.GHSA == self || o.Author == nil || o.Author.Login != login {
			continue
		}

		switch o.State {
		case "published":
			f.PriorPublished++
		case "closed":
			f.PriorClosed++
		default:
			f.PriorOpen++
		}
	}

	return f
}

// sourceIndex lists the checkout's files (relative, slash-separated) and returns a function
// that says whether an identifier appears in any source file. A missing checkout gives an
// empty index.
func sourceIndex(dir string) (map[string]bool, func(string) bool) {
	files := map[string]bool{}

	if dir == "" {
		return files, func(string) bool { return false }
	}

	var sources []string

	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are just not indexed
		}

		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".venv":
				return filepath.SkipDir
			}

			return nil
		}

		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = true

		if info, err := d.Info(); err == nil && info.Size() < 1<<20 && reportFileRe.MatchString(d.Name()) {
			sources = append(sources, p)
		}

		return nil
	})

	cache := map[string]bool{}
	loaded := false

	var bodies []string

	return files, func(sym string) bool {
		if v, ok := cache[sym]; ok {
			return v
		}

		if !loaded {
			for _, p := range sources {
				if b, err := os.ReadFile(p); err == nil {
					bodies = append(bodies, string(b))
				}
			}

			loaded = true
		}

		// A qualified name (pkg.Func) is found by its last part.
		name := sym[strings.LastIndex(sym, ".")+1:]
		found := false

		for _, b := range bodies {
			if strings.Contains(b, name) {
				found = true

				break
			}
		}

		cache[sym] = found

		return found
	}
}

// checkClaim finds the files and functions the report names and says which exist in the checkout.
func checkClaim(text, dir string, files map[string]bool, symbol func(string) bool) ClaimCheck {
	var c ClaimCheck

	if dir == "" {
		return c
	}

	seen := map[string]bool{}

	for _, f := range reportFileRe.FindAllString(text, -1) {
		f = strings.TrimPrefix(strings.TrimPrefix(f, "./"), "/")
		if seen[f] || strings.Contains(f, "..") {
			continue
		}

		seen[f] = true

		if fileExists(files, f) {
			c.Files = append(c.Files, f)
		} else {
			c.FilesMissing = append(c.FilesMissing, f)
		}
	}

	for _, m := range reportSymbolRe.FindAllStringSubmatch(text, -1) {
		s := m[1]
		if seen[s] {
			continue
		}

		seen[s] = true

		if symbol(s) {
			c.Symbols = append(c.Symbols, s)
		} else {
			c.SymbolsMissing = append(c.SymbolsMissing, s)
		}
	}

	return c
}

// fileExists matches a path exactly, or a bare file name anywhere in the tree.
func fileExists(files map[string]bool, name string) bool {
	if files[name] {
		return true
	}

	if !strings.Contains(name, "/") {
		for f := range files {
			if f == name || strings.HasSuffix(f, "/"+name) {
				return true
			}
		}
	}

	return false
}

// reportOverlap finds other advisories and Dependabot alerts the report names or shares a file with.
func reportOverlap(a repoAdvisory, all []repoAdvisory, alerts []Alert, files []string) []string {
	var out []string

	text := a.Summary + "\n" + a.Description

	named := map[string]bool{}
	for _, id := range reportGHSARe.FindAllString(text, -1) {
		named[strings.ToUpper(id)] = true
	}

	for _, o := range all {
		if o.GHSA == a.GHSA {
			continue
		}

		if named[strings.ToUpper(o.GHSA)] {
			out = append(out, fmt.Sprintf("names %s (%s)", o.GHSA, o.State))

			continue
		}

		for _, f := range files {
			if strings.Contains(o.Summary+"\n"+o.Description, f) {
				out = append(out, fmt.Sprintf("%s (%s) also mentions %s", o.GHSA, o.State, f))

				break
			}
		}
	}

	for _, al := range alerts {
		if id := al.SecurityAdvisory.GHSAID; id != "" && named[strings.ToUpper(id)] {
			out = append(out, fmt.Sprintf("names open Dependabot alert #%d (%s)", al.Number, id))
		}
	}

	return out
}

// scoreReport orders the queue. It says how urgently to look, never whether the report is
// true. Reporter reputation does not enter it.
func scoreReport(r PrivateReport) (int, []string) {
	score := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}[strings.ToLower(r.Severity)]

	var why []string

	add := func(n int, reason string) {
		score += n

		why = append(why, reason)
	}

	named := len(r.Claim.Files) + len(r.Claim.FilesMissing) + len(r.Claim.Symbols) + len(r.Claim.SymbolsMissing)
	found := len(r.Claim.Files) + len(r.Claim.Symbols)

	switch {
	case named > 0 && found == named:
		add(2, "everything it names exists in the checkout")
	case named > 0 && found == 0:
		add(-2, "nothing it names exists in the checkout")
	}

	if hasShape(r.Shape, "reproduction") {
		add(1, "has reproduction steps")
	}

	if r.AgeDays >= 7 {
		add(1, fmt.Sprintf("waiting %d days", r.AgeDays))
	}

	if len(r.Overlap) > 0 {
		add(-1, "overlaps an existing advisory or alert")
	}

	return score, why
}

func hasShape(shape []string, s string) bool {
	for _, x := range shape {
		if x == s {
			return true
		}
	}

	return false
}

// WriteReports writes the queue, most urgent first.
func WriteReports(w io.Writer, repo string, reports []PrivateReport) {
	width := textWidth()

	if len(reports) == 0 {
		fmt.Fprintf(w, "%s: no private vulnerability reports in triage\n", repo)

		return
	}

	fmt.Fprintf(w, "%s: %s in triage (most urgent first)\n", repo, plural(len(reports), "report"))

	for _, r := range reports {
		fmt.Fprintf(w, "\n  %s  %-8s score %d  %dd old  %s\n", r.GHSA, r.Severity, r.Score, r.AgeDays, clip(r.Summary, width-50))

		rep := "reporter unknown"
		if r.Reporter.Login != "" {
			rep = "reporter " + r.Reporter.Login
			if r.Reporter.Known {
				rep += fmt.Sprintf(", account %dd old, %d public repos", r.Reporter.AccountDays, r.Reporter.PublicRepos)
			}

			rep += fmt.Sprintf("; earlier reports here: %d published, %d closed, %d open",
				r.Reporter.PriorPublished, r.Reporter.PriorClosed, r.Reporter.PriorOpen)
		}

		fmt.Fprint(w, wrap(rep, "      ", width))

		if c := r.Claim; len(c.Files)+len(c.FilesMissing)+len(c.Symbols)+len(c.SymbolsMissing) > 0 {
			fmt.Fprint(w, wrap(fmt.Sprintf("names: found %s; not found %s (the checkout as it is, not the affected versions)",
				listOrNone(append(append([]string{}, c.Files...), c.Symbols...)),
				listOrNone(append(append([]string{}, c.FilesMissing...), c.SymbolsMissing...))), "      ", width))
		}

		if len(r.Shape) > 0 {
			fmt.Fprint(w, wrap("shape: "+strings.Join(r.Shape, ", "), "      ", width))
		}

		for _, o := range r.Overlap {
			fmt.Fprint(w, wrap("overlap: "+o, "      ", width))
		}

		if len(r.Reasons) > 0 {
			fmt.Fprint(w, wrap("because: "+strings.Join(r.Reasons, "; "), "      ", width))
		}
	}

	fmt.Fprintln(w)
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}

	return strings.Join(l, ", ")
}
