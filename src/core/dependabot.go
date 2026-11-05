package core

import (
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
)

// Proposed actions for a Dependabot alert.
const (
	ActionKeepOpen = "keep-open"
	ActionDismiss  = "dismiss"
	ActionSkip     = "skip" // picard has nothing to say about it
)

// AlertDecision is picard's proposal for one Dependabot alert.
type AlertDecision struct {
	Alert   Alert   `json:"alert"`
	Verdict Verdict `json:"verdict,omitempty"`
	Reason  string  `json:"reason"`
	Action  string  `json:"action"`
	// DismissReason is Dependabot's reason to dismiss with: not_used or tolerable_risk.
	DismissReason string `json:"dismiss_reason,omitempty"`
	// Judged: the verdict rests on judgement - a coverage run or a model's assessment -
	// rather than facts from the lock file alone. Only dismissed with --apply-judged.
	Judged bool `json:"judged"`
	// Applied: the alert was actually dismissed.
	Applied bool `json:"applied"`
}

// DependabotOptions configures processing a repository's alerts.
type DependabotOptions struct {
	// Repo is owner/name; Directory a checkout of it.
	Repo      string
	Directory string
	// State of alerts to process - "open" normally; "fixed" is useful to dry-run against
	// past alerts (with LockFile pointing at the old lock).
	State string
	// Scan is used for every manifest's scan (Directory/LockFile are set per manifest).
	Scan Options
	// LockFile, when set, overrides the lock file for every manifest - for replaying past
	// alerts against an old lock.
	LockFile string
}

// PlanDependabot proposes an action for each of a repository's alerts, scanning each lock
// file the alerts refer to.
func PlanDependabot(gh *GitHub, opts DependabotOptions) ([]AlertDecision, error) {
	state := opts.State
	if state == "" {
		state = "open"
	}

	alerts, err := gh.Alerts(opts.Repo, state)
	if err != nil {
		return nil, err
	}

	byLock := map[string][]Alert{}
	decisions := make([]AlertDecision, 0, len(alerts))

	for _, a := range alerts {
		lock := lockForManifest(opts.Directory, a.Dependency.ManifestPath)
		if opts.LockFile != "" {
			lock = opts.LockFile
		}

		if lock == "" {
			decisions = append(decisions, AlertDecision{
				Alert: a, Action: ActionSkip,
				Reason: "picard reads " + strings.Join(LockFiles, ", ") + "; this alert is on " + a.Dependency.ManifestPath,
			})

			continue
		}

		byLock[lock] = append(byLock[lock], a)
	}

	locks := make([]string, 0, len(byLock))
	for l := range byLock {
		locks = append(locks, l)
	}

	sort.Strings(locks)

	for _, lock := range locks {
		scan := opts.Scan
		scan.LockFile = lock
		scan.Directory = filepath.Join(opts.Directory, filepath.FromSlash(path.Dir(manifestOf(byLock[lock][0]))))

		report, err := Scan(scan)
		if err != nil {
			for _, a := range byLock[lock] {
				decisions = append(decisions, AlertDecision{Alert: a, Action: ActionSkip, Reason: "scan failed: " + err.Error()})
			}

			continue
		}

		for _, a := range byLock[lock] {
			decisions = append(decisions, decide(a, report))
		}
	}

	sort.Slice(decisions, func(i, j int) bool { return decisions[i].Alert.Number < decisions[j].Alert.Number })

	return decisions, nil
}

func manifestOf(a Alert) string {
	if a.Dependency.ManifestPath == "" {
		return "."
	}

	return a.Dependency.ManifestPath
}

// lockForManifest is the lock file picard reads for an alert's manifest: the manifest
// itself when it's a lock picard understands, else the lock beside it (an alert on
// pyproject.toml or package.json, when uv.lock / package-lock.json sits next to it).
func lockForManifest(root, manifest string) string {
	dir := path.Dir(manifest)

	switch path.Base(manifest) {
	case "uv.lock", "package-lock.json", "go.mod":
		return filepath.Join(root, filepath.FromSlash(manifest))
	case "go.sum":
		if lock := filepath.Join(root, filepath.FromSlash(dir), "go.mod"); Exists(lock) {
			return lock
		}
	case "pyproject.toml":
		if lock := filepath.Join(root, filepath.FromSlash(dir), "uv.lock"); Exists(lock) {
			return lock
		}
	case "package.json":
		if lock := filepath.Join(root, filepath.FromSlash(dir), "package-lock.json"); Exists(lock) {
			return lock
		}
	}

	return ""
}

// decide maps the alert onto picard's verdict for the same advisory and package.
func decide(a Alert, report *Report) AlertDecision {
	d := AlertDecision{Alert: a, Action: ActionKeepOpen}

	adv, ok := findAdvisory(a, report)
	if !ok {
		d.Action = ActionSkip
		d.Reason = "no matching advisory in picard's lookup of the locked version (already fixed in the lock, or not in OSV)"

		return d
	}

	d.Verdict, d.Reason = adv.Verdict, adv.Reason

	switch adv.Verdict {
	case VerdictNotShipped:
		d.Action, d.DismissReason = ActionDismiss, "not_used"
	case VerdictNotExecuted, VerdictImportOnly:
		// govulncheck's call graph is a fact; a coverage run is only as good as the run.
		calledNowhere := adv.GoReach != nil && adv.GoReach.Level == GoReachImported && adv.GoReach.Fact()
		d.Action, d.DismissReason, d.Judged = ActionDismiss, "not_used", !calledNowhere
	case VerdictNotApplicable:
		d.Action, d.DismissReason, d.Judged = ActionDismiss, "tolerable_risk", true
	}

	// Exploited, or likely to be: a person decides, whatever picard found.
	if note := adv.ExploitNote(); note != "" && d.Action == ActionDismiss {
		d.Action, d.DismissReason, d.Judged = ActionKeepOpen, "", false
		d.Reason = "not dismissed: " + note + ". Picard's verdict: " + d.Reason
	}

	return d
}

// findAdvisory is picard's advisory for an alert. A package locked at several versions has a
// finding per version, and Dependabot raises an alert per copy, so the copy is picked by the
// alert's vulnerable range; when several copies are in range (Dependabot reports one alert
// for them) the most serious verdict is taken, so nothing shipped is dismissed.
func findAdvisory(a Alert, report *Report) (Advisory, bool) {
	ghsa := a.SecurityAdvisory.GHSAID
	rng := a.SecurityVulnerability.VulnerableVersionRange

	var (
		best, any Advisory
		found     bool
		anyFound  bool
	)

	for _, f := range report.Findings {
		if !sameName(report.Ecosystem, f.Package, a.Dependency.Package.Name) {
			continue
		}

		for _, adv := range f.Advisories {
			if adv.ID != ghsa && !contains(adv.Aliases, ghsa) {
				continue
			}

			if !anyFound || verdictRank(adv.Verdict) > verdictRank(any.Verdict) {
				any, anyFound = adv, true
			}

			if rng != "" && !VersionInRange(f.Version, rng) {
				continue
			}

			if !found || verdictRank(adv.Verdict) > verdictRank(best.Verdict) {
				best, found = adv, true
			}
		}
	}

	if found {
		return best, true
	}

	return any, anyFound
}

// VersionInRange reports whether version satisfies a GitHub advisory range such as
// ">= 2.0.0, < 2.1.7" (comma-separated comparisons, all of which must hold). A range it
// can't read counts as satisfied.
func VersionInRange(version, rng string) bool {
	for _, part := range strings.Split(rng, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		bound := strings.TrimLeft(part, "<>=! ")
		op := strings.TrimSpace(strings.TrimSuffix(part, bound))
		cmp := CompareVersions(version, bound)

		var ok bool

		switch op {
		case "<":
			ok = cmp < 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case ">=":
			ok = cmp >= 0
		case "=", "==", "":
			ok = cmp == 0
		default:
			continue
		}

		if !ok {
			return false
		}
	}

	return true
}

func contains(items []string, want string) bool {
	for _, i := range items {
		if i == want {
			return true
		}
	}

	return false
}

// ApplyDecisions dismisses the alerts proposed for dismissal - only those resting on facts
// unless judged is set - and marks them Applied. Returns the first error, having still
// tried the rest.
func ApplyDecisions(gh *GitHub, repo string, decisions []AlertDecision, judged bool) error {
	var firstErr error

	for i := range decisions {
		d := &decisions[i]
		if d.Action != ActionDismiss || (d.Judged && !judged) {
			continue
		}

		comment := fmt.Sprintf("picard %s: %s", d.Verdict, d.Reason)

		if err := gh.Dismiss(repo, d.Alert.Number, d.DismissReason, comment); err != nil {
			if firstErr == nil {
				firstErr = err
			}

			continue
		}

		d.Applied = true
	}

	return firstErr
}

// alertGroup is the alerts of one package that get the same proposal - one table row.
type alertGroup struct {
	decisions []AlertDecision
	severity  string
}

func (g alertGroup) first() AlertDecision { return g.decisions[0] }

func (g alertGroup) numbers() []int {
	n := make([]int, len(g.decisions))
	for i, d := range g.decisions {
		n[i] = d.Alert.Number
	}

	return n
}

// action is the proposal as the table shows it.
func (g alertGroup) action() string {
	d := g.first()

	switch {
	case d.Action == ActionKeepOpen:
		return "keep open"
	case d.Action == ActionSkip:
		return "skip"
	case d.Applied:
		return "dismissed: " + d.DismissReason
	case d.Judged:
		return "dismiss: " + d.DismissReason + " *"
	default:
		return "dismiss: " + d.DismissReason
	}
}

// actionOrder puts what needs attention first: alerts to keep open, then dismissals that
// rest on facts, then on judgement, then the ones picard couldn't match.
func actionOrder(d AlertDecision) int {
	switch {
	case d.Action == ActionKeepOpen:
		return 0
	case d.Action == ActionDismiss && !d.Judged:
		return 1
	case d.Action == ActionDismiss:
		return 2
	default:
		return 3
	}
}

// groupDecisions groups alerts by package, manifest and proposal, most pressing first.
func groupDecisions(decisions []AlertDecision) []alertGroup {
	index := map[string]int{}

	var groups []alertGroup

	for _, d := range decisions {
		key := strings.Join([]string{d.Alert.Dependency.Package.Name, d.Alert.Dependency.ManifestPath,
			string(d.Verdict), d.Action, d.DismissReason, fmt.Sprint(d.Judged, d.Applied)}, "\x00")

		i, ok := index[key]
		if !ok {
			i = len(groups)
			index[key] = i
			groups = append(groups, alertGroup{})
		}

		g := &groups[i]
		g.decisions = append(g.decisions, d)

		if sev := strings.ToLower(d.Alert.SecurityAdvisory.Severity); severityRank[sev] > severityRank[g.severity] || g.severity == "" {
			g.severity = sev
		}
	}

	sort.SliceStable(groups, func(i, j int) bool {
		oi, oj := actionOrder(groups[i].first()), actionOrder(groups[j].first())
		if oi != oj {
			return oi < oj
		}

		si, sj := severityRank[groups[i].severity], severityRank[groups[j].severity]
		if si != sj {
			return si > sj
		}

		return groups[i].first().Alert.Dependency.Package.Name < groups[j].first().Alert.Dependency.Package.Name
	})

	return groups
}

// WriteDecisions writes the proposals: a summary line, one row per package and proposal,
// the reasons, and what --apply / --apply-judged would do next.
func WriteDecisions(w io.Writer, repo string, decisions []AlertDecision) error {
	if len(decisions) == 0 {
		_, err := fmt.Fprintf(w, "%s: no Dependabot alerts\n", repo)

		return err
	}

	groups := groupDecisions(decisions)
	width := textWidth()

	var (
		keep, fact, judged, skipped, done int
		manifests                         = map[string]bool{}
		packages                          = map[string]bool{}
	)

	for _, d := range decisions {
		manifests[d.Alert.Dependency.ManifestPath] = true
		packages[d.Alert.Dependency.Package.Name] = true

		switch {
		case d.Applied:
			done++
		case d.Action == ActionKeepOpen:
			keep++
		case d.Action == ActionSkip:
			skipped++
		case d.Judged:
			judged++
		default:
			fact++
		}
	}

	var parts []string

	for _, p := range []struct {
		n    int
		text string
	}{
		{done, "dismissed"}, {keep, "to keep open"}, {fact, "to dismiss"},
		{judged, "to dismiss on judgement"}, {skipped, "skipped"},
	} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.text))
		}
	}

	showManifest := len(manifests) > 1

	where := ""
	if !showManifest {
		for m := range manifests {
			where = " in " + m
		}
	}

	fmt.Fprintf(w, "%s: %s on %s%s - %s\n\n", repo, plural(len(decisions), "alert"),
		plural(len(packages), "package"), where, strings.Join(parts, ", "))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	header := "PACKAGE\tALERTS\tSEVERITY\tVERDICT\tACTION"
	if showManifest {
		header += "\tMANIFEST"
	}

	fmt.Fprintln(tw, header)

	for _, g := range groups {
		d := g.first()

		alerts := numberRanges(g.numbers())
		if len(g.decisions) > 2 {
			alerts += fmt.Sprintf(" (%d)", len(g.decisions))
		}

		verdict := string(d.Verdict)
		if verdict == "" {
			verdict = "-"
		}

		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", d.Alert.Dependency.Package.Name, alerts, g.severity, verdict, g.action())
		if showManifest {
			row += "\t" + d.Alert.Dependency.ManifestPath
		}

		fmt.Fprintln(tw, row)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	if judged > 0 {
		fmt.Fprintln(w, "\n* rests on judgement (a coverage run or a model's assessment) - dismissed only with --apply-judged")
	}

	for _, g := range groups {
		writeGroupReasons(w, g, width)
	}

	switch {
	case fact > 0 && judged > 0:
		fmt.Fprintf(w, "\nDry run. --apply dismisses %s; --apply-judged also the %d resting on judgement - read their reasons first.\n",
			plural(fact, "alert"), judged)
	case fact > 0:
		fmt.Fprintf(w, "\nDry run. --apply dismisses %s.\n", plural(fact, "alert"))
	case judged > 0:
		fmt.Fprintf(w, "\nDry run. --apply-judged dismisses %s - read their reasons first.\n", plural(judged, "alert"))
	}

	return nil
}

// writeGroupReasons writes one group's reasoning: once when every alert shares it, else per
// alert.
func writeGroupReasons(w io.Writer, g alertGroup, width int) {
	d := g.first()

	fmt.Fprintf(w, "\n%s %s - %s\n", d.Alert.Dependency.Package.Name, numberRanges(g.numbers()), g.action())

	same := true
	for _, other := range g.decisions[1:] {
		if other.Reason != d.Reason {
			same = false

			break
		}
	}

	if same {
		fmt.Fprint(w, wrap(d.Reason, "  ", width))
	}

	for _, a := range g.decisions {
		adv := a.Alert.SecurityAdvisory
		line := fmt.Sprintf("  #%d %s ", a.Alert.Number, adv.GHSAID)
		fmt.Fprintln(w, line+clip(adv.Summary, width-len(line)))

		if !same {
			fmt.Fprint(w, wrap(a.Reason, "      ", width))
		}
	}
}
