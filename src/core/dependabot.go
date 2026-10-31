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
				Reason: "picard reads uv.lock and package-lock.json; this alert is on " + a.Dependency.ManifestPath,
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
	case "uv.lock", "package-lock.json":
		return filepath.Join(root, filepath.FromSlash(manifest))
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
		d.Action, d.DismissReason, d.Judged = ActionDismiss, "not_used", true
	case VerdictNotApplicable:
		d.Action, d.DismissReason, d.Judged = ActionDismiss, "tolerable_risk", true
	}

	return d
}

func findAdvisory(a Alert, report *Report) (Advisory, bool) {
	ghsa := a.SecurityAdvisory.GHSAID

	for _, f := range report.Findings {
		if !sameName(report.Ecosystem, f.Package, a.Dependency.Package.Name) {
			continue
		}

		for _, adv := range f.Advisories {
			if adv.ID == ghsa || contains(adv.Aliases, ghsa) {
				return adv, true
			}
		}
	}

	return Advisory{}, false
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

// WriteDecisions writes the proposals as a table, then each reason.
func WriteDecisions(w io.Writer, repo string, decisions []AlertDecision) error {
	counts := map[string]int{}
	for _, d := range decisions {
		key := d.Action
		if d.Action == ActionDismiss && d.Judged {
			key += " (judged)"
		}

		counts[key]++
	}

	fmt.Fprintf(w, "%s: %d alerts - %d keep open, %d dismiss, %d dismiss on judgement, %d skipped\n\n",
		repo, len(decisions), counts[ActionKeepOpen], counts[ActionDismiss], counts[ActionDismiss+" (judged)"], counts[ActionSkip])

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ALERT\tPACKAGE\tSEVERITY\tVERDICT\tACTION\tMANIFEST")

	for _, d := range decisions {
		action := d.Action
		if d.Action == ActionDismiss {
			action += " (" + d.DismissReason + ")"
			if d.Judged {
				action += " *"
			}

			if d.Applied {
				action += " done"
			}
		}

		verdict := string(d.Verdict)
		if verdict == "" {
			verdict = "-"
		}

		fmt.Fprintf(tw, "#%d\t%s\t%s\t%s\t%s\t%s\n", d.Alert.Number, d.Alert.Dependency.Package.Name,
			d.Alert.SecurityAdvisory.Severity, verdict, action, d.Alert.Dependency.ManifestPath)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(w, "\n* rests on judgement (coverage or a model's assessment) - dismissed only with --apply-judged")

	for _, d := range decisions {
		fmt.Fprintf(w, "\n#%d %s (%s): %s\n", d.Alert.Number, d.Alert.SecurityAdvisory.GHSAID,
			strings.TrimSpace(d.Alert.SecurityAdvisory.Summary), d.Reason)
	}

	return nil
}
