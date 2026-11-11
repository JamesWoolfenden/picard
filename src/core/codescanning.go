package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// OpenSSF Scorecard raises a code-scanning alert (rule VulnerabilitiesID) for any advisory
// in the lock, shipped or not. These are related to picard's verdict for the same advisory,
// and dismissed through the code-scanning API when that verdict says the code isn't reached.

const (
	scorecardTool = "Scorecard"
	scorecardRule = "VulnerabilitiesID"
)

// CodeScanningAlert is one code-scanning alert.
type CodeScanningAlert struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
	Tool    struct {
		Name string `json:"name"`
	} `json:"tool"`
	Rule struct {
		ID                    string `json:"id"`
		SecuritySeverityLevel string `json:"security_severity_level"`
		Severity              string `json:"severity"`
	} `json:"rule"`
	MostRecentInstance struct {
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path string `json:"path"`
		} `json:"location"`
	} `json:"most_recent_instance"`
}

// Severity is the alert's severity as GitHub shows it.
func (a CodeScanningAlert) Severity() string {
	if a.Rule.SecuritySeverityLevel != "" {
		return a.Rule.SecuritySeverityLevel
	}

	return a.Rule.Severity
}

// ScorecardAlerts lists the open Scorecard "Vulnerabilities" code-scanning alerts.
func (g *GitHub) ScorecardAlerts(repo string) ([]CodeScanningAlert, error) {
	all, err := getAll[CodeScanningAlert](g,
		fmt.Sprintf("%s/repos/%s/code-scanning/alerts?state=open&tool_name=%s&per_page=100", g.BaseURL, repo, scorecardTool))
	if err != nil {
		return nil, err
	}

	var alerts []CodeScanningAlert

	for _, a := range all {
		if a.Tool.Name == scorecardTool && a.Rule.ID == scorecardRule {
			alerts = append(alerts, a)
		}
	}

	return alerts, nil
}

// DismissCodeScanning closes a code-scanning alert with one of its reasons ("false positive",
// "won't fix", "used in tests") and a comment of at most 280 characters.
func (g *GitHub) DismissCodeScanning(repo string, number int, reason, comment string) error {
	if len(comment) > 280 {
		comment = comment[:277] + "..."
	}

	body, err := json.Marshal(map[string]string{
		"state": "dismissed", "dismissed_reason": reason, "dismissed_comment": comment,
	})
	if err != nil {
		return err
	}

	resp, err := g.do(http.MethodPatch, fmt.Sprintf("%s/repos/%s/code-scanning/alerts/%d", g.BaseURL, repo, number), body)
	if err != nil {
		return err
	}

	resp.Body.Close()

	return nil
}

var advisoryIDRe = regexp.MustCompile(`\b(GO-\d{4}-\d+|GHSA(?:-[a-z0-9]{4}){3}|CVE-\d{4}-\d{4,}|PYSEC-\d{4}-\d+)\b`)

// advisoryIDs are the distinct advisory ids named in a Scorecard alert's message
// ("Project is vulnerable to: GO-2026-5932").
func advisoryIDs(message string) []string {
	var ids []string

	seen := map[string]bool{}

	for _, id := range advisoryIDRe.FindAllString(message, -1) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	return ids
}

// ScorecardAdvisory is picard's finding for one advisory a Scorecard alert names.
type ScorecardAdvisory struct {
	ID      string `json:"id"`
	Package string `json:"package,omitempty"`
	Version string `json:"version,omitempty"`
	// Fixed is the lowest version that fixes it, when there is one.
	Fixed         string  `json:"fixed,omitempty"`
	Verdict       Verdict `json:"verdict,omitempty"`
	Reason        string  `json:"reason"`
	Action        string  `json:"action"`
	DismissReason string  `json:"dismiss_reason,omitempty"`
	Judged        bool    `json:"judged"`
}

// ScorecardDecision is picard's proposal for one Scorecard alert: dismiss it only when every
// advisory it names is one picard would dismiss; otherwise it stays open, and upgrading is
// the way to clear it.
type ScorecardDecision struct {
	Alert      CodeScanningAlert   `json:"alert"`
	Advisories []ScorecardAdvisory `json:"advisories"`
	Action     string              `json:"action"`
	Reason     string              `json:"reason"`
	// DismissReason is the code-scanning reason to dismiss with.
	DismissReason string `json:"dismiss_reason,omitempty"`
	Judged        bool   `json:"judged"`
	Applied       bool   `json:"applied"`
}

// ScorecardPlan is picard's reading of a repository's Scorecard alerts.
type ScorecardPlan struct {
	Decisions []ScorecardDecision `json:"decisions"`
	// Note: why the alerts couldn't be read, when the token lacks access.
	Note string `json:"note,omitempty"`
}

// PlanScorecard proposes an action for each open Scorecard "Vulnerabilities" alert, from the
// verdicts of a scan of the lock the alert points at (else the checkout's own lock).
func PlanScorecard(gh *GitHub, opts DependabotOptions) (*ScorecardPlan, error) {
	plan := &ScorecardPlan{}

	alerts, err := gh.ScorecardAlerts(opts.Repo)

	var httpErr *HTTPError

	switch {
	case errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound:
		return plan, nil // code scanning isn't enabled
	case errors.As(err, &httpErr) && httpErr.Status == http.StatusForbidden:
		plan.Note = "couldn't read code-scanning alerts (the token needs the security_events scope): " + httpErr.Message

		return plan, nil
	case err != nil:
		return nil, err
	}

	type scanned struct {
		report *Report
		err    error
	}

	scans := map[string]scanned{}

	for _, a := range alerts {
		lock := ""
		if p := a.MostRecentInstance.Location.Path; p != "" {
			lock = lockForManifest(opts.Directory, p)
		}

		if opts.LockFile != "" {
			lock = opts.LockFile
		}

		s, ok := scans[lock]
		if !ok {
			scan := opts.Scan
			scan.LockFile, scan.Directory = lock, opts.Directory

			if lock != "" {
				scan.Directory = filepath.Dir(lock)
			}

			s.report, s.err = Scan(scan)
			scans[lock] = s
		}

		plan.Decisions = append(plan.Decisions, decideScorecard(a, s.report, s.err))
	}

	sort.Slice(plan.Decisions, func(i, j int) bool { return plan.Decisions[i].Alert.Number < plan.Decisions[j].Alert.Number })

	return plan, nil
}

// decideScorecard maps each advisory a Scorecard alert names onto picard's verdict for it.
func decideScorecard(a CodeScanningAlert, report *Report, scanErr error) ScorecardDecision {
	d := ScorecardDecision{Alert: a, Action: ActionSkip}

	ids := advisoryIDs(a.MostRecentInstance.Message.Text)

	switch {
	case len(ids) == 0:
		d.Reason = "no advisory id in the alert's message"

		return d
	case scanErr != nil:
		d.Reason = "scan failed: " + scanErr.Error()

		return d
	}

	for _, id := range ids {
		d.Advisories = append(d.Advisories, scorecardAdvisory(id, report))
	}

	return d.conclude()
}

// scorecardAdvisory is picard's finding for an advisory id, taking the most serious verdict
// when the package is locked at several versions.
func scorecardAdvisory(id string, report *Report) ScorecardAdvisory {
	var (
		best  Advisory
		pkg   string
		ver   string
		found bool
	)

	for _, f := range report.Findings {
		for _, adv := range f.Advisories {
			if adv.ID != id && !contains(adv.Aliases, id) {
				continue
			}

			if !found || verdictRank(adv.Verdict) > verdictRank(best.Verdict) {
				best, pkg, ver, found = adv, f.Package, f.Version, true
			}
		}
	}

	out := ScorecardAdvisory{ID: id, Action: ActionSkip}
	if !found {
		out.Reason = "not in picard's lookup of the locked versions (already fixed in the lock, or not in OSV)"

		return out
	}

	d := AlertDecision{Action: ActionKeepOpen}
	d.propose(best)

	out.Package, out.Version, out.Fixed = pkg, ver, best.Fixed
	out.Verdict, out.Reason, out.Action = d.Verdict, d.Reason, d.Action
	out.DismissReason, out.Judged = d.DismissReason, d.Judged

	return out
}

// conclude sets the alert's action from its advisories'. All must be dismissible; any one
// that isn't - shipped, exploited, or unknown to picard - keeps the alert open.
func (d ScorecardDecision) conclude() ScorecardDecision {
	d.Action = ActionDismiss
	reasons := map[string]bool{}

	var keep []string

	for _, adv := range d.Advisories {
		switch adv.Action {
		case ActionDismiss:
			d.Judged = d.Judged || adv.Judged
			reasons[adv.DismissReason] = true
		case ActionKeepOpen:
			d.Action = ActionKeepOpen

			how := "upgrade"
			if adv.Fixed != "" {
				how = "upgrade " + adv.Package + " to " + adv.Fixed
			}

			keep = append(keep, adv.ID+" ("+how+")")
		default:
			d.Action = ActionKeepOpen

			keep = append(keep, adv.ID+" (picard has no finding)")
		}
	}

	if d.Action == ActionKeepOpen {
		d.Judged = false
		d.Reason = "still reached or undecided: " + strings.Join(keep, ", ")

		return d
	}

	// Scorecard says the project is vulnerable; picard says the vulnerable code isn't in it.
	d.DismissReason = "false positive"
	if len(reasons) != 1 || !reasons["not_used"] {
		d.DismissReason = "won't fix"
	}

	parts := make([]string, len(d.Advisories))
	for i, adv := range d.Advisories {
		parts[i] = fmt.Sprintf("%s %s: %s", adv.ID, adv.Verdict, adv.Reason)
	}

	d.Reason = strings.Join(parts, "; ")

	return d
}

// ApplyScorecard dismisses the alerts proposed for dismissal - only those resting on facts
// unless judged is set. Returns the first error, having still tried the rest.
func ApplyScorecard(gh *GitHub, repo string, plan *ScorecardPlan, judged bool) error {
	var firstErr error

	for i := range plan.Decisions {
		d := &plan.Decisions[i]
		if d.Action != ActionDismiss || (d.Judged && !judged) {
			continue
		}

		if err := gh.DismissCodeScanning(repo, d.Alert.Number, d.DismissReason, "picard: "+d.Reason); err != nil {
			if firstErr == nil {
				firstErr = err
			}

			continue
		}

		d.Applied = true
	}

	return firstErr
}

// Dismissable is how many alerts --apply would dismiss, and how many more --apply-judged would.
func (p *ScorecardPlan) Dismissable() (fact, judged int) {
	for _, d := range p.Decisions {
		switch {
		case d.Applied || d.Action != ActionDismiss:
		case d.Judged:
			judged++
		default:
			fact++
		}
	}

	return fact, judged
}

// WriteScorecard writes each Scorecard alert beside picard's verdict and proposed action.
func WriteScorecard(w io.Writer, repo string, p *ScorecardPlan) {
	if p.Note != "" {
		fmt.Fprintf(w, "\n%s: Scorecard alerts not read - %s\n", repo, p.Note)
	}

	if len(p.Decisions) == 0 {
		return
	}

	width := textWidth()

	fmt.Fprintf(w, "\n%s: %s from Scorecard's Vulnerabilities check\n", repo, plural(len(p.Decisions), "code-scanning alert"))

	for _, d := range p.Decisions {
		action := d.Action

		switch {
		case d.Applied:
			action = "dismissed: " + d.DismissReason
		case d.Action == ActionDismiss && d.Judged:
			action = "dismiss: " + d.DismissReason + " *"
		case d.Action == ActionDismiss:
			action = "dismiss: " + d.DismissReason
		}

		fmt.Fprintf(w, "\n  #%d %s - %s\n", d.Alert.Number, d.Alert.Severity(), action)
		fmt.Fprint(w, wrap(d.Reason, "      ", width))
	}

	fact, judged := p.Dismissable()

	switch {
	case fact > 0 && judged > 0:
		fmt.Fprintf(w, "\nDry run. --apply dismisses %s; --apply-judged also the %d resting on judgement.\n", plural(fact, "alert"), judged)
	case fact > 0:
		fmt.Fprintf(w, "\nDry run. --apply dismisses %s.\n", plural(fact, "alert"))
	case judged > 0:
		fmt.Fprintf(w, "\nDry run. --apply-judged dismisses %s - read their reasons first.\n", plural(judged, "alert"))
	}
}
