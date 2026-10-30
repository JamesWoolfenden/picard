package core

import (
	"fmt"
	"sort"
	"strings"
)

// Use is how much evidence there is that a package is actually used.
type Use string

const (
	// UseUnknown: no evidence collected (no coverage report given).
	UseUnknown Use = "unknown"
	UseYes     Use = "yes"
	UseNo      Use = "no"
)

// Verdict is picard's call on an advisory, or on a package (its most serious advisory's).
type Verdict string

const (
	// VerdictNotShipped: only dev/test dependencies pull it in - not in a production install.
	VerdictNotShipped Verdict = "not-shipped"
	// VerdictNotApplicable: the advisory's preconditions don't hold for this deployment
	// (e.g. needs another local user, or a different OS).
	VerdictNotApplicable Verdict = "not-applicable"
	// VerdictNotExecuted: shipped, but the vulnerable code didn't run in the coverage run.
	VerdictNotExecuted Verdict = "not-executed"
	// VerdictImportOnly: shipped and imported in the coverage run, but none of its functions
	// were called - only import-time module code ran.
	VerdictImportOnly Verdict = "import-only"
	// VerdictShipped: shipped, with no evidence either way about use.
	VerdictShipped Verdict = "shipped"
	// VerdictReachable: the vulnerable code or data is in use - needs the fix.
	VerdictReachable Verdict = "reachable"
)

// Finding is one vulnerable package - every advisory against it is fixed by the same
// upgrade, so this is one action, however many alerts it accounts for.
type Finding struct {
	Package    string     `json:"package"`
	Version    string     `json:"version"`
	FixVersion string     `json:"fix_version,omitempty"`
	Severity   string     `json:"severity"`
	Advisories []Advisory `json:"advisories"`
	Shipped    bool       `json:"shipped"`
	// Via is the dependency chain that pulls the package into the project, from one of the
	// project's own dependencies down to the package itself.
	Via []string `json:"via"`
	// DirectImport: the project's own production code imports it by name.
	DirectImport bool `json:"direct_import"`
	// Executed: whether any of its code ran in the coverage run; Called, which of its
	// functions did (beyond import-time module code) - only known when FunctionData.
	Executed     Use      `json:"executed"`
	Called       []string `json:"called,omitempty"`
	FunctionData bool     `json:"function_data"`
	// Verdict is the most serious of its advisories' verdicts.
	Verdict Verdict `json:"verdict"`
	// Reason explains the verdict in a sentence.
	Reason string `json:"reason"`
}

// Evidence is everything collected about the project, used to judge each finding.
type Evidence struct {
	Lock     *Lock
	Imported map[string]bool // packages the project's production code imports
	// Executed: per top-level module, what the coverage run shows - nil when no coverage
	// report was given.
	Executed map[string]*ModuleUse
	// Owners maps top-level module -> package (from the installed environment).
	Owners map[string]string
}

var severityRank = map[string]int{"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}

// Triage turns per-package advisories into findings, most serious first. Any assessments
// already attached to the advisories are taken into account (see Rejudge).
func Triage(advisories map[string][]Advisory, ev Evidence) []Finding {
	prod := ev.Lock.Closure(ev.Lock.Direct)
	all := ev.Lock.Closure(append(append([]string(nil), ev.Lock.Direct...), ev.Lock.DevDirect...))

	var findings []Finding

	for name, advs := range advisories {
		if len(advs) == 0 {
			continue
		}

		f := Finding{Package: name, Advisories: advs, Severity: "unknown", Executed: UseUnknown}

		if pkg := ev.Lock.Packages[name]; pkg != nil {
			f.Version = pkg.Version
		}

		for _, a := range advs {
			if severityRank[a.Severity] > severityRank[f.Severity] {
				f.Severity = a.Severity
			}

			if a.Fixed != "" && (f.FixVersion == "" || CompareVersions(a.Fixed, f.FixVersion) > 0) {
				f.FixVersion = a.Fixed
			}
		}

		if path, ok := prod[name]; ok {
			f.Shipped = true
			f.Via = path
		} else {
			f.Via = all[name]
		}

		f.DirectImport = ev.Imported[name]

		if ev.Executed != nil {
			f.Executed = UseNo

			for module, use := range ev.Executed {
				owner, known := ev.Owners[module]
				if !known {
					owner = NormalizeName(module)
				}

				if owner != name || !use.Loaded {
					continue
				}

				f.Executed = UseYes
				f.Called = append(f.Called, use.Called...)
				f.FunctionData = f.FunctionData || use.FunctionData
			}

			sort.Strings(f.Called)
		}

		findings = append(findings, f)
	}

	Rejudge(findings)

	return findings
}

// Rejudge sets every advisory's verdict and each package's overall verdict (its most
// serious advisory), then re-sorts - run again after attaching assessments.
func Rejudge(findings []Finding) {
	for i := range findings {
		f := &findings[i]
		pkgVerdict, pkgReason := judgePackage(*f)

		best := -1

		for j := range f.Advisories {
			a := &f.Advisories[j]
			a.Verdict, a.Reason = judgeAdvisory(*f, *a, pkgVerdict, pkgReason)

			if best < 0 || verdictRank(a.Verdict) > verdictRank(f.Advisories[best].Verdict) {
				best = j
			}
		}

		f.Verdict, f.Reason = f.Advisories[best].Verdict, f.Advisories[best].Reason
	}

	sort.Slice(findings, func(i, j int) bool {
		ri, rj := verdictRank(findings[i].Verdict), verdictRank(findings[j].Verdict)
		if ri != rj {
			return ri > rj
		}

		si, sj := severityRank[findings[i].Severity], severityRank[findings[j].Severity]
		if si != sj {
			return si > sj
		}

		return findings[i].Package < findings[j].Package
	})
}

func verdictRank(v Verdict) int {
	return map[Verdict]int{
		VerdictReachable:     5,
		VerdictShipped:       4,
		VerdictImportOnly:    3,
		VerdictNotExecuted:   2,
		VerdictNotApplicable: 1,
	}[v]
}

func firstN(items []string, n int) []string {
	if len(items) <= n {
		return items
	}

	return items[:n]
}

// judgePackage is the verdict from package-level evidence alone - what every advisory gets
// when there's no assessment to say more.
func judgePackage(f Finding) (Verdict, string) {
	via := strings.Join(f.Via, " → ")

	switch {
	case !f.Shipped:
		return VerdictNotShipped, "only pulled in by dev/test dependencies (" + via + "), so not in a production install"
	case f.Executed == UseYes && !f.FunctionData:
		return VerdictReachable, "its code ran in the coverage run (no per-function data to narrow it down), loaded via " + via
	case f.Executed == UseYes && len(f.Called) == 0:
		return VerdictImportOnly, "shipped via " + via + " and imported in the coverage run, but none of its functions were called"
	case f.Executed == UseYes:
		return VerdictReachable, fmt.Sprintf("%d of its functions ran in the coverage run (e.g. %s), loaded via %s",
			len(f.Called), strings.Join(firstN(f.Called, 3), ", "), via)
	case f.Executed == UseNo:
		return VerdictNotExecuted, "shipped via " + via + ", but none of its code ran in the coverage run"
	case f.DirectImport:
		return VerdictReachable, "imported by the project's own code"
	default:
		return VerdictShipped, "shipped via " + via + " - give a coverage report to see whether it runs"
	}
}

// judgeAdvisory narrows the package verdict using the advisory's assessment, when there is
// one: preconditions that don't hold, data every user of the package consumes, or the
// specific affected functions checked against what actually ran.
func judgeAdvisory(f Finding, a Advisory, pkgVerdict Verdict, pkgReason string) (Verdict, string) {
	as := a.Assessment
	if !f.Shipped || as == nil {
		return pkgVerdict, pkgReason
	}

	switch {
	case as.Applies == "no":
		return VerdictNotApplicable, "preconditions don't hold here: " + as.Reasoning
	case as.Affects == "data":
		return VerdictReachable, "the problem is in data the package ships, used wherever the package is: " + as.Reasoning
	case as.Affects == "install":
		return VerdictShipped, "only matters while installing or building packages, not at runtime: " + as.Reasoning
	case as.Affects == "code" && len(as.Symbols) > 0 && f.Executed == UseNo:
		return VerdictNotExecuted, "none of the package's code ran in the coverage run (affected: " + strings.Join(as.Symbols, ", ") + ")"
	case as.Affects == "code" && len(as.Symbols) > 0 && f.Executed == UseYes && f.FunctionData:
		if matches := MatchSymbols(f.Called, as.Symbols); len(matches) > 0 {
			return VerdictReachable, "affected code ran in the coverage run: " + strings.Join(firstN(matches, 3), ", ")
		}

		return VerdictNotExecuted, "none of the affected code (" + strings.Join(as.Symbols, ", ") + ") ran in the coverage run"
	default:
		return pkgVerdict, pkgReason
	}
}
