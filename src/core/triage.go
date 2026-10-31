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
	// Bundler is the project's bundler, if it has one. Bundled: only dev dependencies
	// declare the package, but the code's imports reach it, so the bundle carries it and it
	// counts as shipped (Via is then the import chain).
	Bundler string `json:"bundler,omitempty"`
	Bundled bool   `json:"bundled,omitempty"`
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
	// GoReach is govulncheck's findings by Go vulnerability id - nil when it didn't run.
	GoReach map[string]*GoReach
}

var severityRank = map[string]int{"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}

// Triage turns per-package advisories into findings, most serious first. Any assessments
// already attached to the advisories are taken into account (see Rejudge).
func Triage(advisories map[string][]Advisory, ev Evidence) []Finding {
	prod := ev.Lock.Closure(ev.Lock.Direct)
	all := ev.Lock.Closure(append(append([]string(nil), ev.Lock.Direct...), ev.Lock.DevDirect...))

	// A bundler copies in what the code's imports reach, however it was declared.
	var bundled map[string][]string
	if ev.Lock.Bundler != "" {
		imported := make([]string, 0, len(ev.Imported))
		for name := range ev.Imported {
			imported = append(imported, name)
		}

		sort.Strings(imported)
		bundled = ev.Lock.Closure(imported)
	}

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

			f.Bundler = ev.Lock.Bundler

			if path, ok := bundled[name]; ok {
				f.Shipped = true
				f.Bundled = true
				f.Via = path
			}
		}

		f.DirectImport = ev.Imported[name]

		if ev.Lock.Compiled != nil {
			for j := range f.Advisories {
				a := &f.Advisories[j]
				if len(a.AffectedPackages) == 0 {
					continue
				}

				a.CompiledKnown, a.Compiled = true, nil

				for _, p := range a.AffectedPackages {
					if ev.Lock.Compiled[p] {
						a.Compiled = append(a.Compiled, p)
					}
				}
			}
		}

		if ev.GoReach != nil {
			for j := range f.Advisories {
				f.Advisories[j].GoReach = goReachFor(f.Advisories[j], ev.GoReach)
			}
		}

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

// compactTrace is a call path short enough for a reason: the project's own function, then
// the last two calls into the vulnerable code (the whole path is in the JSON).
func compactTrace(trace []string) string {
	if len(trace) > 4 {
		trace = append([]string{trace[0], "…"}, trace[len(trace)-2:]...)
	}

	return strings.Join(trace, " → ")
}

func withoutCgo(r *GoReach) string {
	if r.Fact() {
		return ""
	}

	return "; cgo files unseen on " + strings.Join(r.WithoutCgo, ", ") + " - no C compiler for them"
}

func firstNonEmptyList(lists ...[]string) []string {
	for _, l := range lists {
		if len(l) > 0 {
			return l
		}
	}

	return nil
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
	case !f.Shipped && f.Bundler != "":
		return VerdictNotShipped, "only pulled in by dev/test dependencies (" + via + "), and " + f.Bundler +
			" bundles only what the code imports, none of which pulls it in"
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
	case f.Bundled:
		return VerdictShipped, "declared only as a dev dependency, but " + f.Bundler +
			" bundles what the code imports, which reaches it (" + via + ")"
	default:
		return VerdictShipped, "shipped via " + via + " - give a coverage report to see whether it runs"
	}
}

// judgeAdvisory narrows the package verdict using the advisory's assessment, when there is
// one: preconditions that don't hold, data every user of the package consumes, or the
// specific affected functions checked against what actually ran.
func judgeAdvisory(f Finding, a Advisory, pkgVerdict Verdict, pkgReason string) (Verdict, string) {
	// Which of the vulnerable packages the build compiles in is a fact, so it comes first.
	if f.Shipped && a.CompiledKnown && len(a.Compiled) == 0 {
		return VerdictNotShipped, "only " + strings.Join(firstN(a.AffectedPackages, 3), ", ") +
			" affected, and the build compiles none of them in (go list -deps, across platforms)"
	}

	// So is govulncheck's call graph - except that an assessment can still find a called
	// function's preconditions don't hold here.
	if f.Shipped && a.GoReach != nil {
		switch a.GoReach.Level {
		case GoReachCalled:
			if a.Assessment == nil || a.Assessment.Applies != "no" {
				return VerdictReachable, "the build calls vulnerable code (govulncheck, " + a.GoReach.Platform + "): " +
					compactTrace(a.GoReach.Trace)
			}
		case GoReachImported:
			return VerdictNotExecuted, "the build compiles in " + strings.Join(firstN(firstNonEmptyList(a.Compiled, a.AffectedPackages), 3), ", ") +
				", but nothing calls its vulnerable functions (govulncheck's call graph, across platforms" + withoutCgo(a.GoReach) + ")"
		case GoReachRequired:
			return VerdictNotShipped, "the build requires the module but imports none of the affected packages (govulncheck, across platforms" +
				withoutCgo(a.GoReach) + ")"
		}
	}

	if f.Shipped && a.CompiledKnown && a.Assessment == nil && pkgVerdict != VerdictReachable {
		why := "whether the vulnerable functions are called needs govulncheck, which couldn't run"
		if a.GoReach != nil {
			why = "govulncheck doesn't report it for this build (not in the Go vulnerability database, or not for this version), " +
				"so whether the vulnerable functions are called is unknown"
		}

		return VerdictShipped, "the build compiles in the affected " + strings.Join(firstN(a.Compiled, 3), ", ") + " - " + why
	}

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
