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

// Verdict is picard's call on a vulnerable package.
type Verdict string

const (
	// VerdictNotShipped: only dev/test dependencies pull it in - not in a production install.
	VerdictNotShipped Verdict = "not-shipped"
	// VerdictNotExecuted: shipped, but none of its code ran in the coverage run.
	VerdictNotExecuted Verdict = "not-executed"
	// VerdictImportOnly: shipped and imported in the coverage run, but none of its functions
	// were called - only import-time module code ran.
	VerdictImportOnly Verdict = "import-only"
	// VerdictReachable: shipped and imported or executed - the advisory needs a look.
	VerdictReachable Verdict = "reachable"
	// VerdictShipped: shipped, with no evidence either way about use.
	VerdictShipped Verdict = "shipped"
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
	// functions did (beyond import-time module code).
	Executed Use      `json:"executed"`
	Called   []string `json:"called,omitempty"`
	Verdict  Verdict  `json:"verdict"`
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

// Triage turns per-package advisories into findings, most severe first.
func Triage(advisories map[string][]Advisory, ev Evidence) []Finding {
	prod := ev.Lock.Closure(ev.Lock.Direct)
	all := ev.Lock.Closure(append(append([]string(nil), ev.Lock.Direct...), ev.Lock.DevDirect...))

	var findings []Finding

	for name, advs := range advisories {
		if len(advs) == 0 {
			continue
		}

		pkg := ev.Lock.Packages[name]
		f := Finding{Package: name, Advisories: advs, Severity: "unknown", Executed: UseUnknown}

		if pkg != nil {
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
			functionData := false

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
				functionData = functionData || use.FunctionData
			}

			sort.Strings(f.Called)

			// Without per-function data, loaded can't be told apart from called.
			if f.Executed == UseYes && !functionData {
				f.Called = []string{"(no per-function data in the coverage report)"}
			}
		}

		f.Verdict, f.Reason = judge(f)
		findings = append(findings, f)
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

	return findings
}

func verdictRank(v Verdict) int {
	switch v {
	case VerdictReachable:
		return 4
	case VerdictShipped:
		return 3
	case VerdictImportOnly:
		return 2
	case VerdictNotExecuted:
		return 1
	default:
		return 0
	}
}

func firstN(items []string, n int) []string {
	if len(items) <= n {
		return items
	}

	return items[:n]
}

func judge(f Finding) (Verdict, string) {
	via := strings.Join(f.Via, " → ")

	switch {
	case !f.Shipped:
		return VerdictNotShipped, "only pulled in by dev/test dependencies (" + via + "), so not in a production install"
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
