package core

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// Target is the platform a production install runs on, for picking which wheel - and so
// which size and whether it's native code - applies.
type Target struct {
	OS     string // linux, windows, macos
	Arch   string // x86_64, arm64
	Python string // "3.12"
}

// SurfacePackage is one package a dependency alone brings in.
type SurfacePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Native: the wheel for the target is platform-specific - compiled code - rather than
	// pure Python. Unknown when no wheel matches (built from source).
	Native string `json:"native"` // "yes", "no", "unknown"
	// Size of the target's wheel in bytes, 0 when the index didn't report one.
	Size int64 `json:"size"`
	// Advisories is every advisory ever published against the package, at any version.
	Advisories int `json:"advisories"`
}

// Surface is what one of the project's direct dependencies costs - everything that would
// leave the production install if it were removed.
type Surface struct {
	// Dependency is the direct dependency; Also are other direct dependencies only it
	// needs (e.g. torch, listed directly but otherwise only there for
	// sentence-transformers), which would go with it.
	Dependency string   `json:"dependency"`
	Also       []string `json:"also,omitempty"`
	// Packages are everything only this dependency (and Also) brings in, itself included.
	Packages []SurfacePackage `json:"packages"`
	// SharedWith lists direct dependencies that also need this one, so removing it alone
	// removes nothing.
	SharedWith []string `json:"shared_with,omitempty"`
	// UsedNames are the names the project's code imports from it; Called, its functions
	// that ran in the coverage run (nil without coverage).
	UsedNames []string `json:"used_names"`
	Called    []string `json:"called,omitempty"`
	// Command: the project runs one of its console commands (found in the Dockerfile,
	// Makefile and the like) - used from the command line rather than imported.
	Command bool `json:"command"`
}

// Undeclared is a package the project's own code imports without depending on it
// directly - it works only because something else happens to pull it in.
type Undeclared struct {
	Module  string   `json:"module"`
	Package string   `json:"package"`
	Via     []string `json:"via,omitempty"`
	// DevOnly: nothing in the production install provides it - only dev/test dependencies
	// do, so it would fail in production.
	DevOnly bool `json:"dev_only"`
}

// Native counts the packages with compiled code.
func (s Surface) Native() int {
	n := 0

	for _, p := range s.Packages {
		if p.Native == "yes" {
			n++
		}
	}

	return n
}

// Size totals the known wheel sizes; complete is false if any were unknown.
func (s Surface) Size() (total int64, complete bool) {
	complete = true

	for _, p := range s.Packages {
		if p.Size == 0 {
			complete = false
		}

		total += p.Size
	}

	return total, complete
}

// AdvisoryHistory totals the packages' past advisories.
func (s Surface) AdvisoryHistory() int {
	n := 0
	for _, p := range s.Packages {
		n += p.Advisories
	}

	return n
}

// SurfaceReport ranks the project's direct dependencies by what they bring in.
type SurfaceReport struct {
	Project    string       `json:"project"`
	Target     Target       `json:"target"`
	Total      int          `json:"total_packages"`
	Entries    []Surface    `json:"dependencies"`
	Undeclared []Undeclared `json:"undeclared,omitempty"`
}

// SurfaceEvidence is what AnalyzeSurface works from; everything but Lock may be nil.
type SurfaceEvidence struct {
	Lock     *Lock
	Imports  *Imports
	Owners   map[string]string // module -> package
	Commands map[string]bool   // packages whose console commands the project runs
	Executed map[string]*ModuleUse
	History  map[string]int // package -> past advisory count
}

// AnalyzeSurface works out, for each direct dependency, what removing it would remove.
func AnalyzeSurface(ev SurfaceEvidence, target Target) SurfaceReport {
	lock, imports, owners, executed, history := ev.Lock, ev.Imports, ev.Owners, ev.Executed, ev.History
	everything := lock.Closure(lock.Direct)
	report := SurfaceReport{Project: lock.Project, Target: target, Total: len(everything)}
	report.Undeclared = undeclaredImports(lock, imports, owners)

	for _, dep := range lock.Direct {
		group := []string{dep}

		// Other direct dependencies only this one needs go with it.
		for _, other := range lock.Direct {
			if other == dep {
				continue
			}

			if _, needed := lock.Closure([]string{dep})[other]; !needed {
				continue
			}

			if _, elsewhere := lock.Closure(without(lock.Direct, dep, other))[other]; !elsewhere {
				group = append(group, other)
			}
		}

		remaining := lock.Closure(without(lock.Direct, group...))

		s := Surface{Dependency: dep, Also: group[1:]}

		for name := range everything {
			if _, stays := remaining[name]; stays {
				continue
			}

			s.Packages = append(s.Packages, describePackage(lock.Packages[name], name, target, history))
		}

		sort.Slice(s.Packages, func(i, j int) bool { return s.Packages[i].Name < s.Packages[j].Name })

		if len(s.Packages) == 0 {
			for _, other := range lock.Direct {
				if _, needs := lock.Closure([]string{other})[dep]; needs && other != dep {
					s.SharedWith = append(s.SharedWith, other)
				}
			}
		}

		inGroup := map[string]bool{}
		for _, p := range s.Packages {
			inGroup[p.Name] = true
		}

		for _, g := range group {
			inGroup[g] = true
		}

		s.UsedNames = namesFrom(imports, owners, inGroup)

		for g := range inGroup {
			s.Command = s.Command || ev.Commands[g]
		}

		if executed != nil {
			s.Called = []string{}

			for module, use := range executed {
				if inGroup[ownerOf(module, owners)] {
					s.Called = append(s.Called, use.Called...)
				}
			}

			sort.Strings(s.Called)
		}

		report.Entries = append(report.Entries, s)
	}

	sort.Slice(report.Entries, func(i, j int) bool {
		a, b := report.Entries[i], report.Entries[j]
		if len(a.Packages) != len(b.Packages) {
			return len(a.Packages) > len(b.Packages)
		}

		return a.Dependency < b.Dependency
	})

	return report
}

// undeclaredImports finds modules the project's production code imports from a locked
// package it doesn't list as a direct dependency.
func undeclaredImports(lock *Lock, imports *Imports, owners map[string]string) []Undeclared {
	if imports == nil {
		return nil
	}

	direct := map[string]bool{}
	for _, d := range lock.Direct {
		direct[d] = true
	}

	prod := lock.Closure(lock.Direct)
	dev := lock.Closure(lock.DevDirect)

	var found []Undeclared

	for module := range imports.Production {
		pkg := ownerOf(module, owners)
		if direct[pkg] || pkg == lock.Project {
			continue
		}

		if via, ok := prod[pkg]; ok {
			found = append(found, Undeclared{Module: module, Package: pkg, Via: via})
		} else if via, ok := dev[pkg]; ok {
			found = append(found, Undeclared{Module: module, Package: pkg, Via: via, DevOnly: true})
		}
	}

	sort.Slice(found, func(i, j int) bool { return found[i].Module < found[j].Module })

	return found
}

func without(names []string, drop ...string) []string {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}

	var kept []string

	for _, n := range names {
		if !skip[n] {
			kept = append(kept, n)
		}
	}

	return kept
}

func ownerOf(module string, owners map[string]string) string {
	if owner, ok := owners[module]; ok {
		return owner
	}

	return NormalizeName(module)
}

func namesFrom(imports *Imports, owners map[string]string, packages map[string]bool) []string {
	names := []string{}

	if imports == nil {
		return names
	}

	for name := range imports.ProductionNames {
		top := strings.SplitN(name, ".", 2)[0]
		if packages[ownerOf(top, owners)] {
			names = append(names, name)
		}
	}

	sort.Strings(names)

	return names
}

func describePackage(pkg *Package, name string, target Target, history map[string]int) SurfacePackage {
	sp := SurfacePackage{Name: name, Native: "unknown", Advisories: history[name]}
	if pkg == nil {
		return sp
	}

	sp.Version = pkg.Version

	for _, v := range pkg.Variants {
		if w, ok := bestWheel(v.Wheels, target); ok {
			sp.Version = v.Version
			sp.Size = w.Size
			sp.Native = "yes"

			if strings.HasSuffix(w.Filename, "-any.whl") {
				sp.Native = "no"
			}

			return sp
		}
	}

	return sp
}

// bestWheel picks the wheel a target install would use: one whose platform tag fits (or
// "any"), preferring an exact CPython match over the stable ABI over generic py3.
func bestWheel(wheels []Wheel, target Target) (Wheel, bool) {
	best, bestScore := Wheel{}, 0

	for _, w := range wheels {
		parts := strings.Split(strings.TrimSuffix(w.Filename, ".whl"), "-")
		if len(parts) < 5 {
			continue
		}

		pyTag, abiTag, platTag := parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1]

		if !platformFits(platTag, target) {
			continue
		}

		score := pythonFit(pyTag, abiTag, target.Python)
		if score > bestScore {
			best, bestScore = w, score
		}
	}

	return best, bestScore > 0
}

func platformFits(platTag string, target Target) bool {
	if platTag == "any" {
		return true
	}

	osMarker := map[string]string{"linux": "linux", "windows": "win", "macos": "macosx"}[target.OS]
	if osMarker == "" || !strings.Contains(platTag, osMarker) {
		return false
	}

	arches := map[string][]string{
		"x86_64": {"x86_64", "amd64"},
		"arm64":  {"aarch64", "arm64", "universal2"},
	}[target.Arch]

	for _, a := range arches {
		if strings.Contains(platTag, a) {
			return true
		}
	}

	return false
}

// pythonFit scores how well a wheel's python/abi tags fit the target interpreter: 3 for an
// exact CPython build, 2 for the stable ABI (abi3), 1 for generic py3, 0 for no fit.
func pythonFit(pyTag, abiTag, python string) int {
	cp := "cp" + strings.ReplaceAll(python, ".", "")

	for _, tag := range strings.Split(pyTag, ".") {
		switch {
		case tag == cp && abiTag != "abi3":
			return 3
		case abiTag == "abi3" && strings.HasPrefix(tag, "cp3") && CompareVersions(tag[2:], cp[2:]) <= 0:
			return 2
		case tag == "py3" || tag == "py2.py3":
			return 1
		}
	}

	if strings.Contains(pyTag, "py3") {
		return 1
	}

	return 0
}

// WriteTable writes the ranked dependencies, then what each brings in and the undeclared
// imports.
func (r SurfaceReport) WriteTable(w io.Writer, detail bool) error {
	width := textWidth()

	fmt.Fprintf(w, "%s ships %s (%s %s, Python %s). What each direct dependency alone brings in:\n\n",
		r.Project, plural(r.Total, "package"), r.Target.OS, r.Target.Arch, r.Target.Python)

	coverage := false
	for _, s := range r.Entries {
		coverage = coverage || s.Called != nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	header := "DEPENDENCY\tPACKAGES\tNATIVE\tSIZE\tPAST ADVISORIES\tUSED"
	if coverage {
		header += "\tFUNCTIONS CALLED"
	}

	fmt.Fprintln(tw, header)

	for _, s := range r.Entries {
		name := s.Dependency
		if len(s.Also) > 0 {
			name += " (+" + strings.Join(s.Also, ", +") + ")"
		}

		row := fmt.Sprintf("%s\t%d\t%d\t%s\t%d\t%s", name, len(s.Packages), s.Native(), formatSize(s),
			s.AdvisoryHistory(), usedSummary(s))
		if coverage {
			row += "\t" + fmt.Sprint(len(s.Called))
		}

		fmt.Fprintln(tw, row)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	listed := false

	for _, s := range r.Entries {
		if len(s.Packages) == 0 {
			if len(s.SharedWith) > 0 {
				fmt.Fprintf(w, "\n%s\n", s.Dependency)
				fmt.Fprint(w, wrap("removing it alone removes nothing - "+strings.Join(s.SharedWith, ", ")+
					" also need it", "  ", width))
			}

			continue
		}

		if !detail && len(s.Packages) < 3 {
			continue
		}

		listed = true

		fmt.Fprintf(w, "\n%s\n", s.Dependency)
		fmt.Fprint(w, wrap("brings in: "+packageList(s.Packages), "  ", width))

		if len(s.UsedNames) > 0 {
			names := firstN(s.UsedNames, 12)

			text := "uses: " + strings.Join(names, ", ")
			if len(s.UsedNames) > len(names) {
				text += fmt.Sprintf(" and %d more", len(s.UsedNames)-len(names))
			}

			fmt.Fprint(w, wrap(text, "  ", width))
		}
	}

	if listed {
		fmt.Fprintf(w, "\n* native code   (n) past advisories   ? no wheel for %s %s - probably not installed there\n",
			r.Target.OS, r.Target.Arch)
	}

	writeUndeclared(w, r.Undeclared, width)

	return nil
}

// usedSummary is how the project uses a dependency: names imported, and whether it runs
// one of its commands.
func usedSummary(s Surface) string {
	var parts []string

	if len(s.UsedNames) > 0 {
		parts = append(parts, plural(len(s.UsedNames), "name"))
	}

	if s.Command {
		parts = append(parts, "command")
	}

	if len(parts) == 0 {
		return "-"
	}

	return strings.Join(parts, ", ")
}

// writeUndeclared lists imports the project makes without depending on the package.
func writeUndeclared(w io.Writer, undeclared []Undeclared, width int) {
	if len(undeclared) == 0 {
		return
	}

	fmt.Fprint(w, "\n"+wrap("Undeclared imports - declare them, or removing what brings them in breaks the code:",
		"", width))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	for _, u := range undeclared {
		name := u.Package
		if NormalizeName(u.Module) != NormalizeName(u.Package) {
			name = u.Module + " (" + u.Package + ")"
		}

		where := "via " + strings.Join(u.Via, " → ")
		if u.DevOnly {
			where = "only dev dependencies provide it (" + strings.Join(u.Via, " → ") + ") - fails in production"
		}

		fmt.Fprintf(tw, "  %s\t%s\n", name, where)
	}

	_ = tw.Flush()
}

func formatSize(s Surface) string {
	total, complete := s.Size()
	text := fmt.Sprintf("%.1f MB", float64(total)/1e6)

	if !complete {
		text = ">= " + text
	}

	return text
}

func packageList(packages []SurfacePackage) string {
	parts := make([]string, len(packages))
	for i, p := range packages {
		parts[i] = p.Name

		switch p.Native {
		case "yes":
			parts[i] += "*"
		case "unknown":
			parts[i] += "?"
		}

		if p.Advisories > 0 {
			parts[i] += fmt.Sprintf("(%d)", p.Advisories)
		}
	}

	return strings.Join(parts, ", ")
}
