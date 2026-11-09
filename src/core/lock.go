package core

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Versions is every version the lock installs of each package: its locked version, its
// variants' versions, and (npm) each "name@version" install a package is locked at.
func (l *Lock) Versions() map[string][]string {
	set := map[string]map[string]bool{}
	add := func(name, version string) {
		if name == "" || version == "" {
			return
		}

		if set[name] == nil {
			set[name] = map[string]bool{}
		}

		set[name][version] = true
	}

	for name, p := range l.Packages {
		add(name, p.Version)

		for _, v := range p.Variants {
			add(name, v.Version)
		}
	}

	for node := range l.Nodes {
		if i := strings.LastIndex(node, "@"); i > 0 {
			add(node[:i], node[i+1:])
		}
	}

	out := make(map[string][]string, len(set))

	for name, versions := range set {
		for v := range versions {
			out[name] = append(out[name], v)
		}

		sort.Strings(out[name])
	}

	return out
}

// Package is one resolved distribution from a lock file.
type Package struct {
	Name    string
	Version string
	// Deps are the normalized names of the packages this one depends on, including the
	// optional dependencies of any extras it requests (e.g. uvicorn[standard]).
	Deps []string
	// Variants are the package's locked builds - usually one, but a package can be locked
	// at several versions for different platforms (torch from PyPI for Windows/macOS,
	// torch+cpu from PyTorch's index for Linux).
	Variants []Variant
}

// Variant is one locked version of a package and its built distributions.
type Variant struct {
	Version string
	Wheels  []Wheel
	// HasSdist: a source distribution is available (built locally when no wheel fits).
	HasSdist bool
}

// Wheel is one built distribution. Size is 0 when the index didn't report one (PyTorch's
// index doesn't).
type Wheel struct {
	Filename string
	Size     int64
}

// Lock is a parsed uv.lock: every resolved package, plus which of them a production install
// actually gets.
type Lock struct {
	Project string
	// Ecosystem is the package registry the lock is for, as OSV names it (EcosystemPyPI or
	// EcosystemNPM).
	Ecosystem string
	Packages  map[string]*Package
	// Direct are the project's own runtime dependencies; DevDirect its dev-group ones.
	Direct    []string
	DevDirect []string
	// Compiled are the import paths the build compiles in (Go, from go list -deps across
	// platforms), or nil when unknown.
	Compiled map[string]bool
	// Bundler names the bundler the project builds with (npm), or "". A bundler copies
	// whatever the code reaches into its output, so a dev dependency may ship after all.
	Bundler string
	// Nodes (npm) are the edges between exact installs: "name@version" -> the "name@version"s
	// it resolves its dependencies to. RootNodes are the installs the project's own
	// dependencies resolve to. A package locked at several versions is one entry in Packages
	// but one node per version here, so reachability can be judged per version.
	Nodes     map[string][]string
	RootNodes []string
	// MinPython is the lowest Python the lock supports ("3.12" from requires-python
	// ">=3.12"), or "".
	MinPython string
}

type uvDep struct {
	Name  string   `toml:"name"`
	Extra []string `toml:"extra"`
}

type uvDist struct {
	URL  string `toml:"url"`
	Path string `toml:"path"`
	Size int64  `toml:"size"`
}

type uvPackage struct {
	Name                 string             `toml:"name"`
	Version              string             `toml:"version"`
	Source               map[string]any     `toml:"source"`
	Dependencies         []uvDep            `toml:"dependencies"`
	DevDependencies      map[string][]uvDep `toml:"dev-dependencies"`
	OptionalDependencies map[string][]uvDep `toml:"optional-dependencies"`
	Wheels               []uvDist           `toml:"wheels"`
	Sdist                *uvDist            `toml:"sdist"`
}

type uvLock struct {
	RequiresPython string      `toml:"requires-python"`
	Packages       []uvPackage `toml:"package"`
}

var minPythonRe = regexp.MustCompile(`>=\s*(\d+\.\d+)`)

// NormalizeName applies PEP 503 normalization, so "Python_Dotenv" and "python-dotenv" are
// the same package.
func NormalizeName(name string) string {
	name = strings.ToLower(name)

	return strings.NewReplacer("_", "-", ".", "-").Replace(name)
}

// ReadUVLock parses a uv.lock. The project itself is the package whose source is the
// directory being locked (virtual or editable "."), which uv records alongside the real
// dependencies.
func ReadUVLock(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw uvLock
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	lock := &Lock{Ecosystem: EcosystemPyPI, Packages: map[string]*Package{}}
	if m := minPythonRe.FindStringSubmatch(raw.RequiresPython); m != nil {
		lock.MinPython = m[1]
	}

	optional := map[string]map[string][]uvDep{}
	requested := map[string][]uvDep{} // depender -> its dependency entries (for extras)

	for _, p := range raw.Packages {
		name := NormalizeName(p.Name)

		if isProjectSource(p.Source) {
			lock.Project = name
			lock.Direct = depNames(p.Dependencies)
			requested[name] = append(requested[name], p.Dependencies...)

			for _, group := range p.DevDependencies {
				lock.DevDirect = append(lock.DevDirect, depNames(group)...)
			}

			continue
		}

		variant := Variant{Version: p.Version, HasSdist: p.Sdist != nil}
		for _, w := range p.Wheels {
			variant.Wheels = append(variant.Wheels, Wheel{Filename: distFilename(w), Size: w.Size})
		}

		if existing, seen := lock.Packages[name]; seen {
			// Another build of the same package (see Variant); dependency edges are shared.
			existing.Variants = append(existing.Variants, variant)
			existing.Deps = mergeNames(existing.Deps, depNames(p.Dependencies))
		} else {
			lock.Packages[name] = &Package{
				Name: name, Version: p.Version, Deps: depNames(p.Dependencies), Variants: []Variant{variant},
			}
		}

		requested[name] = append(requested[name], p.Dependencies...)

		if len(p.OptionalDependencies) > 0 {
			if optional[name] == nil {
				optional[name] = map[string][]uvDep{}
			}

			for extra, deps := range p.OptionalDependencies {
				optional[name][extra] = append(optional[name][extra], deps...)
			}
		}
	}

	if lock.Project == "" {
		return nil, fmt.Errorf("%s: no project package (source virtual/editable \".\") found", path)
	}

	// A dependency on pkg[extra] also installs pkg's optional dependencies for that extra.
	// They're recorded as pkg's own edges, so they're attributed to it ("uvicorn ->
	// httptools") - slightly over-attributing if one depender asks for the extra and
	// another doesn't, which only ever over-reports what ships.
	for _, deps := range requested {
		for _, d := range deps {
			target := lock.Packages[NormalizeName(d.Name)]
			if target == nil {
				continue
			}

			for _, extra := range d.Extra {
				target.Deps = mergeNames(target.Deps, depNames(optional[target.Name][extra]))
			}
		}
	}

	return lock, nil
}

func distFilename(d uvDist) string {
	ref := d.URL
	if ref == "" {
		ref = d.Path
	}

	name := ref[strings.LastIndex(ref, "/")+1:]

	return strings.ReplaceAll(name, "%2B", "+")
}

func isProjectSource(source map[string]any) bool {
	for _, key := range []string{"virtual", "editable"} {
		if v, ok := source[key]; ok && v == "." {
			return true
		}
	}

	return false
}

func depNames(deps []uvDep) []string {
	return mergeNames(nil, func() []string {
		names := make([]string, len(deps))
		for i, d := range deps {
			names[i] = NormalizeName(d.Name)
		}

		return names
	}())
}

// mergeNames appends the names not already present, keeping order.
func mergeNames(into, more []string) []string {
	seen := map[string]bool{}
	for _, n := range into {
		seen[n] = true
	}

	for _, n := range more {
		if !seen[n] {
			seen[n] = true

			into = append(into, n)
		}
	}

	return into
}

// NodeClosure is every install ("name@version") reachable from the given direct dependency
// names, each mapped to a shortest chain of package names that pulls it in. It is nil when
// the lock has no per-install edges (anything but npm), so callers fall back to Closure.
func (l *Lock) NodeClosure(roots []string) map[string][]string {
	if l.Nodes == nil {
		return nil
	}

	want := map[string]bool{}
	for _, r := range roots {
		want[r] = true
	}

	paths := map[string][]string{}

	var queue []string

	for _, id := range l.RootNodes {
		if _, ok := paths[id]; !ok && want[nodeName(id)] {
			paths[id] = []string{nodeName(id)}
			queue = append(queue, id)
		}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, dep := range l.Nodes[current] {
			if _, seen := paths[dep]; seen {
				continue
			}

			paths[dep] = append(append([]string(nil), paths[current]...), nodeName(dep))
			queue = append(queue, dep)
		}
	}

	return paths
}

// nodeName is the package name of a "name@version" install id (scoped names start with @).
func nodeName(id string) string {
	if i := strings.LastIndex(id, "@"); i > 0 {
		return id[:i]
	}

	return id
}

// Closure is every package reachable from the given roots, each mapped to one shortest
// dependency chain that pulls it in (starting at a root) - the "why is this here" answer.
func (l *Lock) Closure(roots []string) map[string][]string {
	paths := map[string][]string{}
	queue := make([]string, 0, len(roots))

	for _, r := range roots {
		if _, ok := paths[r]; !ok {
			paths[r] = []string{r}
			queue = append(queue, r)
		}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		pkg, ok := l.Packages[current]
		if !ok {
			continue
		}

		deps := append([]string(nil), pkg.Deps...)
		sort.Strings(deps)

		for _, dep := range deps {
			if _, seen := paths[dep]; seen {
				continue
			}

			paths[dep] = append(append([]string(nil), paths[current]...), dep)
			queue = append(queue, dep)
		}
	}

	return paths
}
