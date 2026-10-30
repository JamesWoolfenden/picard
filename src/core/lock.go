package core

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Package is one resolved distribution from a lock file.
type Package struct {
	Name    string
	Version string
	// Deps are the normalized names of the packages this one depends on.
	Deps []string
}

// Lock is a parsed uv.lock: every resolved package, plus which of them a production install
// actually gets.
type Lock struct {
	Project  string
	Packages map[string]*Package
	// Direct are the project's own runtime dependencies; DevDirect its dev-group ones.
	Direct    []string
	DevDirect []string
}

type uvDep struct {
	Name string `toml:"name"`
}

type uvPackage struct {
	Name            string             `toml:"name"`
	Version         string             `toml:"version"`
	Source          map[string]any     `toml:"source"`
	Dependencies    []uvDep            `toml:"dependencies"`
	DevDependencies map[string][]uvDep `toml:"dev-dependencies"`
}

type uvLock struct {
	Packages []uvPackage `toml:"package"`
}

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

	lock := &Lock{Packages: map[string]*Package{}}

	for _, p := range raw.Packages {
		name := NormalizeName(p.Name)

		if isProjectSource(p.Source) {
			lock.Project = name
			lock.Direct = depNames(p.Dependencies)

			for _, group := range p.DevDependencies {
				lock.DevDirect = append(lock.DevDirect, depNames(group)...)
			}

			continue
		}

		// A package locked at two versions (platform-specific builds, e.g. torch and
		// torch+cpu) appears twice - keep the first, the dependency edges are the same.
		if _, seen := lock.Packages[name]; seen {
			continue
		}

		lock.Packages[name] = &Package{Name: name, Version: p.Version, Deps: depNames(p.Dependencies)}
	}

	if lock.Project == "" {
		return nil, fmt.Errorf("%s: no project package (source virtual/editable \".\") found", path)
	}

	return lock, nil
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
	names := make([]string, 0, len(deps))
	seen := map[string]bool{}

	for _, d := range deps {
		n := NormalizeName(d.Name)
		if !seen[n] {
			seen[n] = true

			names = append(names, n)
		}
	}

	return names
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
