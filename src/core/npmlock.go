package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Ecosystems a lock file can belong to, named as OSV names them.
const (
	EcosystemPyPI = "PyPI"
	EcosystemNPM  = "npm"
)

const nodeModules = "node_modules/"

type npmEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

type npmLockFile struct {
	Name            string              `json:"name"`
	LockfileVersion int                 `json:"lockfileVersion"`
	Packages        map[string]npmEntry `json:"packages"`
}

// ReadNPMLock parses a package-lock.json (lockfileVersion 2 or 3, written by npm 7+). The
// root entry's dependencies are the project's runtime ones and its devDependencies the dev
// ones; whether a package ships is then decided by walking the graph, the same as for
// uv.lock, rather than trusting the lock's own "dev" flags.
//
// Dependencies are tracked by package name. A package locked at several versions (nested
// node_modules) is one Package whose Version is the shallowest install and whose Variants
// list every version, so each is looked up; the dependency edges of all copies are merged.
func ReadNPMLock(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw npmLockFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	// A missing packages map is the old format; an empty one is a project without
	// dependencies.
	if raw.LockfileVersion < 2 || raw.Packages == nil {
		return nil, fmt.Errorf("%s: lockfileVersion %d has no packages map - regenerate it with npm 7 or later",
			path, raw.LockfileVersion)
	}

	lock := &Lock{Ecosystem: EcosystemNPM, Packages: map[string]*Package{}, Project: raw.Name}

	if lock.Project == "" {
		if abs, err := filepath.Abs(path); err == nil {
			lock.Project = filepath.Base(filepath.Dir(abs))
		}
	}

	root := raw.Packages[""]
	lock.Direct = mergeNames(nil, sortedKeys(root.Dependencies, root.OptionalDependencies, root.PeerDependencies))
	lock.DevDirect = sortedKeys(root.DevDependencies)
	lock.Bundler = findBundler(mergeNames(lock.Direct, lock.DevDirect))
	if lock.Bundler == "" {
		lock.Bundler = scriptBundler(filepath.Join(filepath.Dir(path), "package.json"))
	}

	keys := make([]string, 0, len(raw.Packages))
	for key := range raw.Packages {
		keys = append(keys, key)
	}

	// Shallowest install first (then alphabetical), so the first copy seen is the primary.
	sort.Slice(keys, func(i, j int) bool {
		di, dj := strings.Count(keys[i], nodeModules), strings.Count(keys[j], nodeModules)
		if di != dj {
			return di < dj
		}

		return keys[i] < keys[j]
	})

	for _, key := range keys {
		entry := raw.Packages[key]

		// "" is the project; entries outside node_modules, and links, are workspace members.
		if key == "" || entry.Link || !strings.Contains(key, nodeModules) {
			continue
		}

		name := entry.Name
		if name == "" {
			name = key[strings.LastIndex(key, nodeModules)+len(nodeModules):]
		}

		deps := sortedKeys(entry.Dependencies, entry.OptionalDependencies, entry.PeerDependencies)

		pkg, seen := lock.Packages[name]
		if !seen {
			lock.Packages[name] = &Package{
				Name: name, Version: entry.Version, Deps: deps, Variants: []Variant{{Version: entry.Version}},
			}

			continue
		}

		pkg.Deps = mergeNames(pkg.Deps, deps)

		if !hasVariant(pkg, entry.Version) {
			pkg.Variants = append(pkg.Variants, Variant{Version: entry.Version})
		}
	}

	return lock, nil
}

// bundlers are packages that, as a project's own direct dependency, mean its build bundles
// code - bundlers themselves, and frameworks whose build runs one.
var bundlers = map[string]bool{
	"esbuild": true, "webpack": true, "webpack-cli": true, "rollup": true, "rolldown": true,
	"vite": true, "parcel": true, "@vercel/ncc": true, "tsup": true, "@rspack/core": true,
	"@rspack/cli": true, "browserify": true, "next": true, "nuxt": true, "@sveltejs/kit": true,
	"react-scripts": true, "@angular-devkit/build-angular": true, "@angular/build": true,
	"gatsby": true, "astro": true, "@remix-run/dev": true,
}

// findBundler is the first of a project's direct dependencies that bundles its build, or "".
// Only direct ones count: a test runner pulling in a bundler for itself (vitest → vite)
// doesn't bundle the project.
func findBundler(direct []string) string {
	for _, name := range direct {
		if bundlers[name] {
			return name
		}
	}

	return ""
}

// bundlerCommands are the commands, as package.json scripts run them, that bundle a build.
var bundlerCommands = map[string]bool{
	"esbuild": true, "webpack": true, "rollup": true, "rolldown": true, "vite": true, "parcel": true,
	"ncc": true, "tsup": true, "rspack": true, "browserify": true, "next": true, "nuxt": true,
	"nuxi": true, "svelte-kit": true, "react-scripts": true, "ng": true, "gatsby": true,
	"astro": true, "remix": true,
}

var scriptWordRe = regexp.MustCompile(`[A-Za-z0-9@/._-]+`)

// scriptBundler is the first bundler command run by a package.json script, or "" - for a
// bundler that only arrives transitively (`vite build` with vite brought in by a plugin).
func scriptBundler(packageJSON string) string {
	data, err := os.ReadFile(packageJSON)
	if err != nil {
		return ""
	}

	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}

	if json.Unmarshal(data, &manifest) != nil {
		return ""
	}

	names := sortedKeys(manifest.Scripts)
	for _, name := range names {
		for _, word := range scriptWordRe.FindAllString(manifest.Scripts[name], -1) {
			if bundlerCommands[word] {
				return word
			}
		}
	}

	return ""
}

func hasVariant(pkg *Package, version string) bool {
	for _, v := range pkg.Variants {
		if v.Version == version {
			return true
		}
	}

	return false
}

// sortedKeys is the sorted union of the keys of several dependency maps.
func sortedKeys(maps ...map[string]string) []string {
	var names []string

	for _, m := range maps {
		for name := range m {
			names = append(names, name)
		}
	}

	sort.Strings(names)

	return mergeNames(nil, names)
}
