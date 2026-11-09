package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// yarnEntry is one resolved package in a yarn.lock: the exact version a set of
// "name@range" specifiers resolved to, and its own requirements.
type yarnEntry struct {
	Name    string
	Version string
	Deps    map[string]string // dependency name -> requested range
}

// ReadYarnLock parses a yarn.lock - classic (v1) or berry (v2+, "__metadata:") - into the same
// Lock npm gets: every install is a node, edges are resolved through the specifiers the lock
// records, and the project's runtime and dev dependencies come from the package.json beside it
// (or in srcDir, when only the lock was fetched).
func ReadYarnLock(path, srcDir string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var specs map[string]*yarnEntry // "name@range" -> entry

	if strings.Contains(string(data), "__metadata:") {
		specs, err = parseYarnBerry(data)
	} else {
		specs, err = parseYarnClassic(string(data))
	}

	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	manifest, err := readManifest(path, srcDir)
	if err != nil {
		return nil, err
	}

	lock := &Lock{Ecosystem: EcosystemNPM, Packages: map[string]*Package{}, Nodes: map[string][]string{}, Project: manifest.Name}
	if lock.Project == "" {
		lock.Project = projectName(path)
	}

	lock.Direct = mergeNames(nil, sortedKeys(manifest.Dependencies, manifest.OptionalDependencies, manifest.PeerDependencies))
	lock.DevDirect = sortedKeys(manifest.DevDependencies)
	lock.Bundler = findBundler(mergeNames(lock.Direct, lock.DevDirect))

	if lock.Bundler == "" {
		lock.Bundler = scriptBundler(manifest.path)
	}

	resolve := func(deps map[string]string) []string {
		var out []string

		for name, rng := range deps {
			if e := lookupYarn(specs, name, rng); e != nil {
				out = append(out, e.Name+"@"+e.Version)
			}
		}

		sort.Strings(out)

		return mergeNames(nil, out)
	}

	roots := map[string]string{}
	for _, m := range []map[string]string{manifest.Dependencies, manifest.OptionalDependencies, manifest.PeerDependencies, manifest.DevDependencies} {
		for name, rng := range m {
			roots[name] = rng
		}
	}

	lock.RootNodes = resolve(roots)

	seen := map[*yarnEntry]bool{}

	for _, e := range specs {
		if seen[e] {
			continue
		}

		seen[e] = true

		id := e.Name + "@" + e.Version
		lock.Nodes[id] = mergeNames(lock.Nodes[id], resolve(e.Deps))

		deps := sortedKeys(e.Deps)

		pkg, ok := lock.Packages[e.Name]
		if !ok {
			lock.Packages[e.Name] = &Package{Name: e.Name, Version: e.Version, Deps: deps, Variants: []Variant{{Version: e.Version}}}

			continue
		}

		pkg.Deps = mergeNames(pkg.Deps, deps)

		if !hasVariant(pkg, e.Version) {
			pkg.Variants = append(pkg.Variants, Variant{Version: e.Version})
		}
	}

	return lock, nil
}

// lookupYarn finds the entry a dependency's range resolved to. Berry records its specifiers
// as "name@npm:range", classic as "name@range".
func lookupYarn(specs map[string]*yarnEntry, name, rng string) *yarnEntry {
	for _, key := range []string{name + "@" + rng, name + "@npm:" + rng} {
		if e, ok := specs[key]; ok {
			return e
		}
	}

	return nil
}

// splitSpecifier splits "@scope/name@^1.0.0" into its name and range.
func splitSpecifier(spec string) (name, rng string) {
	spec = strings.Trim(strings.TrimSpace(spec), `"`)

	i := strings.LastIndex(spec, "@")
	if i <= 0 {
		return spec, ""
	}

	return spec[:i], spec[i+1:]
}

// parseYarnClassic reads yarn v1's own format:
//
//	"@scope/name@^1.0.0", name@^1.1.0:
//	  version "1.2.3"
//	  dependencies:
//	    dep "^2.0.0"
func parseYarnClassic(text string) (map[string]*yarnEntry, error) {
	specs := map[string]*yarnEntry{}

	var (
		current *yarnEntry
		section string
	)

	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		body := strings.TrimSpace(line)

		switch {
		case indent == 0 && strings.HasSuffix(body, ":"):
			current = &yarnEntry{Deps: map[string]string{}}
			section = ""

			for header := range strings.SplitSeq(strings.TrimSuffix(body, ":"), ",") {
				name, _ := splitSpecifier(header)
				current.Name = name
				specs[strings.Trim(strings.TrimSpace(header), `"`)] = current
			}
		case current == nil:
			continue
		case indent == 2:
			section = ""

			switch {
			case strings.HasPrefix(body, "version "):
				current.Version = strings.Trim(strings.TrimPrefix(body, "version "), `"`)
			case body == "dependencies:" || body == "optionalDependencies:":
				section = "deps"
			}
		case indent == 4 && section == "deps":
			key, value, ok := strings.Cut(body, " ")
			if !ok {
				continue
			}

			current.Deps[strings.Trim(key, `"`)] = strings.Trim(strings.TrimSpace(value), `"`)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return specs, nil
}

type yarnBerryEntry struct {
	Version              string            `yaml:"version"`
	Resolution           string            `yaml:"resolution"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// parseYarnBerry reads yarn 2+'s lock, which is YAML keyed by comma-separated specifiers
// ("name@npm:^1.0.0, name@npm:^1.1.0"). Workspace entries (the project and its members)
// are skipped.
func parseYarnBerry(data []byte) (map[string]*yarnEntry, error) {
	var raw map[string]yarnBerryEntry
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	specs := map[string]*yarnEntry{}

	for key, e := range raw {
		if key == "__metadata" || e.Version == "" {
			continue
		}

		if strings.Contains(e.Resolution, "@workspace:") {
			continue
		}

		entry := &yarnEntry{Version: e.Version, Deps: map[string]string{}}
		for _, m := range []map[string]string{e.Dependencies, e.OptionalDependencies} {
			for name, rng := range m {
				entry.Deps[name] = rng
			}
		}

		for spec := range strings.SplitSeq(key, ",") {
			name, _ := splitSpecifier(spec)
			entry.Name = name
			specs[strings.Trim(strings.TrimSpace(spec), `"`)] = entry
		}
	}

	return specs, nil
}

// manifestFile is the part of a package.json picard reads.
type manifestFile struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`

	path string
}

// readManifest reads the package.json beside a lock file, or in srcDir when the lock was
// fetched on its own (a PR's lock at some commit).
func readManifest(lockPath, srcDir string) (*manifestFile, error) {
	for _, dir := range []string{filepath.Dir(lockPath), srcDir} {
		if dir == "" {
			continue
		}

		file := filepath.Join(dir, "package.json")

		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var m manifestFile
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", file, err)
		}

		m.path = file

		return &m, nil
	}

	return nil, fmt.Errorf("%s needs the package.json beside it to tell runtime from dev dependencies", lockPath)
}
