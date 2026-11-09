package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Pipfile.lock and pinned requirements files are flat: they list every installed package
// with its version but not which package asked for which. So there are no dependency
// edges - every locked package is treated as a direct dependency (of the runtime, or for
// the dev group of the dev set). That errs towards "shipped": a transitive package in the
// default group is judged as if the project asked for it, and nothing can be said about
// "only a dev tool pulls this in" within one group.

type pipfileEntry struct {
	Version string `json:"version"`
}

type pipfileLock struct {
	Meta struct {
		Requires struct {
			PythonVersion string `json:"python_version"`
			PythonFull    string `json:"python_full_version"`
		} `json:"requires"`
	} `json:"_meta"`
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

// ReadPipfileLock parses a Pipfile.lock: the "default" section is the runtime, "develop" the
// dev dependencies. Entries without a version (git, path or editable installs) have nothing
// to look up and are left out.
func ReadPipfileLock(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var raw pipfileLock
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	lock := &Lock{Ecosystem: EcosystemPyPI, Packages: map[string]*Package{}, Project: projectName(path)}

	python := raw.Meta.Requires.PythonVersion
	if python == "" {
		python = raw.Meta.Requires.PythonFull
	}

	if parts := strings.Split(python, "."); len(parts) >= 2 {
		lock.MinPython = parts[0] + "." + parts[1]
	}

	add := func(entries map[string]pipfileEntry) []string {
		var names []string

		for name, e := range entries {
			version := strings.TrimLeft(e.Version, "=")
			if version == "" {
				continue
			}

			name = NormalizeName(name)
			names = append(names, name)

			if _, seen := lock.Packages[name]; !seen {
				lock.Packages[name] = &Package{Name: name, Version: version, Variants: []Variant{{Version: version}}}
			}
		}

		return mergeNames(nil, names)
	}

	lock.Direct = add(raw.Default)
	lock.DevDirect = add(raw.Develop)

	return lock, nil
}

// requirementRe is one pinned requirement: name, optional [extras], == version, optional
// environment marker ("; python_version < '3.9'") or options (--hash=...).
var requirementRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)`)

// IsRequirementsFile: requirements.txt, requirements-dev.txt, dev-requirements.txt, ...
func IsRequirementsFile(name string) bool {
	name = strings.ToLower(name)

	return strings.HasSuffix(name, ".txt") && strings.Contains(name, "requirements")
}

// ReadRequirements parses a requirements file for the packages it pins with ==. A
// requirement with a range (>=, ~=) or no version isn't locked - which version gets
// installed is decided when pip runs - so it is left out; a file that pins nothing is an
// error rather than a clean scan. A file named like requirements-dev.txt or test-requirements.txt
// is taken as the dev set, anything else as the runtime.
func ReadRequirements(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lock := &Lock{Ecosystem: EcosystemPyPI, Packages: map[string]*Package{}, Project: projectName(path)}

	var names []string

	// A trailing backslash continues the line (pip-compile --generate-hashes).
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\\\n", " ")

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		// Blank lines, comments, and options (-r other.txt, -e ., --index-url ...).
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		m := requirementRe.FindStringSubmatch(line)
		if m == nil { // a range or no version: not locked
			continue
		}

		name := NormalizeName(m[1])
		if _, seen := lock.Packages[name]; !seen {
			lock.Packages[name] = &Package{Name: name, Version: m[2], Variants: []Variant{{Version: m[2]}}}
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("%s pins no versions (name==1.2.3), so there is nothing locked to look up - "+
			"generate a pinned file with `uv pip compile` or `pip freeze`, or a lock with `uv lock`", path)
	}

	base := strings.ToLower(filepath.Base(path))
	if strings.Contains(base, "dev") || strings.Contains(base, "test") {
		lock.DevDirect = names
	} else {
		lock.Direct = names
	}

	return lock, nil
}

// projectName is the directory a lock file sits in.
func projectName(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return filepath.Base(filepath.Dir(abs))
	}

	return ""
}
