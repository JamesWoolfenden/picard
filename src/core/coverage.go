package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ModuleUse is what a coverage run shows about one third-party top-level module.
type ModuleUse struct {
	// Loaded: some of its code ran - at minimum its import-time module body.
	Loaded bool
	// Called lists functions ("file.py:Class.method") whose bodies ran - actual use, as
	// opposed to merely being imported. Vulnerable code almost always lives in functions.
	Called []string
	// FunctionData: the report has per-function data (coverage.py 7.5+); without it, Loaded
	// is all that's known.
	FunctionData bool
}

// ReadCoverage reads a coverage.py JSON report (`coverage json`) into per-module use, for
// third-party code under site-packages only. Measure with third-party code included, e.g.:
//
//	coverage run --include="*/site-packages/*" -m pytest && coverage json
//
// The evidence is only as good as the run: a test suite that stubs out the network won't
// call an HTTP library's certificate handling even though production does on every request.
// Prefer a run that exercises the app the way production does (a smoke test of the real
// server) where there is one.
func ReadCoverage(path string) (map[string]*ModuleUse, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var report struct {
		Files map[string]struct {
			ExecutedLines []int `json:"executed_lines"`
			Functions     map[string]struct {
				ExecutedLines []int `json:"executed_lines"`
			} `json:"functions"`
		} `json:"files"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	modules := map[string]*ModuleUse{}

	for file, f := range report.Files {
		module, rel := siteModule(file)
		if module == "" || len(f.ExecutedLines) == 0 {
			continue
		}

		use := modules[module]
		if use == nil {
			use = &ModuleUse{}
			modules[module] = use
		}

		use.Loaded = true

		if f.Functions != nil {
			use.FunctionData = true
		}

		for name, fn := range f.Functions {
			// "" is coverage.py's entry for the module body itself - import time, not use.
			if name != "" && len(fn.ExecutedLines) > 0 {
				use.Called = append(use.Called, rel+":"+name)
			}
		}
	}

	for _, use := range modules {
		sort.Strings(use.Called)
	}

	return modules, nil
}

// siteModule is the top-level module a site-packages file belongs to and the file's path
// below site-packages, or "" for a file that isn't third-party.
func siteModule(file string) (string, string) {
	parts := strings.Split(filepath.ToSlash(file), "/")
	for i, p := range parts {
		if p == "site-packages" && i+1 < len(parts) {
			return strings.TrimSuffix(parts[i+1], ".py"), strings.Join(parts[i+1:], "/")
		}
	}

	return "", ""
}
