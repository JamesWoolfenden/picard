package core

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Directories never treated as the project's own source.
var skipDirs = map[string]bool{
	".git": true, ".venv": true, "venv": true, "env": true, "node_modules": true,
	"__pycache__": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true,
	"build": true, "dist": true, "site-packages": true,
}

// Directories whose imports are test-only - they don't ship, so a package used only from
// here isn't used in production.
var testDirs = map[string]bool{"tests": true, "test": true, "testing": true}

var importRe = regexp.MustCompile(`^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+(.+))`)

// Imports is which top-level modules the project's own code imports, split by whether the
// importing file is production code or a test.
type Imports struct {
	Production map[string]bool
	Test       map[string]bool
}

// ScanImports walks the project's Python files for import statements. Static and
// line-based: imports built at runtime (importlib, __import__) aren't seen, which is why
// coverage (Executed) is the stronger evidence when it's available.
func ScanImports(root string) (*Imports, error) {
	result := &Imports{Production: map[string]bool{}, Test: map[string]bool{}}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(d.Name(), ".py") {
			return nil
		}

		target := result.Production
		if isTestPath(root, path) {
			target = result.Test
		}

		return scanFile(path, target)
	})

	return result, err
}

func isTestPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts[:len(parts)-1] {
		if testDirs[p] {
			return true
		}
	}

	name := parts[len(parts)-1]

	return strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test.py") || name == "conftest.py"
}

func scanFile(path string, into map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		m := importRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}

		if m[1] != "" {
			addModule(into, m[1])

			continue
		}

		// "import a.b as c, d" - every comma-separated module.
		for _, part := range strings.Split(m[2], ",") {
			fields := strings.Fields(part)
			if len(fields) > 0 {
				addModule(into, fields[0])
			}
		}
	}

	return scanner.Err()
}

func addModule(into map[string]bool, module string) {
	// Relative imports ("from . import x") are the project's own code.
	if module == "" || strings.HasPrefix(module, ".") {
		return
	}

	into[strings.SplitN(module, ".", 2)[0]] = true
}

// ModuleOwners maps top-level module names to the package that provides them, read from
// an installed environment's *.dist-info (top_level.txt, else RECORD) - the only reliable
// source, since package and module names often differ (python-dotenv provides "dotenv").
// Modules with no installed owner fall back to their own name in PackagesForModules.
func ModuleOwners(sitePackages string) map[string]string {
	owners := map[string]string{}

	entries, err := os.ReadDir(sitePackages)
	if err != nil {
		return owners
	}

	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".dist-info") {
			continue
		}

		dist := distName(filepath.Join(sitePackages, e.Name()))
		if dist == "" {
			continue
		}

		for _, module := range topLevelModules(filepath.Join(sitePackages, e.Name())) {
			if _, taken := owners[module]; !taken {
				owners[module] = dist
			}
		}
	}

	return owners
}

func distName(distInfo string) string {
	data, err := os.ReadFile(filepath.Join(distInfo, "METADATA"))
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Name:") {
			return NormalizeName(strings.TrimSpace(strings.TrimPrefix(line, "Name:")))
		}
	}

	return ""
}

func topLevelModules(distInfo string) []string {
	if data, err := os.ReadFile(filepath.Join(distInfo, "top_level.txt")); err == nil {
		return strings.Fields(string(data))
	}

	data, err := os.ReadFile(filepath.Join(distInfo, "RECORD"))
	if err != nil {
		return nil
	}

	seen := map[string]bool{}

	var modules []string

	for _, line := range strings.Split(string(data), "\n") {
		path := strings.SplitN(line, ",", 2)[0]
		first := strings.SplitN(path, "/", 2)[0]

		if first == "" || strings.HasSuffix(first, ".dist-info") || strings.HasPrefix(first, "..") || first == "__pycache__" {
			continue
		}

		module := strings.TrimSuffix(first, ".py")
		if !seen[module] {
			seen[module] = true

			modules = append(modules, module)
		}
	}

	return modules
}

// FindSitePackages locates the project's virtualenv site-packages (.venv or venv, Windows or
// POSIX layout), or "" if there isn't one.
func FindSitePackages(root string) string {
	for _, venv := range []string{".venv", "venv"} {
		windows := filepath.Join(root, venv, "Lib", "site-packages")
		if st, err := os.Stat(windows); err == nil && st.IsDir() {
			return windows
		}

		matches, _ := filepath.Glob(filepath.Join(root, venv, "lib", "python*", "site-packages"))
		if len(matches) > 0 {
			return matches[0]
		}
	}

	return ""
}

// PackagesForModules maps imported module names to package names.
func PackagesForModules(modules map[string]bool, owners map[string]string) map[string]bool {
	packages := map[string]bool{}

	for m := range modules {
		if owner, ok := owners[m]; ok {
			packages[owner] = true
		} else {
			packages[NormalizeName(m)] = true
		}
	}

	return packages
}
