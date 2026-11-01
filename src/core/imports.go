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
	// ProductionNames are the dotted names production code imports - "fastapi.FastAPI" for
	// `from fastapi import FastAPI`, "numpy" for `import numpy` - a measure of how much of a
	// package the project actually touches.
	ProductionNames map[string]bool
}

// ScanImports walks the project's Python files for import statements. Static and
// line-based: imports built at runtime (importlib, __import__) aren't seen, which is why
// coverage (Executed) is the stronger evidence when it's available.
func ScanImports(root string) (*Imports, error) {
	result := &Imports{Production: map[string]bool{}, Test: map[string]bool{}, ProductionNames: map[string]bool{}}

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

		if isTestPath(root, path) {
			return scanFile(path, result.Test, nil)
		}

		return scanFile(path, result.Production, result.ProductionNames)
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

func scanFile(path string, into, names map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		code     []string              // the lines that aren't imports
		bindings = map[string]string{} // name bound by `import x [as y]` -> module
	)

	defer func() { addAttributeNames(names, bindings, code) }()

	for scanner.Scan() {
		line := stripComment(scanner.Text())

		m := importRe.FindStringSubmatch(line)
		if m == nil {
			code = append(code, line)

			continue
		}

		if m[1] != "" {
			addModule(into, m[1])

			if names != nil && !strings.HasPrefix(m[1], ".") {
				// `from x import (\n a,\n b,\n)` spans lines until the closing paren.
				imported := line[strings.Index(line, " import ")+len(" import "):]
				for strings.Contains(imported, "(") && !strings.Contains(imported, ")") && scanner.Scan() {
					imported += " " + stripComment(scanner.Text())
				}

				for _, name := range importedNames(imported) {
					names[m[1]+"."+name] = true
				}
			}

			continue
		}

		// "import a.b as c, d" - every comma-separated module.
		for _, part := range strings.Split(m[2], ",") {
			fields := strings.Fields(part)
			if len(fields) > 0 {
				addModule(into, fields[0])

				if names != nil && !strings.HasPrefix(fields[0], ".") {
					// `import a.b` binds a; `import a.b as c` binds c to a.b.
					binding, module := strings.SplitN(fields[0], ".", 2)[0], strings.SplitN(fields[0], ".", 2)[0]
					if len(fields) == 3 && fields[1] == "as" {
						binding, module = fields[2], fields[0]
					}

					bindings[binding] = module
				}
			}
		}
	}

	return scanner.Err()
}

// addAttributeNames records what a bare `import x` actually uses: each `x.name` in the
// file's code, as "x.name". A module imported but never referenced that way is recorded
// as itself, so it still counts as used.
func addAttributeNames(names map[string]bool, bindings map[string]string, code []string) {
	if names == nil {
		return
	}

	text := strings.Join(code, "\n")

	for binding, module := range bindings {
		re := regexp.MustCompile(`(?:^|[^\w.])` + regexp.QuoteMeta(binding) + `\.([A-Za-z_]\w*)`)

		found := false

		for _, m := range re.FindAllStringSubmatch(text, -1) {
			names[module+"."+m[1]] = true
			found = true
		}

		if !found {
			names[module] = true
		}
	}
}

// stripComment drops a trailing "# ..." - import lines have no string literals to confuse it.
func stripComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}

	return line
}

// importedNames parses the right-hand side of `from x import ...`: "a, b as c", "(a, b)".
func importedNames(s string) []string {
	s = strings.NewReplacer("(", " ", ")", " ", "\\", " ").Replace(s)

	var names []string

	for _, part := range strings.Split(s, ",") {
		fields := strings.Fields(part)
		if len(fields) > 0 && fields[0] != "*" {
			names = append(names, fields[0])
		}
	}

	return names
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

// ScriptOwners maps console commands to the package that installs them, from the installed
// environment's entry_points.txt ([console_scripts]) - e.g. "uvicorn" -> uvicorn - so a
// package run from the command line rather than imported is still seen as used.
func ScriptOwners(sitePackages string) map[string]string {
	owners := map[string]string{}

	entries, err := os.ReadDir(sitePackages)
	if err != nil {
		return owners
	}

	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".dist-info") {
			continue
		}

		distInfo := filepath.Join(sitePackages, e.Name())

		data, err := os.ReadFile(filepath.Join(distInfo, "entry_points.txt"))
		if err != nil {
			continue
		}

		dist := distName(distInfo)
		inScripts := false

		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)

			if strings.HasPrefix(line, "[") {
				inScripts = line == "[console_scripts]"

				continue
			}

			if name, _, ok := strings.Cut(line, "="); ok && inScripts && dist != "" {
				owners[strings.TrimSpace(name)] = dist
			}
		}
	}

	return owners
}

// launchFiles are where a project says how it's run.
var launchFiles = []string{"Dockerfile", "Containerfile", "Makefile", "Procfile", "docker-compose.yml",
	"docker-compose.yaml", "compose.yml", "compose.yaml", "entrypoint.sh", "start.sh", "run.sh"}

var wordRe = regexp.MustCompile(`[A-Za-z0-9_.-]+`)

// CommandsUsed returns the packages whose console commands appear in the project's launch
// files (Dockerfile CMD, Makefile targets, compose commands...).
func CommandsUsed(root string, scripts map[string]string) map[string]bool {
	used := map[string]bool{}

	for _, name := range launchFiles {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue
		}

		for _, word := range wordRe.FindAllString(string(data), -1) {
			if pkg, ok := scripts[word]; ok {
				used[pkg] = true
			}
		}
	}

	return used
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
