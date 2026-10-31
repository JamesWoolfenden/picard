package core

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var jsExts = map[string]bool{".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true}

// Directories holding tests rather than shipped code, beyond the shared testDirs.
var jsTestDirs = map[string]bool{"__tests__": true, "__mocks__": true, "e2e": true, "cypress": true}

// jsImportRe finds the module specifier of `import x from "y"`, `import "y"`, `import("y")`,
// `export * from "y"` and `require("y")`. Line-based, like the Python scan: a multi-line
// `import {\n a,\n} from "y"` is caught on its `from` line.
var jsImportRe = regexp.MustCompile(`\b(?:from|import|require)\s*\(?\s*["']([^"']+)["']`)

// ScanJSImports walks the project's JavaScript and TypeScript for imports and requires,
// reporting the npm packages they name. Test files and build/test tool configuration
// (vite.config.js and the like) don't ship, so they land in Imports.Test. Dynamic specifiers
// built at runtime aren't seen.
func ScanJSImports(root string) (*Imports, error) {
	result := &Imports{Production: map[string]bool{}, Test: map[string]bool{}, ProductionNames: map[string]bool{}}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") || d.Name() == "coverage") {
				return filepath.SkipDir
			}

			return nil
		}

		if !jsExts[filepath.Ext(d.Name())] {
			return nil
		}

		into, names := result.Production, result.ProductionNames
		if isJSTestPath(root, path) {
			into, names = result.Test, nil
		}

		err = scanJSFile(path, into, names)
		if errors.Is(err, bufio.ErrTooLong) {
			return nil // a minified bundle: not the project's own source
		}

		return err
	})

	return result, err
}

func isJSTestPath(root, path string) bool {
	if isTestPath(root, path) {
		return true
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts[:len(parts)-1] {
		if jsTestDirs[p] {
			return true
		}
	}

	name := parts[len(parts)-1]

	for _, marker := range []string{".test.", ".spec.", ".config.", ".stories."} {
		if strings.Contains(name, marker) {
			return true
		}
	}

	stem := strings.TrimSuffix(name, filepath.Ext(name))

	return stem == "test-setup" || stem == "setupTests" || stem == "vitest.setup"
}

func scanJSFile(path string, into, names map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		for _, m := range jsImportRe.FindAllStringSubmatch(scanner.Text(), -1) {
			if pkg := npmPackageOf(m[1]); pkg != "" {
				into[pkg] = true

				if names != nil {
					names[m[1]] = true
				}
			}
		}
	}

	return scanner.Err()
}

// npmPackageOf maps a module specifier to the npm package that provides it: "react" and
// "react/jsx-runtime" are react, "@scope/kit/sub" is @scope/kit. Relative paths, absolute
// paths, URLs, node: built-ins and bare "@/" aliases are not packages ("").
func npmPackageOf(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.Contains(spec, ":") {
		return ""
	}

	parts := strings.Split(spec, "/")

	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 || parts[0] == "@" || parts[1] == "" {
			return ""
		}

		return parts[0] + "/" + parts[1]
	}

	return parts[0]
}
