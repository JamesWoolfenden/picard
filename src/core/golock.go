package core

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// EcosystemGo is OSV's name for Go modules (and the standard library, as package "stdlib").
const EcosystemGo = "Go"

// GoStdlib is the standard library as OSV names it.
const GoStdlib = "stdlib"

var (
	goDirectiveRe = regexp.MustCompile(`^go\s+(\d+\.\d+(?:\.\d+)?)`)
	goToolchainRe = regexp.MustCompile(`^toolchain\s+go(\d+\.\d+(?:\.\d+)?)`)
)

// goPlatforms are the GOOS/GOARCH/cgo combinations go list is asked about. A file can be
// compiled in only on some (build tags), so what ships is the union - never just the
// platform picard happens to run on, which could leave a vulnerable package out.
var goPlatforms = [][3]string{
	{"linux", "amd64", "1"}, {"linux", "amd64", "0"}, {"linux", "arm64", "1"},
	{"darwin", "arm64", "1"}, {"windows", "amd64", "1"},
}

// goListDeps lists what the non-test build compiles in across goPlatforms - modules and
// import paths - or an error when the go command can't tell. A variable so tests can stand
// in for it.
var goListDeps = func(dir string) (modules, packages []string, err error) {
	type result struct {
		out []byte
		err error
	}

	results := make([]result, len(goPlatforms))

	var wg sync.WaitGroup

	for i, p := range goPlatforms {
		wg.Add(1)

		go func() {
			defer wg.Done()

			cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{with .Module}}{{.Path}}{{end}}", "./...")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOOS="+p[0], "GOARCH="+p[1], "CGO_ENABLED="+p[2])

			out, err := cmd.Output()
			results[i] = result{out, err}
		}()
	}

	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			return nil, nil, fmt.Errorf("go list -deps (%s/%s): %w", goPlatforms[i][0], goPlatforms[i][1], r.err)
		}

		for _, line := range strings.Split(string(r.out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}

			packages = append(packages, fields[0])

			if len(fields) > 1 {
				modules = append(modules, fields[1])
			}
		}
	}

	return mergeNames(nil, modules), mergeNames(nil, packages), nil
}

// ReadGoMod reads a go.mod as a Lock: every required module at its version (Go's minimal
// version selection makes go.mod the build list), plus the standard library at the version
// the go or toolchain line names.
//
// go.mod has no dependency edges, so what ships comes from the source in srcDir instead:
// the modules `go list -deps ./...` compiles into the non-test build are Direct, the rest
// (test-only, tools, unused) DevDirect. Without a go command that can answer, every module
// counts as shipped.
func ReadGoMod(path, srcDir string) (*Lock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	lock := &Lock{Ecosystem: EcosystemGo, Packages: map[string]*Package{}}
	replaced := map[string][2]string{} // module -> replacement path, version ("" for a local path)

	var (
		block string
		goVer string
		tool  string
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Comments, including "// indirect": whether a module ships is decided from the source.
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		if line == "" {
			continue
		}

		if line == ")" {
			block = ""

			continue
		}

		if fields := strings.Fields(line); len(fields) == 2 && fields[1] == "(" {
			block = fields[0]

			continue
		}

		directive, rest := block, line
		if block == "" {
			directive, rest, _ = strings.Cut(line, " ")
		}

		switch directive {
		case "module":
			lock.Project = strings.Trim(strings.TrimSpace(rest), `"`)
		case "go":
			if m := goDirectiveRe.FindStringSubmatch("go " + rest); m != nil {
				goVer = m[1]
			}
		case "toolchain":
			if m := goToolchainRe.FindStringSubmatch("toolchain " + rest); m != nil {
				tool = m[1]
			}
		case "require":
			if fields := strings.Fields(rest); len(fields) >= 2 {
				lock.Packages[fields[0]] = &Package{Name: fields[0], Version: fields[1], Variants: []Variant{{Version: fields[1]}}}
			}
		case "replace":
			from, to, ok := strings.Cut(rest, "=>")
			if !ok {
				continue
			}

			src, dst := strings.Fields(from), strings.Fields(to)
			if len(src) == 0 || len(dst) == 0 {
				continue
			}

			version := ""
			if len(dst) > 1 {
				version = dst[1]
			}

			replaced[src[0]] = [2]string{dst[0], version}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	applyReplaces(lock, replaced)

	if lock.Project == "" {
		lock.Project = filepath.Base(srcDir)
	}

	// The go line is the minimum the module needs; the toolchain line, when present, what
	// it's built with. Either way the Go that actually builds it may be newer.
	if v := firstNonEmpty(tool, goVer); v != "" {
		if strings.Count(v, ".") == 1 {
			v += ".0"
		}

		lock.Packages[GoStdlib] = &Package{Name: GoStdlib, Version: v, Variants: []Variant{{Version: v}}}
	}

	all := make([]string, 0, len(lock.Packages))
	for name := range lock.Packages {
		all = append(all, name)
	}

	sort.Strings(all)

	built, packages, err := goListDeps(srcDir)
	if err != nil {
		log.Warn().Err(err).Msg("can't tell which Go modules the build compiles in - counting every required module as shipped")

		lock.Direct = all

		return lock, nil
	}

	lock.Compiled = map[string]bool{}
	for _, p := range packages {
		lock.Compiled[p] = true
	}

	compiled := map[string]bool{GoStdlib: true}
	for _, m := range built {
		compiled[m] = true
	}

	for _, name := range all {
		if compiled[name] {
			lock.Direct = append(lock.Direct, name)
		} else {
			lock.DevDirect = append(lock.DevDirect, name)
		}
	}

	return lock, nil
}

// applyReplaces swaps replaced modules for what's actually built: another module at its
// version, or - for a local directory - nothing to look up.
func applyReplaces(lock *Lock, replaced map[string][2]string) {
	for from, to := range replaced {
		pkg, ok := lock.Packages[from]
		if !ok {
			continue
		}

		delete(lock.Packages, from)

		if to[1] == "" { // a local path
			continue
		}

		pkg.Name, pkg.Version, pkg.Variants = to[0], to[1], []Variant{{Version: to[1]}}
		lock.Packages[to[0]] = pkg
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}

	return ""
}

var goImportRe = regexp.MustCompile(`^\s*(?:import\s+)?(?:[\w.]+\s+)?"([^"]+)"`)

// ScanGoImports finds the modules the project's own non-test Go code imports: each import
// path is attributed to the locked module that is its longest prefix.
func ScanGoImports(root string, lock *Lock) (map[string]bool, error) {
	modules := make([]string, 0, len(lock.Packages))
	for name := range lock.Packages {
		if name != GoStdlib {
			modules = append(modules, name)
		}
	}

	// Longest first, so golang.org/x/net/http2 beats golang.org/x/net.
	sort.Slice(modules, func(i, j int) bool { return len(modules[i]) > len(modules[j]) })

	imported := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || d.Name() == "vendor" || d.Name() == "testdata" ||
				strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		inBlock := false

		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)

			switch {
			case strings.HasPrefix(trimmed, "import ("):
				inBlock = true

				continue
			case inBlock && trimmed == ")":
				inBlock = false

				continue
			case !inBlock && !strings.HasPrefix(trimmed, "import "):
				continue
			}

			m := goImportRe.FindStringSubmatch(trimmed)
			if m == nil {
				continue
			}

			for _, mod := range modules {
				if m[1] == mod || strings.HasPrefix(m[1], mod+"/") {
					imported[mod] = true

					break
				}
			}
		}

		return nil
	})

	return imported, err
}
