package core

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

const testGoMod = `module github.com/example/tool

go 1.22

toolchain go1.22.4

require (
	github.com/urfave/cli/v2 v2.27.1
	golang.org/x/net v0.10.0 // indirect
	github.com/stretchr/testify v1.9.0
	example.com/forked v1.0.0
	example.com/local v0.0.0
)

require github.com/rs/zerolog v1.33.0

replace example.com/forked => github.com/me/forked v1.0.1

replace example.com/local => ../local
`

// stubGoList makes go list -deps answer with the given modules for the test's duration.
func stubGoList(t *testing.T, modules []string, err error) {
	t.Helper()

	saved := goListDeps
	goListDeps = func(string) ([]string, []string, error) { return modules, nil, err }

	t.Cleanup(func() { goListDeps = saved })
}

func TestReadGoMod(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"go.mod": testGoMod})

	// testify is only used by tests, so the build doesn't compile it in.
	stubGoList(t, []string{"github.com/urfave/cli/v2", "golang.org/x/net", "github.com/rs/zerolog", "github.com/me/forked"}, nil)

	lock, err := ReadGoMod(filepath.Join(dir, "go.mod"), dir)
	if err != nil {
		t.Fatal(err)
	}

	if lock.Project != "github.com/example/tool" || lock.Ecosystem != EcosystemGo {
		t.Errorf("project/ecosystem = %q/%q", lock.Project, lock.Ecosystem)
	}

	if std := lock.Packages[GoStdlib]; std == nil || std.Version != "1.22.4" {
		t.Errorf("stdlib = %+v, want the toolchain's 1.22.4", std)
	}

	if f := lock.Packages["github.com/me/forked"]; f == nil || f.Version != "v1.0.1" {
		t.Errorf("replaced module = %+v", f)
	}

	for _, gone := range []string{"example.com/forked", "example.com/local"} {
		if _, ok := lock.Packages[gone]; ok {
			t.Errorf("%s should have been replaced", gone)
		}
	}

	want := []string{"github.com/me/forked", "github.com/rs/zerolog", "github.com/urfave/cli/v2", "golang.org/x/net", GoStdlib}
	if !reflect.DeepEqual(lock.Direct, want) {
		t.Errorf("direct = %v, want %v", lock.Direct, want)
	}

	if !reflect.DeepEqual(lock.DevDirect, []string{"github.com/stretchr/testify"}) {
		t.Errorf("dev = %v", lock.DevDirect)
	}
}

// pike's x/crypto advisory: only openpgp is affected, and the build compiles in ssh and
// cast5 but not openpgp - a fact, so not-shipped. Another advisory hits a compiled package.
func TestTriageUsesWhatTheGoBuildCompilesIn(t *testing.T) {
	lock := &Lock{
		Ecosystem: EcosystemGo,
		Packages:  map[string]*Package{"golang.org/x/crypto": {Name: "golang.org/x/crypto", Version: "v0.58.0"}},
		Direct:    []string{"golang.org/x/crypto"},
		Compiled:  map[string]bool{"golang.org/x/crypto/ssh": true, "golang.org/x/crypto/cast5": true},
	}

	findings := Triage(map[string][]Advisory{"golang.org/x/crypto": {
		{ID: "GO-openpgp", AffectedPackages: []string{"golang.org/x/crypto/openpgp", "golang.org/x/crypto/openpgp/armor"}},
		{ID: "GO-ssh", AffectedPackages: []string{"golang.org/x/crypto/ssh"}},
	}}, Evidence{Lock: lock})

	verdicts := map[string]Verdict{}
	for _, a := range findings[0].Advisories {
		verdicts[a.ID] = a.Verdict
	}

	if verdicts["GO-openpgp"] != VerdictNotShipped || verdicts["GO-ssh"] != VerdictShipped {
		t.Errorf("verdicts = %v", verdicts)
	}
}

func TestReadGoModWithoutTheGoCommandShipsEverything(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"go.mod": "module m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n"})
	stubGoList(t, nil, errors.New("go: not found"))

	lock, err := ReadGoMod(filepath.Join(dir, "go.mod"), dir)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(lock.Direct, []string{"github.com/x/y", GoStdlib}) || len(lock.DevDirect) != 0 {
		t.Errorf("direct %v, dev %v", lock.Direct, lock.DevDirect)
	}

	if lock.Packages[GoStdlib].Version != "1.21.0" {
		t.Errorf("stdlib = %s, want 1.21.0", lock.Packages[GoStdlib].Version)
	}
}

func TestScanGoImports(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"main.go": `package main

import (
	"fmt"
	cli "github.com/urfave/cli/v2"
	_ "golang.org/x/net/http2"
)
`,
		"util.go":        `package main` + "\n\n" + `import "github.com/rs/zerolog/log"`,
		"main_test.go":   `package main` + "\n\n" + `import "github.com/stretchr/testify/assert"`,
		"vendor/x/x.go":  `package x` + "\n\n" + `import "never.scanned/x"`,
		"testdata/t.go":  `package t` + "\n\n" + `import "never.scanned/y"`,
		"sub/nested.go":  `package sub` + "\n\n" + `import "golang.org/x/netlike"`,
		"sub/comment.go": "package sub\n\n// import \"github.com/stretchr/testify\"\n",
	})

	lock := &Lock{Packages: map[string]*Package{}}
	for _, m := range []string{"github.com/urfave/cli/v2", "golang.org/x/net", "github.com/rs/zerolog", "github.com/stretchr/testify", GoStdlib} {
		lock.Packages[m] = &Package{Name: m}
	}

	got, err := ScanGoImports(root, lock)
	if err != nil {
		t.Fatal(err)
	}

	// golang.org/x/netlike isn't golang.org/x/net; test imports don't count.
	want := map[string]bool{"github.com/urfave/cli/v2": true, "golang.org/x/net": true, "github.com/rs/zerolog": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("imports = %v, want %v", got, want)
	}
}

func TestScanWithoutALockFileSaysWhatItReads(t *testing.T) {
	_, err := Scan(Options{Directory: t.TempDir()})

	var noLock *NoLockFileError
	if !errors.As(err, &noLock) {
		t.Fatalf("err = %v, want a NoLockFileError", err)
	}
}

// An npm project with no dependencies has an empty packages map - that's zero packages,
// not the old lock format.
func TestReadNPMLockAcceptsAnEmptyPackagesMap(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"package-lock.json": `{"name": "backend", "lockfileVersion": 3, "requires": true, "packages": {}}`,
	})

	lock, err := ReadNPMLock(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}

	if len(lock.Packages) != 0 || lock.Project != "backend" {
		t.Errorf("lock = %+v", lock)
	}
}

func TestMergeAliasesFoldsOneVulnerabilityIntoOneAdvisory(t *testing.T) {
	got := mergeAliases([]Advisory{
		{ID: "GO-2023-2102", Aliases: []string{"CVE-2023-39325", "GHSA-4374-p667-p6c8"}, Severity: "unknown", Fixed: "0.17.0"},
		{ID: "GHSA-4374-p667-p6c8", Aliases: []string{"CVE-2023-39325"}, Severity: "high", Fixed: "0.17.0", Summary: "rapid reset"},
		{ID: "GHSA-other", Severity: "low"},
	})

	if len(got) != 2 {
		t.Fatalf("got %d advisories, want 2: %+v", len(got), got)
	}

	a := got[0]
	if a.ID != "GHSA-4374-p667-p6c8" || a.Severity != "high" || a.Summary != "rapid reset" ||
		!contains(a.Aliases, "GO-2023-2102") || !contains(a.Aliases, "CVE-2023-39325") {
		t.Errorf("merged = %+v", a)
	}
}
