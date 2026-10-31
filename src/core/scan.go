package core

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/rs/zerolog/log"
)

// Options configures a scan.
type Options struct {
	Directory string
	// LockFile defaults to <Directory>/uv.lock, or <Directory>/package-lock.json when there
	// is no uv.lock. A file named package-lock.json is read as an npm lock, anything else as
	// a uv.lock.
	LockFile string
	// Coverage is an optional coverage.py JSON report (see ReadCoverage). Python only.
	Coverage string
	OSV      *OSV
	// Assessor, when set, reads each shipped package's advisories (see assess.go);
	// Deployment is what they're checked against.
	Assessor   Assessor
	Deployment *Deployment
}

// assessConcurrency bounds parallel assessment requests.
const assessConcurrency = 4

// Scan runs every check against a project and returns the triaged report.
func Scan(opts Options) (*Report, error) {
	lockFile := resolveLockFile(opts)

	var (
		lock     *Lock
		err      error
		imported map[string]bool
		owners   map[string]string
		executed map[string]*ModuleUse
	)

	if filepath.Base(lockFile) == "package-lock.json" {
		if opts.Coverage != "" {
			return nil, fmt.Errorf("--coverage is a coverage.py report: it doesn't apply to an npm lock")
		}

		if lock, err = ReadNPMLock(lockFile); err != nil {
			return nil, err
		}

		imports, err := ScanJSImports(opts.Directory)
		if err != nil {
			return nil, fmt.Errorf("scanning imports: %w", err)
		}

		imported = imports.Production
	} else {
		if lock, err = ReadUVLock(lockFile); err != nil {
			return nil, err
		}

		imports, err := ScanImports(opts.Directory)
		if err != nil {
			return nil, fmt.Errorf("scanning imports: %w", err)
		}

		owners = ModuleOwners(FindSitePackages(opts.Directory))
		imported = PackagesForModules(imports.Production, owners)

		if opts.Coverage != "" {
			if executed, err = ReadCoverage(opts.Coverage); err != nil {
				return nil, err
			}
		}
	}

	packages := make([]*Package, 0, len(lock.Packages))
	for _, p := range lock.Packages {
		packages = append(packages, p)
	}

	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })

	osv := opts.OSV
	if osv == nil {
		osv = NewOSV()
	}

	advisories, err := osv.Query(lock.Ecosystem, packages)
	if err != nil {
		return nil, err
	}

	findings := Triage(advisories, Evidence{
		Lock:     lock,
		Imported: imported,
		Executed: executed,
		Owners:   owners,
	})

	if opts.Assessor != nil {
		assess(findings, opts.Assessor, opts.Deployment, osv.Client)
		Rejudge(findings)
	}

	return &Report{Project: lock.Project, Ecosystem: lock.Ecosystem, Findings: findings}, nil
}

// resolveLockFile is the lock file to scan: the one given, else uv.lock, else (for a
// JavaScript project) package-lock.json. uv.lock is the default when neither exists, so the
// error names it.
func resolveLockFile(opts Options) string {
	if opts.LockFile != "" {
		return opts.LockFile
	}

	uv := filepath.Join(opts.Directory, "uv.lock")
	npm := filepath.Join(opts.Directory, "package-lock.json")

	if !Exists(uv) && Exists(npm) {
		return npm
	}

	return uv
}

// assess attaches an assessment to every advisory of every shipped package - those not
// shipped need no reading. A failed assessment is logged and left out: that advisory keeps
// its package-level verdict rather than a guessed one.
func assess(findings []Finding, assessor Assessor, deployment *Deployment, client *http.Client) {
	var wg sync.WaitGroup

	sem := make(chan struct{}, assessConcurrency)

	for i := range findings {
		f := &findings[i]
		if !f.Shipped {
			continue
		}

		evidence := describeEvidence(*f)

		for j := range f.Advisories {
			a := &f.Advisories[j]

			wg.Add(1)

			go func() {
				defer wg.Done()

				sem <- struct{}{}
				defer func() { <-sem }()

				result, err := assessor.Assess(context.Background(), AssessInput{
					Package:    f.Package,
					Version:    f.Version,
					Advisory:   *a,
					FixPatch:   FetchFixPatch(client, a.FixRefs),
					Deployment: deployment,
					Evidence:   evidence,
				})
				if err != nil {
					log.Warn().Err(err).Str("package", f.Package).Msg("advisory left unassessed")

					return
				}

				a.Assessment = result
			}()
		}
	}

	wg.Wait()
}

// Exists reports whether a path exists - for validating flags before a scan.
func Exists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}
