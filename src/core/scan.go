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
	// LockFile defaults to <Directory>/uv.lock.
	LockFile string
	// Coverage is an optional coverage.py JSON report (see ReadCoverage).
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
	lockFile := opts.LockFile
	if lockFile == "" {
		lockFile = filepath.Join(opts.Directory, "uv.lock")
	}

	lock, err := ReadUVLock(lockFile)
	if err != nil {
		return nil, err
	}

	imports, err := ScanImports(opts.Directory)
	if err != nil {
		return nil, fmt.Errorf("scanning imports: %w", err)
	}

	owners := ModuleOwners(FindSitePackages(opts.Directory))

	var executed map[string]*ModuleUse
	if opts.Coverage != "" {
		if executed, err = ReadCoverage(opts.Coverage); err != nil {
			return nil, err
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

	advisories, err := osv.Query(packages)
	if err != nil {
		return nil, err
	}

	findings := Triage(advisories, Evidence{
		Lock:     lock,
		Imported: PackagesForModules(imports.Production, owners),
		Executed: executed,
		Owners:   owners,
	})

	if opts.Assessor != nil {
		assess(findings, opts.Assessor, opts.Deployment, osv.Client)
		Rejudge(findings)
	}

	return &Report{Project: lock.Project, Findings: findings}, nil
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
