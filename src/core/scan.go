package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Options configures a scan.
type Options struct {
	Directory string
	// LockFile defaults to <Directory>/uv.lock.
	LockFile string
	// Coverage is an optional coverage.py JSON report (see ReadCoverage).
	Coverage string
	OSV      *OSV
}

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

	return &Report{Project: lock.Project, Findings: findings}, nil
}

// Exists reports whether a path exists - for validating flags before a scan.
func Exists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}
