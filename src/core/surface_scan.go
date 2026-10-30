package core

import (
	"fmt"
	"path/filepath"
	"sort"
)

// SurfaceOptions configures a surface analysis.
type SurfaceOptions struct {
	Directory string
	LockFile  string
	Coverage  string
	Target    Target
	// History looks up each package's past advisories (network).
	History bool
	OSV     *OSV
}

// AnalyzeProjectSurface runs the surface analysis against a project directory.
func AnalyzeProjectSurface(opts SurfaceOptions) (*SurfaceReport, error) {
	lockFile := opts.LockFile
	if lockFile == "" {
		lockFile = filepath.Join(opts.Directory, "uv.lock")
	}

	lock, err := ReadUVLock(lockFile)
	if err != nil {
		return nil, err
	}

	if opts.Target.Python == "" {
		opts.Target.Python = lock.MinPython
	}

	if opts.Target.Python == "" {
		return nil, fmt.Errorf("%s has no requires-python - pass --python", lockFile)
	}

	imports, err := ScanImports(opts.Directory)
	if err != nil {
		return nil, fmt.Errorf("scanning imports: %w", err)
	}

	site := FindSitePackages(opts.Directory)
	owners := ModuleOwners(site)

	var executed map[string]*ModuleUse
	if opts.Coverage != "" {
		if executed, err = ReadCoverage(opts.Coverage); err != nil {
			return nil, err
		}
	}

	var history map[string]int

	if opts.History {
		osv := opts.OSV
		if osv == nil {
			osv = NewOSV()
		}

		names := make([]string, 0, len(lock.Packages))
		for n := range lock.Closure(lock.Direct) {
			names = append(names, n)
		}

		sort.Strings(names)

		if history, err = osv.History(names); err != nil {
			return nil, err
		}
	}

	report := AnalyzeSurface(SurfaceEvidence{
		Lock:     lock,
		Imports:  imports,
		Owners:   owners,
		Commands: CommandsUsed(opts.Directory, ScriptOwners(site)),
		Executed: executed,
		History:  history,
	}, opts.Target)

	return &report, nil
}
