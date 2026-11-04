package core

import (
	"fmt"
	"os"
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
	// Decisions are recorded in picard.yaml.
	Decisions []Decision
}

// AnalyzeProjectSurface runs the surface analysis against a project directory.
func AnalyzeProjectSurface(opts SurfaceOptions) (*SurfaceReport, error) {
	lockFile := opts.LockFile
	if lockFile == "" {
		lockFile = filepath.Join(opts.Directory, "uv.lock")

		// uv.lock first, then whichever of the other locks the directory has.
		for _, name := range []string{"package-lock.json", "go.mod"} {
			if _, err := os.Stat(lockFile); err == nil {
				break
			}

			if _, err := os.Stat(filepath.Join(opts.Directory, name)); err == nil {
				lockFile = filepath.Join(opts.Directory, name)
			}
		}
	}

	switch filepath.Base(lockFile) {
	case "go.mod":
		return analyzeGoSurface(lockFile, opts)
	case "package-lock.json":
		return analyzeNPMSurface(lockFile, opts)
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

	var history map[string][]PastAdvisory

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

		if history, err = osv.History(EcosystemPyPI, names); err != nil {
			return nil, err
		}
	}

	report := AnalyzeSurface(SurfaceEvidence{
		Lock:      lock,
		Imports:   imports,
		Owners:    owners,
		Commands:  CommandsUsed(opts.Directory, ScriptOwners(site)),
		Executed:  executed,
		History:   history,
		Decisions: opts.Decisions,
	}, opts.Target)

	return &report, nil
}

// analyzeGoSurface is AnalyzeProjectSurface for a go.mod: the modules the project's own
// code imports are its direct dependencies, and the edges between modules come from go
// list, since go.mod records none.
func analyzeGoSurface(lockFile string, opts SurfaceOptions) (*SurfaceReport, error) {
	if opts.Coverage != "" {
		return nil, fmt.Errorf("--coverage is a coverage.py report: it doesn't apply to go.mod")
	}

	lock, err := ReadGoMod(lockFile, opts.Directory)
	if err != nil {
		return nil, err
	}

	edges, err := goModuleEdges(opts.Directory)
	if err != nil {
		return nil, fmt.Errorf("can't build the module graph: %w", err)
	}

	ApplyGoEdges(lock, edges)

	used, err := ScanGoImportPaths(opts.Directory, lock)
	if err != nil {
		return nil, fmt.Errorf("scanning imports: %w", err)
	}

	// Direct: what the production code imports itself and the build compiles in.
	compiled := map[string]bool{}
	for _, m := range lock.Direct {
		compiled[m] = true
	}

	lock.Direct = nil

	for m := range used {
		if compiled[m] {
			lock.Direct = append(lock.Direct, m)
		}
	}

	sort.Strings(lock.Direct)

	var history map[string][]PastAdvisory

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

		if history, err = osv.History(EcosystemGo, names); err != nil {
			return nil, err
		}
	}

	report := AnalyzeSurface(SurfaceEvidence{Lock: lock, UsedBy: used, History: history, Decisions: opts.Decisions}, opts.Target)

	return &report, nil
}

// analyzeNPMSurface is AnalyzeProjectSurface for a package-lock.json. The lock records the
// edges and the project's own runtime dependencies, so only the imports are scanned.
func analyzeNPMSurface(lockFile string, opts SurfaceOptions) (*SurfaceReport, error) {
	if opts.Coverage != "" {
		return nil, fmt.Errorf("--coverage is a coverage.py report: it doesn't apply to an npm lock")
	}

	lock, err := ReadNPMLock(lockFile)
	if err != nil {
		return nil, err
	}

	imports, err := ScanJSImports(opts.Directory)
	if err != nil {
		return nil, fmt.Errorf("scanning imports: %w", err)
	}

	used := map[string][]string{}

	for spec := range imports.ProductionNames {
		pkg := npmPackageOf(spec)
		used[pkg] = append(used[pkg], spec)
	}

	var history map[string][]PastAdvisory

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

		if history, err = osv.History(EcosystemNPM, names); err != nil {
			return nil, err
		}
	}

	report := AnalyzeSurface(SurfaceEvidence{Lock: lock, UsedBy: used, History: history, Decisions: opts.Decisions}, opts.Target)

	return &report, nil
}
