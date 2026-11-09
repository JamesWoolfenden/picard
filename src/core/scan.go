package core

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// Intel, when set, marks advisories in CISA's KEV catalog and with their EPSS score.
	Intel *Intel
}

// assessConcurrency bounds parallel assessment requests.
const assessConcurrency = 4

// Scan runs every check against a project and returns the triaged report.
func Scan(opts Options) (*Report, error) {
	lockFile := resolveLockFile(opts)
	if lockFile == "" {
		return nil, &NoLockFileError{Directory: opts.Directory}
	}

	var (
		lock     *Lock
		err      error
		imported map[string]bool
		owners   map[string]string
		executed map[string]*ModuleUse
		goReach  map[string]*GoReach
	)

	switch filepath.Base(lockFile) {
	case "go.mod":
		if opts.Coverage != "" {
			return nil, fmt.Errorf("--coverage is a coverage.py report: it doesn't apply to go.mod")
		}

		if lock, err = ReadGoMod(lockFile, opts.Directory); err != nil {
			return nil, err
		}

		if imported, err = ScanGoImports(opts.Directory, lock); err != nil {
			return nil, fmt.Errorf("scanning imports: %w", err)
		}

		goReach = runGoVulnCheck(lockFile, opts.Directory, lock)
	case "package-lock.json":
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
	default:
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
		GoReach:  goReach,
	})

	if opts.Assessor != nil {
		assess(findings, opts.Assessor, opts.Deployment, osv.Client)
		Rejudge(findings)
	}

	if opts.Intel != nil {
		if err := opts.Intel.Enrich(findings); err != nil {
			return nil, fmt.Errorf("exploitation data (--no-exploit-intel skips it): %w", err)
		}
	}

	return &Report{Project: lock.Project, Ecosystem: lock.Ecosystem, Findings: findings, Versions: lock.Versions()}, nil
}

// runGoVulnCheck is govulncheck's findings for the module, or nil when they can't be had.
// It analyses the source and its own go.mod, so only when that's the go.mod being scanned
// (not, say, a pull request's, checked against this checkout) and go list could load it.
func runGoVulnCheck(goMod, dir string, lock *Lock) map[string]*GoReach {
	modAbs, err1 := filepath.Abs(goMod)
	dirAbs, err2 := filepath.Abs(dir)

	if err1 != nil || err2 != nil || filepath.Dir(modAbs) != dirAbs || lock.Compiled == nil {
		return nil
	}

	goVersion := ""
	if std := lock.Packages[GoStdlib]; std != nil {
		goVersion = std.Version
	}

	reach, err := goVulnCheck(dir, goVersion)
	if err != nil {
		log.Warn().Err(err).Msg("govulncheck failed - Go advisories keep their package-level verdicts")

		return nil
	}

	return reach
}

// LockFiles are the files picard reads, in the order it looks for them.
var LockFiles = []string{"uv.lock", "package-lock.json", "go.mod"}

// NoLockFileError: the directory has none of the lock files picard reads.
type NoLockFileError struct{ Directory string }

func (e *NoLockFileError) Error() string {
	return fmt.Sprintf("%s has no lock file picard reads (%s)", e.Directory, strings.Join(LockFiles, ", "))
}

// resolveLockFile is the lock file to scan: the one given, else the first of LockFiles in
// the directory, else "".
func resolveLockFile(opts Options) string {
	if opts.LockFile != "" {
		return opts.LockFile
	}

	for _, name := range LockFiles {
		if path := filepath.Join(opts.Directory, name); Exists(path) {
			return path
		}
	}

	return ""
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
