package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Assessment is what reading an advisory (and its fix) says it's about, and whether this
// deployment meets its preconditions.
type Assessment struct {
	// Affects: "code" (specific functions), "data" (something the package ships, e.g. a
	// CA bundle - affected wherever the package is used), "install" (only while installing
	// or building packages) or "unclear".
	Affects string `json:"affects"`
	// Symbols are the package's affected functions/classes/modules, as dotted names
	// relative to the package ("ReadWriteLock.acquire", "_read_write").
	Symbols []string `json:"affected_symbols"`
	// Preconditions are what an attacker needs, e.g. "another local user on the host".
	Preconditions []string `json:"preconditions"`
	// Applies: whether this deployment meets the preconditions - "yes", "no" or "unclear".
	Applies string `json:"applies"`
	// Justification is the OpenVEX not_affected justification when Applies is "no".
	Justification string `json:"justification"`
	Reasoning     string `json:"reasoning"`
	Confidence    string `json:"confidence"`
}

// AssessInput is everything given to an assessor about one advisory.
type AssessInput struct {
	Package    string
	Version    string
	Advisory   Advisory
	FixPatch   string
	Deployment *Deployment
	// Evidence summarizes what's already known about the package's use.
	Evidence string
}

// Assessor reads advisories. The Claude implementation is in claude.go.
type Assessor interface {
	Assess(ctx context.Context, in AssessInput) (*Assessment, error)
	// ID identifies the assessor (model), for the cache key.
	ID() string
}

// CachedAssessor remembers assessments on disk, keyed by advisory, package version,
// deployment and model - an advisory is only ever assessed once per setup.
type CachedAssessor struct {
	Inner Assessor
	Path  string

	mu      sync.Mutex
	entries map[string]*Assessment
}

// DefaultCachePath is the per-user assessment cache.
func DefaultCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}

	return filepath.Join(dir, "picard", "assessments.json")
}

func (c *CachedAssessor) key(in AssessInput) string {
	return strings.Join([]string{in.Advisory.ID, in.Package, in.Version, in.Deployment.Hash(), c.Inner.ID()}, "|")
}

// ID is the inner assessor's.
func (c *CachedAssessor) ID() string { return c.Inner.ID() }

// Assess returns the cached assessment, or asks the inner assessor and saves the answer.
func (c *CachedAssessor) Assess(ctx context.Context, in AssessInput) (*Assessment, error) {
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*Assessment{}
		if data, err := os.ReadFile(c.Path); err == nil {
			_ = json.Unmarshal(data, &c.entries)
		}
	}

	if a, ok := c.entries[c.key(in)]; ok {
		c.mu.Unlock()

		return a, nil
	}
	c.mu.Unlock()

	a, err := c.Inner.Assess(ctx, in)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[c.key(in)] = a

	data, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return a, nil
	}

	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err == nil {
		_ = os.WriteFile(c.Path, data, 0o600)
	}

	return a, nil
}

// MatchSymbols returns the called functions (coverage's "path/file.py:Class.method") that
// fall within any affected symbol - a function, a class (any of its methods), or a module
// (any function in it).
func MatchSymbols(called []string, symbols []string) []string {
	var matches []string

	for _, c := range called {
		file, qualname, _ := strings.Cut(c, ":")
		module := strings.ReplaceAll(strings.TrimSuffix(strings.TrimSuffix(file, ".py"), "/__init__"), "/", ".")

		for _, s := range symbols {
			if symbolCovers(s, module, qualname) {
				matches = append(matches, c)

				break
			}
		}
	}

	return matches
}

// symbolCovers: the symbol appears as a whole run of dotted segments in the called
// function's full name (module.Class.method) - so a function, its class, or its module all
// cover it. Advisories often name the public path ("filelock.ReadWriteLock") rather than
// the defining module ("filelock._read_write.ReadWriteLock"), so a leading top-level
// package name is also tried without. Over-matching (a bare "acquire" covers every
// acquire) errs towards reporting reachable, never the reverse.
func symbolCovers(symbol, module, qualname string) bool {
	symbol = strings.Trim(strings.TrimSpace(strings.TrimSuffix(symbol, "()")), ".")
	if symbol == "" {
		return false
	}

	full := "." + module + "." + qualname + "."
	if strings.Contains(full, "."+symbol+".") {
		return true
	}

	top, rest, found := strings.Cut(symbol, ".")
	if found && strings.HasPrefix(module, top) {
		return strings.Contains(full, "."+rest+".")
	}

	return false
}

// describeEvidence summarizes a finding's evidence for an assessment prompt.
func describeEvidence(f Finding) string {
	var b strings.Builder

	switch {
	case f.Bundled:
		fmt.Fprintf(&b, "Declared only as a dev dependency, but %s bundles it: the code's imports reach it via %s.\n",
			f.Bundler, strings.Join(f.Via, " -> "))
	case f.Shipped:
		fmt.Fprintf(&b, "Shipped in the production install, pulled in via %s.\n", f.chain(" -> "))
	default:
		fmt.Fprintf(&b, "Not shipped - only dev/test dependencies pull it in (%s).\n", strings.Join(f.Via, " -> "))
	}

	if f.DirectImport {
		b.WriteString("The project's own code imports it directly.\n")
	}

	switch f.Executed {
	case UseUnknown:
		b.WriteString("No coverage data - unknown which of its code runs.\n")
	case UseNo:
		b.WriteString("None of its code ran in the measured coverage run.\n")
	default:
		if len(f.Called) == 0 {
			b.WriteString("Imported in the coverage run, but none of its functions were called.\n")
		} else {
			fmt.Fprintf(&b, "Functions called in the coverage run: %s\n", strings.Join(firstN(f.Called, 40), ", "))
		}
	}

	return b.String()
}
