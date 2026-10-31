package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"golang.org/x/vuln/scan"
)

// GoReach levels, from govulncheck's findings - how far into an advisory's vulnerable code
// the build reaches.
const (
	// GoReachCalled: a call path leads from the build's code to a vulnerable function.
	GoReachCalled = "called"
	// GoReachImported: a vulnerable package is compiled in, but nothing calls its vulnerable
	// functions.
	GoReachImported = "imported"
	// GoReachRequired: the module is required, but no vulnerable package is imported.
	GoReachRequired = "required"
	// GoReachUnreported: govulncheck ran but didn't report the advisory for this build - the
	// Go vulnerability database doesn't list it, or not for this version.
	GoReachUnreported = "unreported"
)

var goReachRank = map[string]int{GoReachCalled: 3, GoReachImported: 2, GoReachRequired: 1}

// GoReach is govulncheck's finding for one advisory, combined across goPlatforms.
type GoReach struct {
	Level string `json:"level"`
	// Trace is a call path for GoReachCalled, from the build's own code to the vulnerable
	// function; Platform, the GOOS/GOARCH it was found on.
	Trace    []string `json:"trace,omitempty"`
	Platform string   `json:"platform,omitempty"`
	// WithoutCgo are platforms analysed with cgo off because their cgo files couldn't be
	// type-checked (no C compiler for them) - code only those files reach went unseen, so a
	// "nothing calls it" resting on them isn't quite a fact.
	WithoutCgo []string `json:"without_cgo,omitempty"`
}

// Fact: govulncheck saw every platform whole, so its call graph settles the question.
func (r *GoReach) Fact() bool { return len(r.WithoutCgo) == 0 }

// goVulnCheck runs govulncheck (in process, at symbol level) on the module in dir for each
// of goPlatforms, with the standard library at goVersion, and returns the deepest finding per
// Go vulnerability id. A cgo platform whose C files can't be type-checked is analysed with cgo
// off (and the findings say so); any other failure fails the lot, since a missing platform
// could hide a call. A variable so tests can stand in for it.
var goVulnCheck = func(dir, goVersion string) (map[string]*GoReach, error) {
	type result struct {
		reach map[string]*GoReach
		noCgo bool
		err   error
	}

	results := make([]result, len(goPlatforms))

	// Each run type-checks the whole program and builds its call graph - heavy, so two at once.
	sem := make(chan struct{}, 2)

	var wg sync.WaitGroup

	for i, p := range goPlatforms {
		wg.Add(1)

		go func() {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			r := &results[i]
			platform := p[0] + "/" + p[1]

			r.reach, r.err = runGovulncheck(dir, goVersion, p[0], p[1], p[2], platform)
			if r.err != nil && p[2] == "1" && strings.Contains(r.err.Error(), "C compiler") {
				r.noCgo = true
				r.reach, r.err = runGovulncheck(dir, goVersion, p[0], p[1], "0", platform)
			}
		}()
	}

	wg.Wait()

	var (
		combined = map[string]*GoReach{}
		noCgo    []string
	)

	for i, r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("govulncheck (%s/%s cgo=%s): %w", goPlatforms[i][0], goPlatforms[i][1], goPlatforms[i][2], r.err)
		}

		if r.noCgo {
			noCgo = append(noCgo, goPlatforms[i][0]+"/"+goPlatforms[i][1])
		}

		for id, reach := range r.reach {
			if have := combined[id]; have == nil || goReachRank[reach.Level] > goReachRank[have.Level] {
				combined[id] = reach
			}
		}
	}

	// A call found is found wherever; only "not called" depends on having seen everything.
	for _, reach := range combined {
		if reach.Level != GoReachCalled {
			reach.WithoutCgo = noCgo
		}
	}

	return combined, nil
}

// runGovulncheck is one govulncheck run, for one platform.
func runGovulncheck(dir, goVersion, goos, goarch, cgo, platform string) (map[string]*GoReach, error) {
	var out, stderr bytes.Buffer

	cmd := scan.Command(context.Background(), "-json", "-C", dir, "./...")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(""), &out, &stderr
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED="+cgo)

	if goVersion != "" {
		cmd.Env = append(cmd.Env, "GOVERSION=go"+goVersion)
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return parseGovulncheck(&out, platform)
}

type govulnFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
}

// parseGovulncheck reads govulncheck's -json stream: a sequence of messages, of which only
// findings matter. A vulnerability gets one finding per level reached (module, package,
// symbol), told apart by the first frame of its trace; the deepest is kept, and for calls the
// shortest path.
func parseGovulncheck(r io.Reader, platform string) (map[string]*GoReach, error) {
	reach := map[string]*GoReach{}
	dec := json.NewDecoder(r)

	for {
		var msg struct {
			Finding *struct {
				OSV   string        `json:"osv"`
				Trace []govulnFrame `json:"trace"`
			} `json:"finding"`
		}

		if err := dec.Decode(&msg); errors.Is(err, io.EOF) {
			return reach, nil
		} else if err != nil {
			return nil, fmt.Errorf("reading govulncheck output: %w", err)
		}

		f := msg.Finding
		if f == nil || f.OSV == "" || len(f.Trace) == 0 {
			continue
		}

		found := &GoReach{Level: GoReachRequired}

		switch {
		case f.Trace[0].Function != "":
			found.Level, found.Platform = GoReachCalled, platform

			// Frames run from the vulnerable symbol out to the entry point; read the other way.
			for i := len(f.Trace) - 1; i >= 0; i-- {
				found.Trace = append(found.Trace, frameName(f.Trace[i]))
			}
		case f.Trace[0].Package != "":
			found.Level = GoReachImported
		}

		have := reach[f.OSV]
		if have == nil || goReachRank[found.Level] > goReachRank[have.Level] ||
			(found.Level == GoReachCalled && have.Level == GoReachCalled && len(found.Trace) < len(have.Trace)) {
			reach[f.OSV] = found
		}
	}
}

// frameName is a frame as Go code would write it: http.Get, tls.(*Conn).Read.
func frameName(f govulnFrame) string {
	pkg := path.Base(f.Package)

	switch {
	case strings.HasPrefix(f.Receiver, "*"):
		return pkg + ".(" + f.Receiver + ")." + f.Function
	case f.Receiver != "":
		return pkg + "." + f.Receiver + "." + f.Function
	default:
		return pkg + "." + f.Function
	}
}

// goReachFor is govulncheck's finding for an advisory, by its id or any alias (govulncheck
// uses the Go database's GO- ids; picard keeps GitHub's where both exist).
func goReachFor(a Advisory, reach map[string]*GoReach) *GoReach {
	for _, id := range append([]string{a.ID}, a.Aliases...) {
		if r := reach[id]; r != nil {
			return r
		}
	}

	return &GoReach{Level: GoReachUnreported}
}
