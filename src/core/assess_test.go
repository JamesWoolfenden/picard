package core

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMatchSymbols(t *testing.T) {
	called := []string{
		"filelock/_api.py:BaseFileLock.__init_subclass__",
		"filelock/_read_write.py:ReadWriteLock.acquire_read",
		"filelock/__init__.py:__getattr__",
		"certifi/core.py:where",
	}

	cases := map[string][]string{
		"ReadWriteLock":                {"filelock/_read_write.py:ReadWriteLock.acquire_read"},
		"filelock.ReadWriteLock":       {"filelock/_read_write.py:ReadWriteLock.acquire_read"},
		"ReadWriteLock.acquire_read()": {"filelock/_read_write.py:ReadWriteLock.acquire_read"},
		"_read_write":                  {"filelock/_read_write.py:ReadWriteLock.acquire_read"},
		"SoftFileLock":                 nil,
		"SoftFileLock.acquire":         nil,
		"where":                        {"certifi/core.py:where"},
		"BaseFile":                     nil, // a prefix of a name is not the name
	}

	for symbol, want := range cases {
		if got := MatchSymbols(called, []string{symbol}); !reflect.DeepEqual(got, want) {
			t.Errorf("MatchSymbols(%q) = %v, want %v", symbol, got, want)
		}
	}
}

type fakeAssessor map[string]*Assessment

func (f fakeAssessor) ID() string { return "fake" }

func (f fakeAssessor) Assess(_ context.Context, in AssessInput) (*Assessment, error) {
	return f[in.Advisory.ID], nil
}

func TestAssessmentsNarrowVerdictsPerAdvisory(t *testing.T) {
	findings := Triage(map[string][]Advisory{
		"locks": {
			{ID: "LOCAL-USER", Severity: "high"},
			{ID: "SOFT", Severity: "moderate"},
			{ID: "RW", Severity: "moderate"},
		},
		"certs": {{ID: "CA", Severity: "critical"}},
	}, Evidence{
		Lock: testLock(),
		Executed: map[string]*ModuleUse{
			"locks": {Loaded: true, FunctionData: true, Called: []string{"locks/_rw.py:ReadWriteLock.acquire"}},
			"certs": {Loaded: true, FunctionData: true},
		},
		Owners: map[string]string{},
	})

	assess(findings, fakeAssessor{
		"LOCAL-USER": {Affects: "code", Symbols: []string{"UnixFileLock"}, Applies: "no", Justification: "vulnerable_code_cannot_be_controlled_by_adversary", Reasoning: "needs a second local user"},
		"SOFT":       {Affects: "code", Symbols: []string{"SoftFileLock"}, Applies: "unclear"},
		"RW":         {Affects: "code", Symbols: []string{"ReadWriteLock"}, Applies: "unclear"},
		"CA":         {Affects: "data", Applies: "yes", Reasoning: "bundled CA list"},
	}, nil, nil)
	Rejudge(findings)

	got := map[string]Verdict{}
	for _, f := range findings {
		for _, a := range f.Advisories {
			got[a.ID] = a.Verdict
		}
	}

	want := map[string]Verdict{
		"LOCAL-USER": VerdictNotApplicable,
		"SOFT":       VerdictNotExecuted,
		"RW":         VerdictReachable,
		// Import-only by package evidence, but the problem is shipped data.
		"CA": VerdictReachable,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts = %v, want %v", got, want)
	}

	if byPackage(findings)["locks"].Verdict != VerdictReachable {
		t.Error("a package takes its most serious advisory's verdict")
	}
}

func TestCachedAssessorOnlyAsksOnce(t *testing.T) {
	calls := 0
	inner := countingAssessor{calls: &calls}
	cache := &CachedAssessor{Inner: inner, Path: filepath.Join(t.TempDir(), "cache.json")}
	in := AssessInput{Package: "locks", Version: "1", Advisory: Advisory{ID: "A"}}

	for i := 0; i < 2; i++ {
		if _, err := cache.Assess(context.Background(), in); err != nil {
			t.Fatal(err)
		}
	}

	// A fresh cache reads the file the first one wrote.
	reloaded := &CachedAssessor{Inner: inner, Path: cache.Path}
	if _, err := reloaded.Assess(context.Background(), in); err != nil {
		t.Fatal(err)
	}

	if calls != 1 {
		t.Errorf("inner assessor called %d times, want 1", calls)
	}

	// A different deployment is a different question.
	in.Deployment = &Deployment{Platform: "windows"}
	if _, err := cache.Assess(context.Background(), in); err != nil {
		t.Fatal(err)
	}

	if calls != 2 {
		t.Errorf("changed deployment reused a cached assessment")
	}
}

type countingAssessor struct{ calls *int }

func (c countingAssessor) ID() string { return "count" }

func (c countingAssessor) Assess(context.Context, AssessInput) (*Assessment, error) {
	*c.calls++

	return &Assessment{Affects: "code"}, nil
}

func TestDescribeDeploymentWithoutOneSaysUnknown(t *testing.T) {
	var d *Deployment
	if !strings.Contains(d.Describe(), "Unknown") {
		t.Errorf("nil deployment described as %q", d.Describe())
	}
}
