package core

import (
	"reflect"
	"strings"
	"testing"
)

// A trimmed govulncheck -json stream: config and progress are ignored; GO-called is found at
// module, package and symbol level (twice, the shorter path kept), GO-imported at package
// level, GO-required at module level only.
const govulncheckStream = `{"config": {"protocol_version": "v1.0.0", "scan_level": "symbol"}}
{"progress": {"message": "Scanning your code..."}}
{"osv": {"id": "GO-called", "summary": "ignored"}}
{"finding": {"osv": "GO-called", "trace": [{"module": "stdlib", "version": "v1.27.0"}]}}
{"finding": {"osv": "GO-called", "trace": [{"module": "stdlib", "package": "net/http"}]}}
{"finding": {"osv": "GO-called", "trace": [
  {"module": "stdlib", "package": "net/http", "function": "Do", "receiver": "*Client"},
  {"module": "stdlib", "package": "net/http", "function": "Get", "receiver": "*Client"},
  {"module": "example.com/tool", "package": "example.com/tool/core", "function": "Fetch"}]}}
{"finding": {"osv": "GO-called", "trace": [
  {"module": "stdlib", "package": "net/http", "function": "Get"},
  {"module": "example.com/tool", "package": "example.com/tool/core", "function": "Fetch"}]}}
{"finding": {"osv": "GO-imported", "trace": [{"module": "stdlib", "version": "v1.27.0"}]}}
{"finding": {"osv": "GO-imported", "trace": [{"module": "stdlib", "package": "os"}]}}
{"finding": {"osv": "GO-required", "trace": [{"module": "golang.org/x/net", "version": "v0.1.0"}]}}
`

func TestParseGovulncheckKeepsTheDeepestFinding(t *testing.T) {
	got, err := parseGovulncheck(strings.NewReader(govulncheckStream), "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]*GoReach{
		"GO-called":   {Level: GoReachCalled, Trace: []string{"core.Fetch", "http.Get"}, Platform: "linux/amd64"},
		"GO-imported": {Level: GoReachImported},
		"GO-required": {Level: GoReachRequired},
	}
	if !reflect.DeepEqual(got, want) {
		for id, r := range got {
			t.Logf("%s: %+v", id, *r)
		}

		t.Errorf("want %v", want)
	}
}

func TestFrameName(t *testing.T) {
	for frame, want := range map[govulnFrame]string{
		{Package: "crypto/tls", Function: "Read", Receiver: "*Conn"}: "tls.(*Conn).Read",
		{Package: "net/http", Function: "Close", Receiver: "body"}:   "http.body.Close",
		{Package: "net/http", Function: "Get"}:                       "http.Get",
	} {
		if got := frameName(frame); got != want {
			t.Errorf("frameName(%+v) = %q, want %q", frame, got, want)
		}
	}
}

func TestCompactTrace(t *testing.T) {
	if got := compactTrace([]string{"a", "b", "c", "d", "e"}); got != "a → … → d → e" {
		t.Errorf("got %q", got)
	}

	if got := compactTrace([]string{"a", "b"}); got != "a → b" {
		t.Errorf("got %q", got)
	}
}

// govulncheck's findings outrank the package-level verdict: called is reachable, imported
// is not-executed, and an advisory it didn't report keeps "shipped" with the reason why.
// Findings are matched by alias, since picard keeps GitHub's id where both exist.
func TestTriageUsesGovulncheck(t *testing.T) {
	lock := &Lock{
		Ecosystem: EcosystemGo,
		Packages:  map[string]*Package{GoStdlib: {Name: GoStdlib, Version: "1.27.0"}},
		Direct:    []string{GoStdlib},
		Compiled:  map[string]bool{"net/http": true, "os": true},
	}

	findings := Triage(map[string][]Advisory{GoStdlib: {
		{ID: "GHSA-called", Aliases: []string{"GO-called"}, AffectedPackages: []string{"net/http"}},
		{ID: "GO-imported", AffectedPackages: []string{"os"}},
		{ID: "GO-unreported", AffectedPackages: []string{"net/http"}},
	}}, Evidence{Lock: lock, GoReach: map[string]*GoReach{
		"GO-called":   {Level: GoReachCalled, Trace: []string{"core.Fetch", "http.Get"}, Platform: "linux/amd64"},
		"GO-imported": {Level: GoReachImported},
	}})

	got := map[string]Verdict{}
	for _, a := range findings[0].Advisories {
		got[a.ID] = a.Verdict

		if a.ID == "GHSA-called" && !strings.Contains(a.Reason, "core.Fetch → http.Get") {
			t.Errorf("called reason = %q", a.Reason)
		}

		if a.ID == "GO-unreported" && !strings.Contains(a.Reason, "doesn't report it") {
			t.Errorf("unreported reason = %q", a.Reason)
		}
	}

	want := map[string]Verdict{"GHSA-called": VerdictReachable, "GO-imported": VerdictNotExecuted, "GO-unreported": VerdictShipped}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts = %v, want %v", got, want)
	}
}

// "Nothing calls it" from a complete call graph is a fact, dismissed with --apply; with a
// platform's cgo files unseen, or from a coverage run, it's judgement.
func TestDecideTreatsGovulncheckAsFact(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reach  *GoReach
		judged bool
	}{
		{"complete call graph", &GoReach{Level: GoReachImported}, false},
		{"cgo unseen", &GoReach{Level: GoReachImported, WithoutCgo: []string{"linux/amd64"}}, true},
		{"coverage run", nil, true},
	} {
		alert := Alert{}
		alert.SecurityAdvisory.GHSAID = "GHSA-x"
		alert.Dependency.Package.Ecosystem = "go"
		alert.Dependency.Package.Name = "golang.org/x/net"

		report := &Report{Ecosystem: EcosystemGo, Findings: []Finding{{
			Package: "golang.org/x/net",
			Advisories: []Advisory{{
				ID: "GHSA-x", Verdict: VerdictNotExecuted, GoReach: tc.reach,
			}},
		}}}

		if d := decide(alert, report); d.Action != ActionDismiss || d.Judged != tc.judged {
			t.Errorf("%s: action %s judged %v, want dismiss judged %v", tc.name, d.Action, d.Judged, tc.judged)
		}
	}
}
