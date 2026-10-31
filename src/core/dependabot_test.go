package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func alertJSON(number int, pkg, ghsa, manifest string) map[string]any {
	return map[string]any{
		"number": number,
		"state":  "open",
		"dependency": map[string]any{
			"package":       map[string]string{"ecosystem": "pip", "name": pkg},
			"manifest_path": manifest,
		},
		"security_advisory": map[string]string{"ghsa_id": ghsa, "severity": "high", "summary": "s"},
	}
}

// fakeGitHub serves two pages of alerts and records dismissals.
func fakeGitHub(t *testing.T, dismissed map[string]map[string]string) *GitHub {
	t.Helper()

	var server *httptest.Server

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)

			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/o/r/dependabot/alerts?per_page=100&page=2>; rel="next"`, server.URL))
			_ = json.NewEncoder(w).Encode([]any{alertJSON(1, "locks", "GHSA-1", "uv.lock")})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]any{alertJSON(2, "web", "GHSA-2", "requirements.txt")})
		case r.Method == http.MethodPatch:
			var body map[string]string

			_ = json.NewDecoder(r.Body).Decode(&body)
			dismissed[r.URL.Path] = body
			_ = json.NewEncoder(w).Encode(map[string]any{"number": 1})
		}
	}))
	t.Cleanup(server.Close)

	return &GitHub{BaseURL: server.URL, Token: "test-token", Client: server.Client()}
}

func TestAlertsFollowsPagination(t *testing.T) {
	alerts, err := fakeGitHub(t, nil).Alerts("o/r", "open")
	if err != nil {
		t.Fatal(err)
	}

	if len(alerts) != 2 || alerts[0].Number != 1 || alerts[1].Dependency.ManifestPath != "requirements.txt" {
		t.Errorf("alerts = %+v", alerts)
	}
}

func TestDecideMapsVerdictsToDependabotReasons(t *testing.T) {
	report := &Report{Findings: []Finding{
		{Package: "locks", Advisories: []Advisory{
			{ID: "PYSEC-1", Aliases: []string{"GHSA-a"}, Verdict: VerdictNotShipped, Reason: "dev only"},
			{ID: "GHSA-b", Verdict: VerdictNotApplicable, Reason: "needs a second user"},
			{ID: "GHSA-c", Verdict: VerdictImportOnly},
			{ID: "GHSA-d", Verdict: VerdictReachable},
		}},
	}}

	alert := func(ghsa string) Alert {
		var a Alert
		a.Dependency.Package.Name = "Locks" // PyPI names compare normalized
		a.SecurityAdvisory.GHSAID = ghsa

		return a
	}

	cases := map[string][3]any{
		"GHSA-a": {ActionDismiss, "not_used", false}, // matched through an alias
		"GHSA-b": {ActionDismiss, "tolerable_risk", true},
		"GHSA-c": {ActionDismiss, "not_used", true},
		"GHSA-d": {ActionKeepOpen, "", false},
		"GHSA-z": {ActionSkip, "", false},
	}

	for ghsa, want := range cases {
		d := decide(alert(ghsa), report)
		if d.Action != want[0] || d.DismissReason != want[1] || d.Judged != want[2] {
			t.Errorf("%s: %s/%s judged=%v, want %v", ghsa, d.Action, d.DismissReason, d.Judged, want)
		}
	}
}

func TestApplyOnlyDismissesJudgedVerdictsWhenAsked(t *testing.T) {
	dismissed := map[string]map[string]string{}
	gh := fakeGitHub(t, dismissed)

	decisions := []AlertDecision{
		{Alert: Alert{Number: 1}, Action: ActionDismiss, DismissReason: "not_used", Verdict: VerdictNotShipped, Reason: strings.Repeat("x", 400)},
		{Alert: Alert{Number: 2}, Action: ActionDismiss, DismissReason: "tolerable_risk", Judged: true},
		{Alert: Alert{Number: 3}, Action: ActionKeepOpen},
	}

	if err := ApplyDecisions(gh, "o/r", decisions, false); err != nil {
		t.Fatal(err)
	}

	if len(dismissed) != 1 || !decisions[0].Applied || decisions[1].Applied {
		t.Fatalf("dismissed %v, decisions %+v", dismissed, decisions)
	}

	body := dismissed["/repos/o/r/dependabot/alerts/1"]
	if body["state"] != "dismissed" || body["dismissed_reason"] != "not_used" || len(body["dismissed_comment"]) != 280 {
		t.Errorf("dismissal body = %v (comment %d chars)", body, len(body["dismissed_comment"]))
	}

	if err := ApplyDecisions(gh, "o/r", decisions, true); err != nil {
		t.Fatal(err)
	}

	if _, ok := dismissed["/repos/o/r/dependabot/alerts/2"]; !ok {
		t.Error("judged alert not dismissed with --apply-judged")
	}
}

func TestLockForManifest(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "ui", "package-lock.json"), "{}")

	cases := map[string]string{
		"uv.lock":                     filepath.Join(root, "uv.lock"),
		"editors/x/package-lock.json": filepath.Join(root, "editors", "x", "package-lock.json"),
		"ui/package.json":             filepath.Join(root, "ui", "package-lock.json"),
		"pyproject.toml":              "", // no uv.lock beside it
		"go.sum":                      "",
	}

	for manifest, want := range cases {
		if got := lockForManifest(root, manifest); got != want {
			t.Errorf("lockForManifest(%q) = %q, want %q", manifest, got, want)
		}
	}
}

func TestRepoFromRemote(t *testing.T) {
	for remote, want := range map[string]string{
		"https://github.com/JamesWoolfenden/pan.git": "JamesWoolfenden/pan",
		"git@github.com:JamesWoolfenden/ghat.git":    "JamesWoolfenden/ghat",
		"https://github.com/o/r":                     "o/r",
	} {
		if m := remoteRe.FindStringSubmatch(remote); m == nil || m[1] != want {
			t.Errorf("%s -> %v, want %s", remote, m, want)
		}
	}
}
