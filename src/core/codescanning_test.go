package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdvisoryIDs(t *testing.T) {
	got := advisoryIDs("Project is vulnerable to: GO-2026-5932\nGHSA-abcd-1234-wxyz (CVE-2026-0001), GO-2026-5932")
	want := []string{"GO-2026-5932", "GHSA-abcd-1234-wxyz", "CVE-2026-0001"}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("advisoryIDs = %v, want %v", got, want)
	}
}

func scorecardAlert(msg string) CodeScanningAlert {
	var a CodeScanningAlert

	a.Number = 28
	a.MostRecentInstance.Message.Text = msg

	return a
}

// sato's alert #28: GO-2026-5932 is judged not-shipped, so the alert is a false positive.
func TestDecideScorecard(t *testing.T) {
	report := &Report{Ecosystem: "Go", Findings: []Finding{
		{Package: "golang.org/x/crypto", Version: "v0.30.0", Advisories: []Advisory{
			{ID: "GO-2026-5932", Verdict: VerdictNotShipped, Reason: "openpgp isn't compiled in"},
		}},
		{Package: "example.com/shipped", Version: "v1.0.0", Advisories: []Advisory{
			{ID: "GHSA-aaaa-bbbb-cccc", Verdict: VerdictShipped, Fixed: "v1.0.1", Reason: "compiled in"},
		}},
	}}

	d := decideScorecard(scorecardAlert("Project is vulnerable to: GO-2026-5932"), report, nil)
	if d.Action != ActionDismiss || d.DismissReason != "false positive" || d.Judged {
		t.Errorf("not-shipped alert: %+v", d)
	}

	// One reached advisory keeps the whole alert open, with the upgrade named.
	d = decideScorecard(scorecardAlert("vulnerable to: GO-2026-5932 GHSA-aaaa-bbbb-cccc"), report, nil)
	if d.Action != ActionKeepOpen || !strings.Contains(d.Reason, "upgrade example.com/shipped to v1.0.1") {
		t.Errorf("mixed alert: %+v", d)
	}

	// An advisory picard has no finding for can't be dismissed on its say-so.
	d = decideScorecard(scorecardAlert("vulnerable to: GO-2026-0000"), report, nil)
	if d.Action != ActionKeepOpen {
		t.Errorf("unknown advisory: %+v", d)
	}

	if d := decideScorecard(scorecardAlert("no ids"), report, nil); d.Action != ActionSkip {
		t.Errorf("no ids: %+v", d)
	}
}

func TestPlanAndApplyScorecard(t *testing.T) {
	var dismissed []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/o/r/code-scanning/alerts" && r.Method == http.MethodGet:
			if r.URL.Query().Get("tool_name") != "Scorecard" {
				t.Errorf("query = %s", r.URL.RawQuery)
			}

			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"number": 1, "tool": map[string]string{"name": "Scorecard"}, "rule": map[string]string{"id": "PinnedDependenciesID"}},
				{"number": 2, "tool": map[string]string{"name": "CodeQL"}, "rule": map[string]string{"id": "VulnerabilitiesID"}},
				{"number": 28, "tool": map[string]string{"name": "Scorecard"}, "rule": map[string]string{"id": "VulnerabilitiesID"}},
			})
		case r.Method == http.MethodPatch:
			var body map[string]string

			_ = json.NewDecoder(r.Body).Decode(&body)
			dismissed = append(dismissed, r.URL.Path+" "+body["dismissed_reason"])
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	gh := &GitHub{BaseURL: server.URL, Client: server.Client()}

	alerts, err := gh.ScorecardAlerts("o/r")
	if err != nil || len(alerts) != 1 || alerts[0].Number != 28 {
		t.Fatalf("alerts = %+v, err %v", alerts, err)
	}

	plan := &ScorecardPlan{Decisions: []ScorecardDecision{
		{Alert: alerts[0], Action: ActionDismiss, DismissReason: "false positive", Reason: "x"},
		{Alert: CodeScanningAlert{Number: 29}, Action: ActionDismiss, DismissReason: "won't fix", Judged: true},
		{Alert: CodeScanningAlert{Number: 30}, Action: ActionKeepOpen},
	}}

	if err := ApplyScorecard(gh, "o/r", plan, false); err != nil {
		t.Fatal(err)
	}

	if len(dismissed) != 1 || dismissed[0] != "/repos/o/r/code-scanning/alerts/28 false positive" || !plan.Decisions[0].Applied {
		t.Errorf("dismissed = %v", dismissed)
	}
}

func TestPlanScorecardNoAccess(t *testing.T) {
	for status, wantNote := range map[int]bool{http.StatusNotFound: false, http.StatusForbidden: true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"nope"}`))
		}))

		plan, err := PlanScorecard(&GitHub{BaseURL: server.URL, Client: server.Client()}, DependabotOptions{Repo: "o/r"})
		server.Close()

		if err != nil || plan == nil || len(plan.Decisions) != 0 || (plan.Note != "") != wantNote {
			t.Errorf("status %d: plan %+v, err %v", status, plan, err)
		}
	}
}
