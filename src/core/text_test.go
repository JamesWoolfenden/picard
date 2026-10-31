package core

import (
	"bytes"
	"strings"
	"testing"
)

func TestNumberRanges(t *testing.T) {
	got := numberRanges([]int{20, 3, 4, 5, 6, 7, 8, 9, 2, 12, 13, 15})
	if want := "#2-9, #12, #13, #15, #20"; got != want {
		t.Errorf("numberRanges = %q, want %q", got, want)
	}
}

func TestWrapCollapsesWhitespaceAndIndents(t *testing.T) {
	got := wrap("one two\n  three four five", "  ", 12)
	if want := "  one two\n  three four\n  five\n"; got != want {
		t.Errorf("wrap = %q, want %q", got, want)
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{1: "1 advisory", 2: "2 advisories"} {
		if got := plural(n, "advisory"); got != want {
			t.Errorf("plural(%d) = %q, want %q", n, got, want)
		}
	}
}

func decision(n int, pkg, sev string, v Verdict, action string, judged bool, reason string) AlertDecision {
	d := AlertDecision{Verdict: v, Action: action, Judged: judged, Reason: reason}
	if action == ActionDismiss {
		d.DismissReason = "tolerable_risk"
	}

	d.Alert.Number = n
	d.Alert.Dependency.Package.Name = pkg
	d.Alert.Dependency.ManifestPath = "uv.lock"
	d.Alert.SecurityAdvisory.Severity = sev
	d.Alert.SecurityAdvisory.GHSAID = "GHSA-" + pkg

	return d
}

// One row per package and proposal, keep-open first, a reason shared by every alert said
// once, and the next step spelled out.
func TestWriteDecisionsGroupsAlerts(t *testing.T) {
	var decisions []AlertDecision
	for _, n := range []int{3, 4, 5, 7} {
		decisions = append(decisions, decision(n, "filelock", "medium", VerdictNotApplicable, ActionDismiss, true, "single user"))
	}

	decisions = append(decisions, decision(9, "certifi", "critical", VerdictReachable, ActionKeepOpen, false, "CA data"))

	var b bytes.Buffer
	if err := WriteDecisions(&b, "o/r", decisions); err != nil {
		t.Fatal(err)
	}

	out := b.String()

	for _, want := range []string{
		"o/r: 5 alerts on 2 packages in uv.lock - 1 to keep open, 4 to dismiss on judgement",
		"#3-5, #7 (4)",
		"--apply-judged dismisses 4 alerts",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	if strings.Index(out, "certifi") > strings.Index(out, "filelock") {
		t.Errorf("the alert to keep open should come first:\n%s", out)
	}

	if n := strings.Count(out, "single user"); n != 1 {
		t.Errorf("shared reason written %d times, want once:\n%s", n, out)
	}
}
