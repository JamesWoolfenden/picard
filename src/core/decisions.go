package core

import (
	"fmt"
	"strings"
)

// Decisions a Decision entry can record. keep and defer settle a review flag for as long as
// the facts behind them hold; replace and remove record a decision to act, so the flag stays.
const (
	DecisionKeep    = "keep"
	DecisionDefer   = "defer"
	DecisionReplace = "replace"
	DecisionRemove  = "remove"
)

// Decision is a recorded decision about a dependency picard's surface review flagged: what
// was decided, when, why, on what evidence, and what would change it. It lives in picard.yaml
// so the decision is versioned with the code it is about.
type Decision struct {
	Dependency string `yaml:"dependency" json:"dependency"`
	Decision   string `yaml:"decision" json:"decision"`
	Date       string `yaml:"date" json:"date"`
	Reason     string `yaml:"reason" json:"reason"`
	// Evidence is where the facts behind the decision came from (a command, a PR, an issue).
	Evidence string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	// Revisit says in words what would reopen the decision.
	Revisit string `yaml:"revisit,omitempty" json:"revisit,omitempty"`
	// Baseline is the measured facts the decision was made against. If the dependency
	// later brings in more packages, or more recent high or critical advisories, than
	// this, the decision no longer matches the evidence and the flag returns.
	Baseline *Baseline `yaml:"baseline,omitempty" json:"baseline,omitempty"`
}

// Baseline is what a surface review measured when a decision was made.
type Baseline struct {
	Packages     int `yaml:"packages" json:"packages"`
	RecentSevere int `yaml:"recent_severe" json:"recent_severe"`
}

// Validate reports what is wrong with an entry that can't be used as a record.
func (a Decision) Validate() error {
	switch {
	case a.Dependency == "":
		return fmt.Errorf("decision entry has no dependency")
	case a.Date == "" || a.Reason == "":
		return fmt.Errorf("decision for %s: a decision needs a date and a reason", a.Dependency)
	}

	switch a.Decision {
	case DecisionKeep, DecisionDefer, DecisionReplace, DecisionRemove:
		return nil
	}

	return fmt.Errorf("decision for %s: %q is not keep, defer, replace or remove", a.Dependency, a.Decision)
}

// Settles is whether the decision, while current, stands in for the review flag.
func (a Decision) Settles() bool {
	return a.Decision == DecisionKeep || a.Decision == DecisionDefer
}

// Summary is the decision on one line.
func (a Decision) Summary() string {
	return fmt.Sprintf("%s (%s): %s", a.Decision, a.Date, strings.TrimSpace(a.Reason))
}

// Stale reports why the facts no longer match the decision, or "" if they do (or no baseline
// was recorded).
func (a Decision) Stale(s Surface) string {
	if a.Baseline == nil {
		return ""
	}

	var why []string

	if n := len(s.Packages); n > a.Baseline.Packages {
		why = append(why, fmt.Sprintf("now brings in %d packages, was %d", n, a.Baseline.Packages))
	}

	if n := s.Churn.Severe; n > a.Baseline.RecentSevere {
		why = append(why, fmt.Sprintf("%d recent high or critical advisories, was %d", n, a.Baseline.RecentSevere))
	}

	return strings.Join(why, "; ")
}

// matchDecision finds the decision recorded for a surface entry's dependency, or any it
// takes with it.
func matchDecision(decisions []Decision, s Surface) *Decision {
	for i := range decisions {
		if decisions[i].Dependency == s.Dependency {
			return &decisions[i]
		}
	}

	for i := range decisions {
		for _, also := range s.Also {
			if decisions[i].Dependency == also {
				return &decisions[i]
			}
		}
	}

	return nil
}
