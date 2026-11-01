package core

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// PastAdvisory is one advisory ever published against a package.
type PastAdvisory struct {
	ID        string    `json:"id"`
	Published time.Time `json:"published"`
	Severity  string    `json:"severity"`
}

// churnYears is how far back "recent" advisories go - long enough to see a pattern, short
// enough that a project's distant past doesn't count against it.
const churnYears = 3

// burstGap: advisories against one package published within this of each other are one
// event - an audit sweeping a subsystem, not a stream of separate problems.
const burstGap = 7 * 24 * time.Hour

// Churn is a dependency group's advisory record.
type Churn struct {
	// Total is every advisory ever; Recent, those in the last churnYears.
	Total  int `json:"total"`
	Recent int `json:"recent"`
	// Events are the recent ones with each package's bursts counted once; Severe, the
	// recent high or critical ones.
	Events int `json:"recent_events"`
	Severe int `json:"recent_severe"`
}

// churnOf totals the packages' advisory records as of now.
func churnOf(packages []SurfacePackage, now time.Time) Churn {
	var c Churn

	since := now.AddDate(-churnYears, 0, 0)

	for _, p := range packages {
		c.Total += len(p.History)

		var recent []time.Time

		for _, a := range p.History {
			if a.Published.Before(since) {
				continue
			}

			recent = append(recent, a.Published)
			c.Recent++

			if severityRank[a.Severity] >= severityRank["high"] {
				c.Severe++
			}
		}

		sort.Slice(recent, func(i, j int) bool { return recent[i].Before(recent[j]) })

		for i, t := range recent {
			if i == 0 || t.Sub(recent[i-1]) > burstGap {
				c.Events++
			}
		}
	}

	return c
}

// Thresholds for a dependency that costs a lot: any one is enough.
const (
	heavyPackages = 10
	heavySize     = 50e6
	heavyEvents   = 3
	heavySevere   = 2
	// lightUse: this many imported names or fewer, and no command run, is light use.
	lightUse = 5
)

// Review is a dependency worth a second look: Kind "unused" (nothing uses it) or "replace"
// (little used for what it costs), with the facts behind it.
type Review struct {
	Kind    string   `json:"kind"`
	Reasons []string `json:"reasons"`
}

// review applies the rules. A dependency that removing alone removes nothing from isn't
// reviewed - its cost belongs to what shares it. The rules flag; what to use instead is a
// judgement (the picard-triage skill's), never picard's.
func review(s Surface, historyKnown bool) *Review {
	if len(s.Packages) == 0 {
		return nil
	}

	if len(s.UsedNames) == 0 && !s.Command {
		return &Review{Kind: "unused", Reasons: []string{
			"nothing in the production code imports it or runs its commands - remove it, unless it's loaded by name " +
				"(a plugin, driver or server extra)",
		}}
	}

	if s.Command || len(s.UsedNames) > lightUse {
		return nil
	}

	var (
		costs []string
		heavy bool
	)

	if n := len(s.Packages); n >= heavyPackages {
		heavy = true
		costs = append(costs, fmt.Sprintf("alone brings in %s", plural(n, "package")))
	}

	if n := s.Native(); n > 0 {
		costs = append(costs, fmt.Sprintf("%d with native code", n))
	}

	if size, _ := s.Size(); size >= heavySize {
		heavy = true
		costs = append(costs, formatSize(s))
	}

	if historyKnown && s.Churn.Recent > 0 {
		text := fmt.Sprintf("%s in the last %d years", plural(s.Churn.Recent, "advisory"), churnYears)

		var detail []string
		if s.Churn.Events < s.Churn.Recent {
			detail = append(detail, fmt.Sprintf("%d separate %s", s.Churn.Events, verb(s.Churn.Events, "event", "events")))
		}

		if s.Churn.Severe > 0 {
			detail = append(detail, fmt.Sprintf("%d high or critical", s.Churn.Severe))
		}

		if len(detail) > 0 {
			text += " (" + strings.Join(detail, ", ") + ")"
		}

		costs = append(costs, text)
		heavy = heavy || s.Churn.Events >= heavyEvents || s.Churn.Severe >= heavySevere
	}

	if !heavy {
		return nil
	}

	use := "uses " + plural(len(s.UsedNames), "name") + " (" + strings.Join(s.UsedNames, ", ") + ")"
	if s.Called != nil {
		use += fmt.Sprintf(", %s called in the coverage run", plural(len(s.Called), "function"))
	}

	return &Review{Kind: "replace", Reasons: append([]string{use}, costs...)}
}
