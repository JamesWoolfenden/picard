package core

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// Report is a whole scan's result.
type Report struct {
	Project string `json:"project"`
	// Ecosystem is the registry the packages come from (PyPI or npm); empty means PyPI.
	Ecosystem string    `json:"ecosystem,omitempty"`
	Findings  []Finding `json:"findings"`
}

// purl is the package URL for a package in the report's ecosystem, with the version when
// one is given. Scoped npm names carry their "@" percent-encoded.
func (r Report) purl(name, version string) string {
	kind := "pypi"
	if r.Ecosystem == EcosystemNPM {
		kind = "npm"
		name = strings.Replace(name, "@", "%40", 1)
	}

	if version == "" {
		return "pkg:" + kind + "/" + name
	}

	return "pkg:" + kind + "/" + name + "@" + version
}

// AlertCount is the number of advisories - what Dependabot would show as separate alerts.
func (r Report) AlertCount() int {
	n := 0
	for _, f := range r.Findings {
		n += len(f.Advisories)
	}

	return n
}

// WriteTable writes the human-readable summary: one line per fix, then the reasoning.
func (r Report) WriteTable(w io.Writer) error {
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintf(w, "%s: no known advisories against locked packages\n", r.Project)

		return err
	}

	fmt.Fprintf(w, "%s: %d advisories across %d packages - %d upgrade(s) fix all of them\n\n",
		r.Project, r.AlertCount(), len(r.Findings), len(r.Findings))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERDICT\tPACKAGE\tVERSION\tFIX\tSEVERITY\tALERTS\tIMPORTED\tEXECUTED")

	for _, f := range r.Findings {
		fix := f.FixVersion
		if fix == "" {
			fix = "none"
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", f.Verdict, f.Package, f.Version, fix,
			f.Severity, len(f.Advisories), yesNo(f.DirectImport), f.Executed)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n%s %s: %s\n", f.Package, f.Version, f.Reason)

		if len(f.Advisories) > 1 {
			fmt.Fprintf(w, "  %d advisories: %s\n", len(f.Advisories), verdictCounts(f.Advisories))
		}

		// The advisories that still need acting on, individually.
		for _, a := range f.Advisories {
			if verdictRank(a.Verdict) < verdictRank(VerdictShipped) || len(f.Advisories) == 1 {
				continue
			}

			fmt.Fprintf(w, "  - %s (%s) %s: %s\n", a.ID, a.Severity, a.Verdict, a.Reason)
		}
	}

	return nil
}

func verdictCounts(advs []Advisory) string {
	counts := map[Verdict]int{}
	for _, a := range advs {
		counts[a.Verdict]++
	}

	verdicts := make([]Verdict, 0, len(counts))
	for v := range counts {
		verdicts = append(verdicts, v)
	}

	sort.Slice(verdicts, func(i, j int) bool { return verdictRank(verdicts[i]) > verdictRank(verdicts[j]) })

	parts := make([]string, len(verdicts))
	for i, v := range verdicts {
		parts[i] = fmt.Sprintf("%d %s", counts[v], v)
	}

	return strings.Join(parts, ", ")
}

func yesNo(b bool) string {
	if b {
		return "direct"
	}

	return "no"
}

// WriteJSON writes the full report as JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(r)
}

type vexDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability   vexVulnerability `json:"vulnerability"`
	Products        []vexProduct     `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
}

type vexVulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type vexProduct struct {
	ID            string       `json:"@id"`
	Subcomponents []vexProduct `json:"subcomponents,omitempty"`
}

// WriteVEX writes an OpenVEX document (https://openvex.dev) with one statement per
// advisory - picard's proposed status for each, to review and commit alongside the project
// so the decision is recorded in a format other scanners understand.
func (r Report) WriteVEX(w io.Writer, now time.Time) error {
	doc := vexDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        fmt.Sprintf("urn:picard:%s:%d", r.Project, now.Unix()),
		Author:    "picard",
		Timestamp: now.UTC().Format(time.RFC3339),
		Version:   1,
	}

	for _, f := range r.Findings {
		product := vexProduct{
			ID:            r.purl(r.Project, ""),
			Subcomponents: []vexProduct{{ID: r.purl(f.Package, f.Version)}},
		}

		for _, a := range f.Advisories {
			s := vexStatement{
				Vulnerability:   vexVulnerability{Name: a.ID, Aliases: a.Aliases},
				Products:        []vexProduct{product},
				ImpactStatement: "picard: " + a.Reason,
			}

			switch a.Verdict {
			case VerdictNotShipped:
				s.Status, s.Justification = "not_affected", "component_not_present"
			case VerdictNotApplicable:
				s.Status, s.Justification = "not_affected", "vulnerable_code_cannot_be_controlled_by_adversary"
				if a.Assessment != nil && a.Assessment.Justification != "" {
					s.Justification = a.Assessment.Justification
				}
			case VerdictNotExecuted, VerdictImportOnly:
				s.Status, s.Justification = "not_affected", "vulnerable_code_not_in_execute_path"
			case VerdictReachable:
				s.Status = "affected"
				s.ImpactStatement = ""
				s.ActionStatement = upgradeAction(f)
			default:
				s.Status = "under_investigation"
			}

			doc.Statements = append(doc.Statements, s)
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(doc)
}

func upgradeAction(f Finding) string {
	if f.FixVersion == "" {
		return "no fixed version published yet - " + f.Reason
	}

	return fmt.Sprintf("upgrade %s to %s or later", f.Package, f.FixVersion)
}
