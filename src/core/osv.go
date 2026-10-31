package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultOSVURL is the public OSV API - the same advisory data GitHub's Dependabot alerts
// come from (GHSA), plus PyPI's own.
const DefaultOSVURL = "https://api.osv.dev"

// Advisory is one vulnerability affecting a locked package version.
type Advisory struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary"`
	Details  string   `json:"-"`
	Severity string   `json:"severity"`
	// Fixed is the lowest version that fixes this advisory above the locked one, or "".
	Fixed string `json:"fixed,omitempty"`
	// FixRefs are the advisory's FIX references - usually the commit or pull request.
	FixRefs []string `json:"fix_refs,omitempty"`
	// AffectedPackages are the import paths the advisory names as vulnerable (Go advisories
	// do); Compiled, those the build compiles in, when CompiledKnown.
	AffectedPackages []string `json:"affected_packages,omitempty"`
	Compiled         []string `json:"compiled,omitempty"`
	CompiledKnown    bool     `json:"compiled_known,omitempty"`
	// GoReach is what govulncheck's call graph says about it, when govulncheck ran.
	GoReach *GoReach `json:"go_reach,omitempty"`
	// Assessment, Verdict and Reason are this advisory's own triage (see Triage); the
	// Finding carries the package-level summary.
	Assessment *Assessment `json:"assessment,omitempty"`
	Verdict    Verdict     `json:"verdict,omitempty"`
	Reason     string      `json:"reason,omitempty"`
}

// OSV is a minimal client for the batch query and per-vulnerability endpoints.
type OSV struct {
	BaseURL string
	Client  *http.Client
}

// NewOSV returns a client for the public OSV API.
func NewOSV() *OSV {
	return &OSV{BaseURL: DefaultOSVURL, Client: &http.Client{Timeout: 30 * time.Second}}
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Imports []struct {
				Path string `json:"path"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// queryVersions are the versions of a package to look up. A Python lock's variants are
// builds of one release for different platforms, so its primary version stands for them
// all; an npm package locked at several versions (nested node_modules) really installs each
// one, so each is looked up.
func queryVersions(ecosystem string, p *Package) []string {
	if ecosystem != EcosystemNPM || len(p.Variants) == 0 {
		return []string{p.Version}
	}

	versions := make([]string, 0, len(p.Variants))
	for _, v := range p.Variants {
		versions = append(versions, v.Version)
	}

	return versions
}

// Query returns the advisories for each package (by name as the lock spells it) at its
// locked version(s), looked up in the given OSV ecosystem (EcosystemPyPI or EcosystemNPM).
func (o *OSV) Query(ecosystem string, packages []*Package) (map[string][]Advisory, error) {
	var (
		queries []osvQuery
		owners  []*Package // the package each query is about
		asked   []string   // the version each query asked for
	)

	for _, p := range packages {
		for _, version := range queryVersions(ecosystem, p) {
			var q osvQuery

			q.Package.Name = p.Name
			q.Package.Ecosystem = ecosystem
			q.Version = version

			queries = append(queries, q)
			owners = append(owners, p)
			asked = append(asked, version)
		}
	}

	var batch struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}

	if err := o.post("/v1/querybatch", map[string]any{"queries": queries}, &batch); err != nil {
		return nil, err
	}

	result := map[string][]Advisory{}
	seen := map[string]bool{} // "<package>/<advisory>": one alert per package, however many versions hit it

	for i, r := range batch.Results {
		if i >= len(queries) {
			break
		}

		name := owners[i].Name

		for _, v := range r.Vulns {
			if seen[name+"/"+v.ID] {
				continue
			}

			seen[name+"/"+v.ID] = true

			vuln, err := o.vuln(v.ID)
			if err != nil {
				return nil, err
			}

			result[name] = append(result[name], toAdvisory(vuln, ecosystem, name, asked[i]))
		}
	}

	for name, advs := range result {
		result[name] = mergeAliases(advs)
	}

	return result, nil
}

// mergeAliases folds advisories that are the same vulnerability - OSV returns GitHub's
// record and the ecosystem's own (PYSEC-, GO-) side by side, aliasing each other - into
// one, so a vulnerability counts once, as Dependabot counts it. The GitHub id is kept as
// the id, the others become aliases; the highest severity and every fix reference are kept.
func mergeAliases(advs []Advisory) []Advisory {
	group := make([]int, len(advs)) // index of each advisory's group leader
	byName := map[string]int{}

	var find func(int) int
	find = func(i int) int {
		for group[i] != i {
			i = group[i]
		}

		return i
	}

	for i, a := range advs {
		group[i] = i

		for _, name := range append([]string{a.ID}, a.Aliases...) {
			if j, ok := byName[name]; ok {
				group[find(i)] = find(j)
			} else {
				byName[name] = i
			}
		}
	}

	merged := map[int]*Advisory{}

	var order []int

	for i := range advs {
		leader := find(i)

		m, ok := merged[leader]
		if !ok {
			c := advs[i]
			merged[leader], order = &c, append(order, leader)

			continue
		}

		m.absorb(advs[i])
	}

	out := make([]Advisory, 0, len(order))
	for _, leader := range order {
		out = append(out, *merged[leader])
	}

	return out
}

// absorb merges another record of the same vulnerability into a.
func (a *Advisory) absorb(b Advisory) {
	if !strings.HasPrefix(a.ID, "GHSA-") && strings.HasPrefix(b.ID, "GHSA-") {
		a.ID, b.ID = b.ID, a.ID
		a.Summary, a.Details = firstNonEmpty(b.Summary, a.Summary), firstNonEmpty(b.Details, a.Details)
	}

	names := map[string]bool{a.ID: true}

	var aliases []string

	for _, n := range append(append(append([]string(nil), a.Aliases...), b.ID), b.Aliases...) {
		if !names[n] {
			names[n] = true
			aliases = append(aliases, n)
		}
	}

	a.Aliases = aliases

	if severityRank[b.Severity] > severityRank[a.Severity] {
		a.Severity = b.Severity
	}

	if b.Fixed != "" && (a.Fixed == "" || CompareVersions(b.Fixed, a.Fixed) < 0) {
		a.Fixed = b.Fixed
	}

	a.FixRefs = mergeNames(a.FixRefs, b.FixRefs)
	a.AffectedPackages = mergeNames(a.AffectedPackages, b.AffectedPackages)
}

// History counts every advisory ever published against each package, at any version - a
// package's track record, as opposed to its current exposure.
func (o *OSV) History(names []string) (map[string]int, error) {
	type pkgQuery struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		PageToken string `json:"page_token,omitempty"`
	}

	counts := map[string]int{}
	pending := make([]pkgQuery, len(names))
	owner := make([]string, len(names))

	for i, n := range names {
		pending[i].Package.Name = n
		pending[i].Package.Ecosystem = "PyPI"
		owner[i] = n
	}

	// A package with a long history pages its results; keep asking for the next page.
	for len(pending) > 0 {
		var batch struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			} `json:"results"`
		}

		if err := o.post("/v1/querybatch", map[string]any{"queries": pending}, &batch); err != nil {
			return nil, err
		}

		var next []pkgQuery

		var nextOwner []string

		for i, r := range batch.Results {
			if i >= len(pending) {
				break
			}

			counts[owner[i]] += len(r.Vulns)

			if r.NextPageToken != "" {
				q := pending[i]
				q.PageToken = r.NextPageToken
				next = append(next, q)
				nextOwner = append(nextOwner, owner[i])
			}
		}

		pending, owner = next, nextOwner
	}

	return counts, nil
}

func (o *OSV) vuln(id string) (*osvVuln, error) {
	resp, err := o.Client.Get(o.BaseURL + "/v1/vulns/" + id)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: HTTP %d", id, resp.StatusCode)
	}

	var v osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", id, err)
	}

	return &v, nil
}

func (o *OSV) post(path string, body any, into any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	resp, err := o.Client.Post(o.BaseURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("querying OSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("querying OSV: HTTP %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(into)
}

// sameName compares an advisory's package name with a lock's: PyPI names are normalized
// (PEP 503); npm names and Go module paths are case-sensitive and compared as they are.
func sameName(ecosystem, a, b string) bool {
	if ecosystem == EcosystemNPM || ecosystem == EcosystemGo {
		return a == b
	}

	return NormalizeName(a) == NormalizeName(b)
}

// toAdvisory converts an OSV record for the given package at the version that was looked up.
func toAdvisory(v *osvVuln, ecosystem, name, version string) Advisory {
	a := Advisory{
		ID:       v.ID,
		Aliases:  v.Aliases,
		Summary:  strings.TrimSpace(v.Summary),
		Details:  v.Details,
		Severity: strings.ToLower(v.DatabaseSpecific.Severity),
	}
	if a.Severity == "" {
		a.Severity = "unknown"
	}

	if a.Summary == "" {
		a.Summary = firstLine(v.Details)
	}

	for _, ref := range v.References {
		if ref.Type == "FIX" {
			a.FixRefs = append(a.FixRefs, ref.URL)
		}
	}

	for _, aff := range v.Affected {
		if !sameName(ecosystem, aff.Package.Name, name) {
			continue
		}

		for _, imp := range aff.EcosystemSpecific.Imports {
			a.AffectedPackages = mergeNames(a.AffectedPackages, []string{imp.Path})
		}

		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				fixed, ok := ev["fixed"]
				if !ok || CompareVersions(fixed, version) <= 0 {
					continue
				}

				if a.Fixed == "" || CompareVersions(fixed, a.Fixed) < 0 {
					a.Fixed = fixed
				}
			}
		}
	}

	return a
}

var githubFixRe = regexp.MustCompile(`^https://github\.com/[^/]+/[^/]+/(commit/[0-9a-f]{7,40}|pull/\d+)/?$`)

// FetchFixPatch returns the code change behind the first GitHub commit or pull request
// among an advisory's FIX references (GitHub serves either as a patch at <url>.patch), or
// "" if there isn't one or it can't be fetched - the assessment then works from the
// advisory text alone.
func FetchFixPatch(client *http.Client, refs []string) string {
	for _, ref := range refs {
		ref = strings.TrimSuffix(ref, "/")
		if !githubFixRe.MatchString(ref) {
			continue
		}

		resp, err := client.Get(ref + ".patch")
		if err != nil {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		if err == nil && resp.StatusCode == http.StatusOK {
			return string(data)
		}
	}

	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}

	return s
}

var versionPartRe = regexp.MustCompile(`\d+`)

// CompareVersions orders two versions by their numeric release components - enough for
// "which fix is higher" between PyPI releases, without a full PEP 440 implementation
// (pre-releases and local tags like "+cpu" compare by their numbers only).
func CompareVersions(a, b string) int {
	pa := versionPartRe.FindAllString(strings.SplitN(a, "+", 2)[0], -1)
	pb := versionPartRe.FindAllString(strings.SplitN(b, "+", 2)[0], -1)

	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}

		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}

		if x != y {
			if x < y {
				return -1
			}

			return 1
		}
	}

	return 0
}
