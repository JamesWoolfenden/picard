package core

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Query returns the advisories for each package (by normalized name) at its locked version.
func (o *OSV) Query(packages []*Package) (map[string][]Advisory, error) {
	queries := make([]osvQuery, len(packages))
	for i, p := range packages {
		queries[i].Package.Name = p.Name
		queries[i].Package.Ecosystem = "PyPI"
		queries[i].Version = p.Version
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

	for i, r := range batch.Results {
		if i >= len(packages) {
			break
		}

		for _, v := range r.Vulns {
			vuln, err := o.vuln(v.ID)
			if err != nil {
				return nil, err
			}

			result[packages[i].Name] = append(result[packages[i].Name], toAdvisory(vuln, packages[i]))
		}
	}

	return result, nil
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

func toAdvisory(v *osvVuln, pkg *Package) Advisory {
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

	for _, aff := range v.Affected {
		if NormalizeName(aff.Package.Name) != pkg.Name {
			continue
		}

		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				fixed, ok := ev["fixed"]
				if !ok || CompareVersions(fixed, pkg.Version) <= 0 {
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
