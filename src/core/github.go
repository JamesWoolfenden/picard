package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// DefaultGitHubURL is the public GitHub REST API.
const DefaultGitHubURL = "https://api.github.com"

// GitHub is a minimal client for the Dependabot alerts API.
type GitHub struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// NewGitHub authenticates with GITHUB_TOKEN, else GH_TOKEN, else the GitHub CLI's
// (`gh auth token`). Listing alerts needs read access to them; dismissing needs write
// (the security_events scope, or a fine-grained token with Dependabot alerts read/write).
func NewGitHub() (*GitHub, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}

	if token == "" {
		out, err := exec.Command("gh", "auth", "token").Output()
		if err != nil {
			return nil, fmt.Errorf("no GitHub token: set GITHUB_TOKEN or log in with `gh auth login`")
		}

		token = strings.TrimSpace(string(out))
	}

	return &GitHub{BaseURL: DefaultGitHubURL, Token: token, Client: &http.Client{Timeout: 30 * time.Second}}, nil
}

// Alert is one Dependabot alert.
type Alert struct {
	Number     int    `json:"number"`
	State      string `json:"state"`
	HTMLURL    string `json:"html_url"`
	Dependency struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
		Scope        string `json:"scope"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		GHSAID   string `json:"ghsa_id"`
		CVEID    string `json:"cve_id"`
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
	} `json:"security_advisory"`
	SecurityVulnerability struct {
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    *struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
}

var nextLinkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// Alerts lists a repository's Dependabot alerts in the given state (open, fixed,
// dismissed, auto_dismissed; "" for all), following pagination.
func (g *GitHub) Alerts(repo, state string) ([]Alert, error) {
	url := fmt.Sprintf("%s/repos/%s/dependabot/alerts?per_page=100", g.BaseURL, repo)
	if state != "" {
		url += "&state=" + state
	}

	var all []Alert

	for url != "" {
		resp, err := g.do(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		var page []Alert

		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()

		if err != nil {
			return nil, fmt.Errorf("decoding alerts: %w", err)
		}

		all = append(all, page...)

		url = ""
		if m := nextLinkRe.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
			url = m[1]
		}
	}

	return all, nil
}

// Dismiss closes an alert with one of Dependabot's reasons (fix_started, inaccurate,
// no_bandwidth, not_used, tolerable_risk) and a comment of at most 280 characters.
func (g *GitHub) Dismiss(repo string, number int, reason, comment string) error {
	if len(comment) > 280 {
		comment = comment[:277] + "..."
	}

	body, err := json.Marshal(map[string]string{
		"state": "dismissed", "dismissed_reason": reason, "dismissed_comment": comment,
	})
	if err != nil {
		return err
	}

	resp, err := g.do(http.MethodPatch, fmt.Sprintf("%s/repos/%s/dependabot/alerts/%d", g.BaseURL, repo, number), body)
	if err != nil {
		return err
	}

	resp.Body.Close()

	return nil
}

func (g *GitHub) do(method, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+g.Token)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, url, err)
	}

	if resp.StatusCode >= 300 {
		var msg struct {
			Message string `json:"message"`
		}

		_ = json.NewDecoder(resp.Body).Decode(&msg)
		resp.Body.Close()

		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, url, resp.StatusCode, msg.Message)
	}

	return resp, nil
}

// RepoFromGit is the owner/name of a checkout's origin remote on GitHub.
func RepoFromGit(dir string) (string, error) {
	r, err := RemoteFromGit(dir)
	if err != nil {
		return "", err
	}

	if !r.GitHub() {
		return "", fmt.Errorf("origin of %s isn't a GitHub repository - pass --repo owner/name", dir)
	}

	return r.Path, nil
}
