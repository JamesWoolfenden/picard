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

// GitLab is a minimal GraphQL client for a GitLab instance, gitlab.com or self-managed.
type GitLab struct {
	// BaseURL is the instance, e.g. https://gitlab.example.com.
	BaseURL string
	Token   string
	Client  *http.Client
}

// NewGitLab authenticates with GITLAB_TOKEN, else the token glab has stored for the host
// (`glab auth login --hostname <host>`). The setup check needs read_api.
func NewGitLab(host string) (*GitLab, error) {
	token := os.Getenv("GITLAB_TOKEN")

	if token == "" {
		out, err := exec.Command("glab", "config", "get", "token", "--host", host).Output()
		if err == nil {
			token = strings.TrimSpace(string(out))
		}
	}

	if token == "" {
		return nil, fmt.Errorf("no GitLab token for %s: set GITLAB_TOKEN or log in with `glab auth login --hostname %s`", host, host)
	}

	return &GitLab{BaseURL: "https://" + host, Token: token, Client: &http.Client{Timeout: 30 * time.Second}}, nil
}

// graphql runs a query and decodes its data into v.
func (g *GitLab) graphql(query string, vars map[string]any, v any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}

	url := g.BaseURL + "/api/graphql"

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.Token)

	resp, err := g.Client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: HTTP %d", url, resp.StatusCode)
	}

	var out struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decoding %s: %w", url, err)
	}

	if len(out.Errors) > 0 {
		return fmt.Errorf("GitLab GraphQL: %s", out.Errors[0].Message)
	}

	return json.Unmarshal(out.Data, v)
}

// Remote is where a checkout's origin lives: a host and the repository path on it
// (owner/name on GitHub, group/.../project on GitLab).
type Remote struct {
	Host string
	Path string
}

// GitHub reports whether the remote is github.com.
func (r Remote) GitHub() bool { return r.Host == "github.com" }

var (
	scpRemoteRe = regexp.MustCompile(`^[\w.-]+@([\w.-]+):(.+)$`)                   // git@host:group/project.git
	urlRemoteRe = regexp.MustCompile(`^\w+://(?:[^@/]+@)?([^/:]+)(?::\d+)?/(.+)$`) // https://host/group/project
)

// ParseRemote reads a git remote URL (https, ssh:// or scp-style).
func ParseRemote(url string) (Remote, bool) {
	url = strings.TrimSpace(url)

	m := scpRemoteRe.FindStringSubmatch(url)
	if m == nil {
		m = urlRemoteRe.FindStringSubmatch(url)
	}

	if m == nil {
		return Remote{}, false
	}

	path := strings.TrimSuffix(strings.TrimSuffix(m[2], "/"), ".git")
	if !strings.Contains(path, "/") {
		return Remote{}, false
	}

	return Remote{Host: strings.ToLower(m[1]), Path: path}, true
}

// RemoteFromGit is a checkout's origin remote.
func RemoteFromGit(dir string) (Remote, error) {
	out, err := exec.Command("git", "-C", dir, "remote", "get-url", "origin").Output()
	if err != nil {
		return Remote{}, fmt.Errorf("no origin remote in %s - pass --repo", dir)
	}

	r, ok := ParseRemote(string(out))
	if !ok {
		return Remote{}, fmt.Errorf("can't read origin remote %q of %s - pass --repo", strings.TrimSpace(string(out)), dir)
	}

	return r, nil
}
