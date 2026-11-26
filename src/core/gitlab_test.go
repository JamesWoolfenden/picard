package core

import (
	"testing"
)

// The origin remote of a scanned checkout is untrusted input, so GITLAB_TOKEN must only
// reach gitlab.com or the host the user named in GITLAB_HOST.
func TestNewGitLabTokenHostAllowList(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		gitlabHost string
		wantToken  bool
	}{
		{"gitlab.com", "gitlab.com", "", true},
		{"gitlab.com uppercase", "GitLab.com", "", true},
		{"named host", "git.example.com", "git.example.com", true},
		{"named host with scheme", "git.example.com", "https://git.example.com/", true},
		{"hostile origin", "evil.example", "", false},
		{"suffix trick", "gitlab.com.evil.example", "", false},
		{"prefix trick", "evilgitlab.com", "", false},
		{"userinfo trick", "gitlab.com@evil.example", "", false},
		{"trailing dot", "gitlab.com.", "", false},
		{"other host with GITLAB_HOST set", "evil.example", "git.example.com", false},
		{"subdomain of named host", "x.git.example.com", "git.example.com", false},
		{"empty host", "", "", false},
		{"empty host, empty GITLAB_HOST", "", " ", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITLAB_TOKEN", "secret-token")
			t.Setenv("GITLAB_HOST", tc.gitlabHost)
			// No glab on PATH, so the only possible token source is the environment.
			t.Setenv("PATH", t.TempDir())

			g, err := NewGitLab(tc.host)

			if tc.wantToken {
				if err != nil || g.Token != "secret-token" {
					t.Fatalf("NewGitLab(%q) = %v, %v; want the env token", tc.host, g, err)
				}

				return
			}

			if err == nil {
				t.Fatalf("NewGitLab(%q) used GITLAB_TOKEN for an untrusted host (token %q)", tc.host, g.Token)
			}
		})
	}
}
