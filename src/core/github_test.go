package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	const base = "https://api.github.com"

	for name, tc := range map[string]struct {
		next    string
		wantErr bool
	}{
		"same host":       {"https://api.github.com/repos/o/r/dependabot/alerts?page=2", false},
		"host case":       {"https://API.GitHub.com/repos/o/r/dependabot/alerts?page=2", false},
		"other host":      {"https://evil.example/repos/o/r/dependabot/alerts?page=2", true},
		"lookalike host":  {"https://api.github.com.evil.example/x", true},
		"userinfo trick":  {"https://api.github.com@evil.example/x", true},
		"other scheme":    {"http://api.github.com/x", true},
		"other port":      {"https://api.github.com:8443/x", true},
		"relative link":   {"/repos/o/r/dependabot/alerts?page=2", true},
		"unparseable url": {"https://api.github.com/%zz", true},
	} {
		t.Run(name, func(t *testing.T) {
			err := sameOrigin(base, tc.next)
			if (err != nil) != tc.wantErr {
				t.Errorf("sameOrigin(%q, %q) error = %v, wantErr %v", base, tc.next, err, tc.wantErr)
			}
		})
	}
}

func TestGetAllDoesNotSendTheTokenToAnotherHost(t *testing.T) {
	var hits atomic.Int32

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "[]")
	}))
	defer other.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s/steal>; rel="next"`, other.URL))
		fmt.Fprint(w, "[]")
	}))
	defer api.Close()

	gh := &GitHub{BaseURL: api.URL, Token: "secret-token", Client: api.Client()}

	if _, err := gh.Alerts("o/r", ""); err == nil {
		t.Fatal("Alerts followed a pagination link to another host; want an error")
	}

	if n := hits.Load(); n != 0 {
		t.Errorf("the other host received %d request(s) carrying the token; want 0", n)
	}
}
