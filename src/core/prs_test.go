package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPRLocks(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"uv.lock": "", "ui/package-lock.json": ""})

	locks, unread, stale := prLocks(dir, []string{
		"ui/package.json", "ui/package-lock.json", // compared through the lock
		"pyproject.toml",           // its uv.lock isn't in the PR
		"backend/requirements.txt", // not a lock
	})

	if !reflect.DeepEqual(locks, []string{"ui/package-lock.json"}) ||
		!reflect.DeepEqual(unread, []string{"backend/requirements.txt"}) ||
		!reflect.DeepEqual(stale, []string{"pyproject.toml"}) {
		t.Errorf("locks %v, unread %v, stale %v", locks, unread, stale)
	}
}

func TestMajorOf(t *testing.T) {
	for v, want := range map[string]string{">=1.13.0": "1", ">=2.3.0": "2", "13.1.0": "13", "v2": "2", "~=0.17": "0"} {
		if got := majorOf(v); got != want {
			t.Errorf("majorOf(%q) = %q, want %q", v, got, want)
		}
	}
}

// Dependabot titles carry the repo's commit-message prefix, and digest bumps are not major.
func TestPRTitleParsing(t *testing.T) {
	for _, c := range []struct {
		title, pkg, from, to string
		major                bool
	}{
		{"Bump vitest from 1.0.0 to 2.0.0 in /ui", "vitest", "1.0.0", "2.0.0", true},
		{"chore(deps): bump @sveltejs/kit from 2.70.4 to 3.1.1", "@sveltejs/kit", "2.70.4", "3.1.1", true},
		{"build(deps): Bump aiohttp from 3.9.1 to 3.14.5", "aiohttp", "3.9.1", "3.14.5", false},
		{"deps(deps)!: bump x from 1.2.0 to 1.3.0", "x", "1.2.0", "1.3.0", false},
		{"docker(deps): bump golang from `d200d2d` to `fa3d596`", "golang", "`d200d2d`", "`fa3d596`", false},
		{"Update requests requirement from >=2.3.0 to >=3.0.0", "requests", ">=2.3.0", ">=3.0.0", true},
	} {
		m := prTitleRe.FindStringSubmatch(c.title)
		if m == nil {
			t.Errorf("%q did not match", c.title)

			continue
		}

		if m[1] != c.pkg || m[2] != c.from || m[3] != c.to {
			t.Errorf("%q parsed as %v", c.title, m[1:])
		}

		if major := isVersion(m[2]) && isVersion(m[3]) && majorOf(m[2]) != majorOf(m[3]); major != c.major {
			t.Errorf("%q major = %v, want %v", c.title, major, c.major)
		}
	}

	// Grouped titles name no versions, so there is nothing to parse.
	for _, title := range []string{
		"deps(deps): bump the minor-and-patch group with 6 updates",
		"build(deps): bump cookie, @sveltejs/adapter-auto and @sveltejs/kit",
	} {
		if prTitleRe.MatchString(title) {
			t.Errorf("%q should not match", title)
		}
	}
}

// A grouped PR's title names no versions: whether it moved a major version has to come from
// the lock diff, and a PR whose locks couldn't be read stays unknown instead of "false".
func TestGroupedPRMajor(t *testing.T) {
	base, err := os.ReadFile("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	major := strings.Replace(string(base), `"node_modules/@scope/kit": { "version": "1.2.0"`, `"node_modules/@scope/kit": { "version": "2.0.0"`, 1)
	minor := strings.Replace(string(base), `"node_modules/react": { "version": "18.3.1"`, `"node_modules/react": { "version": "18.4.0"`, 1)

	osv := uuidOSV()
	defer osv.Close()

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/pulls/1/files", "/repos/o/r/pulls/2/files":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"filename": "ui/package.json"}, {"filename": "ui/package-lock.json"}})
		case "/repos/o/r/pulls/3/files":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"filename": "Dockerfile"}})
		case "/repos/o/r/contents/ui/package-lock.json":
			switch r.URL.Query().Get("ref") {
			case "head1":
				_, _ = w.Write([]byte(major))
			case "head2":
				_, _ = w.Write([]byte(minor))
			default:
				_, _ = w.Write(base)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"ui/package-lock.json": string(base), "ui/src/index.js": `import React from 'react';`})

	pr := func(n int, title, sha string) PullRequest {
		p := PullRequest{Number: n, Title: title}
		p.Head.SHA, p.Base.SHA = sha, "base"

		return p
	}

	got, err := TriagePRs(&GitHub{BaseURL: gh.URL, Client: gh.Client()}, "o/r", dir, []PullRequest{
		pr(1, "build(deps): bump @scope/kit and react", "head1"),
		pr(2, "deps(deps): bump the minor-and-patch group with 2 updates", "head2"),
		pr(3, "docker(deps): bump the base group", "head3"),
	}, Options{OSV: &OSV{BaseURL: osv.URL, Client: osv.Client()}})
	if err != nil {
		t.Fatal(err)
	}

	if g := got[0]; g.Major == nil || !*g.Major || !reflect.DeepEqual(g.MajorChanges, []string{"@scope/kit 1.2.0 → 2.0.0"}) {
		t.Errorf("major group = %+v", g)
	}

	if g := got[1]; g.Major == nil || *g.Major || len(g.MajorChanges) != 0 {
		t.Errorf("minor group = %+v", g)
	}

	if g := got[2]; g.Major != nil {
		t.Errorf("unreadable group should leave major unknown, got %+v", *g.Major)
	}
}

// garmin-mcp-gt's PRs in miniature: a lock bump that removes an advisory, and a requirement
// floor raised in an unpinned file.
func TestTriagePRs(t *testing.T) {
	base, err := os.ReadFile("testdata/ui-package-lock.json")
	if err != nil {
		t.Fatal(err)
	}

	// The head drops uuid from vitest's dependencies, and with it the advisory.
	head := strings.Replace(strings.Replace(string(base), `, "uuid": "^9.0.0"`, "", 1),
		`"node_modules/uuid": { "version": "9.0.1", "dev": true },`, "", 1)

	osv := uuidOSV()
	defer osv.Close()

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/pulls/1/files":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"filename": "ui/package.json"}, {"filename": "ui/package-lock.json"}})
		case "/repos/o/r/pulls/2/files":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"filename": "backend/requirements.txt"}})
		case "/repos/o/r/contents/ui/package-lock.json":
			if r.URL.Query().Get("ref") == "head1" {
				_, _ = w.Write([]byte(head))
			} else {
				_, _ = w.Write(base)
			}
		case "/repos/o/r/commits/head1/check-runs", "/repos/o/r/commits/head2/check-runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"check_runs": []map[string]string{
				{"status": "completed", "conclusion": "success"},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"ui/package-lock.json": string(base), "ui/src/index.js": `import React from 'react';`})

	pr := func(n int, title, sha string) PullRequest {
		p := PullRequest{Number: n, Title: title}
		p.Head.SHA, p.Base.SHA = sha, "base"

		return p
	}

	got, err := TriagePRs(&GitHub{BaseURL: gh.URL, Client: gh.Client()}, "o/r", dir, []PullRequest{
		pr(1, "Bump vitest from 1.0.0 to 2.0.0 in /ui", "head1"),
		pr(2, "Update fastapi requirement from >=0.143.0 to >=0.162.0", "head2"),
	}, Options{OSV: &OSV{BaseURL: osv.URL, Client: osv.Client()}})
	if err != nil {
		t.Fatal(err)
	}

	bump := got[0]
	if bump.Class != PRFixesDevOnly || len(bump.Removes) != 1 || bump.Removes[0].Package != "uuid" ||
		bump.Major == nil || !*bump.Major || bump.CI != "passing" || bump.Package != "vitest" {
		t.Errorf("bump = %+v", bump)
	}

	if floor := got[1]; floor.Class != PRNoInstallChange || floor.Major == nil || *floor.Major {
		t.Errorf("floor = %+v", floor)
	}
}

// Docker base-image PRs change no lock: a golang builder bump is judged by the standard
// library advisories fixed between the two Go versions, any other image is classed base-image.
func TestTriageDockerPRs(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var body struct {
				Queries []osvQuery `json:"queries"`
			}

			_ = json.NewDecoder(r.Body).Decode(&body)

			results := make([]any, len(body.Queries))
			for i, q := range body.Queries {
				results[i] = map[string]any{}
				// The standard library has an advisory in 1.27.3 that 1.27.4 fixes.
				if q.Package.Name == GoStdlib && q.Version == "1.27.3" {
					results[i] = map[string]any{"vulns": []any{map[string]string{"id": "GO-2026-1"}}}
				}
			}

			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/GO-2026-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "GO-2026-1", "summary": "net/http: something"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer osv.Close()

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/files") {
			_ = json.NewEncoder(w).Encode([]map[string]string{{"filename": "Dockerfile"}})

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"check_runs": []map[string]string{{"status": "completed", "conclusion": "success"}}})
	}))
	defer gh.Close()

	pr := func(n int, title string) PullRequest {
		p := PullRequest{Number: n, Title: title}
		p.Head.SHA, p.Base.SHA = "head", "base"

		return p
	}

	got, err := TriagePRs(&GitHub{BaseURL: gh.URL, Client: gh.Client()}, "o/r", t.TempDir(), []PullRequest{
		pr(1, "docker(deps): bump golang from 1.27.3-alpine3.24 to 1.27.4-alpine3.24"),
		pr(2, "docker(deps): bump golang from 1.27.4-alpine3.24 to 1.27.5-alpine3.24"),
		pr(3, "docker(deps): bump alpine from be26560 to f59abe6"),
		pr(4, "docker(deps): bump node from 22-alpine to 24-alpine"),
	}, Options{OSV: &OSV{BaseURL: osv.URL, Client: osv.Client()}})
	if err != nil {
		t.Fatal(err)
	}

	for i, want := range []string{PRFixesShipped, PRFixesNothing, PRBaseImage, PRBaseImage} {
		if got[i].Class != want {
			t.Errorf("PR %d class = %s (%s), want %s", got[i].Number, got[i].Class, got[i].Reason, want)
		}
	}

	if len(got[0].Removes) != 1 || got[0].Removes[0].ID != "GO-2026-1" {
		t.Errorf("golang bump removes = %+v", got[0].Removes)
	}

	if !strings.Contains(got[2].Reason, "digest") {
		t.Errorf("digest bump reason = %q", got[2].Reason)
	}
}
