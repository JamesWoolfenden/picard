package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOSVQueryFindsTheLowestFixAboveTheLockedVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{
				map[string]any{"vulns": []any{map[string]string{"id": "GHSA-1"}}},
				map[string]any{},
			}})
		case "/v1/vulns/GHSA-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                "GHSA-1",
				"summary":           "lock file trouble",
				"aliases":           []string{"CVE-2026-1"},
				"database_specific": map[string]string{"severity": "HIGH"},
				"affected": []any{map[string]any{
					"package": map[string]string{"name": "FileLock", "ecosystem": "PyPI"},
					"ranges": []any{map[string]any{"events": []map[string]string{
						{"introduced": "0"}, {"fixed": "3.0.0"}, {"introduced": "4.0.0"}, {"fixed": "4.2.1"},
					}}},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	osv := &OSV{BaseURL: server.URL, Client: server.Client()}

	got, err := osv.Query([]*Package{{Name: "filelock", Version: "4.1.0"}, {Name: "safe", Version: "1"}})
	if err != nil {
		t.Fatal(err)
	}

	advs := got["filelock"]
	if len(advs) != 1 {
		t.Fatalf("advisories = %+v", got)
	}

	if a := advs[0]; a.Fixed != "4.2.1" || a.Severity != "high" || a.Summary != "lock file trouble" {
		t.Errorf("advisory = %+v", a)
	}

	if len(got["safe"]) != 0 {
		t.Errorf("safe package got advisories: %+v", got["safe"])
	}
}
