package core

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

// effectiveEnv resolves cmd.Env the way os/exec does: the last entry for a key wins, and
// keys are case-insensitive on Windows.
func effectiveEnv(env []string, key string) (string, bool) {
	val, found := "", false

	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}

		if k == key || (runtime.GOOS == "windows" && strings.EqualFold(k, key)) {
			val, found = v, true
		}
	}

	return val, found
}

// The scanned checkout is untrusted: `go list` must not honour a go.work or rewrite
// go.mod, whatever the ambient environment says. GOTOOLCHAIN is deliberately not pinned
// (it would break scanning repos that need a newer Go).
func TestGoListCmdIsHardened(t *testing.T) {
	ambient := map[string][][2]string{
		"clean environment":        {},
		"toolchain auto":           {{"GOTOOLCHAIN", "auto"}},
		"toolchain pinned version": {{"GOTOOLCHAIN", "go9.99.0"}},
		"toolchain path switch":    {{"GOTOOLCHAIN", "local+path"}},
		"workspace elsewhere":      {{"GOWORK", "/evil/go.work"}},
		"GOFLAGS mod=mod":          {{"GOFLAGS", "-mod=mod"}},
		"lowercase key":            {{"gotoolchain", "auto"}, {"gowork", "/evil/go.work"}},
		"all at once":              {{"GOTOOLCHAIN", "auto"}, {"GOWORK", "/evil/go.work"}, {"GOFLAGS", "-mod=mod"}},
	}

	for name, vars := range ambient {
		t.Run(name, func(t *testing.T) {
			for _, kv := range vars {
				t.Setenv(kv[0], kv[1])
			}

			p := [3]string{"linux", "arm64", "0"}
			cmd := goListCmd("/some/checkout", p)

			if got, _ := effectiveEnv(cmd.Env, "GOWORK"); got != "off" {
				t.Errorf("GOWORK = %q, want off", got)
			}

			if !slices.Contains(cmd.Args, "-mod=readonly") {
				t.Errorf("args %v lack -mod=readonly, which must override GOFLAGS", cmd.Args)
			}

			// The platform and directory must be unaffected by the hardening.
			for k, want := range map[string]string{"GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "0"} {
				if got, _ := effectiveEnv(cmd.Env, k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}

			if cmd.Dir != "/some/checkout" {
				t.Errorf("Dir = %q", cmd.Dir)
			}
		})
	}
}
