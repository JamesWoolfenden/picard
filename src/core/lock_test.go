package core

import (
	"reflect"
	"testing"
)

func TestReadUVLockFindsProjectAndProductionClosure(t *testing.T) {
	lock, err := ReadUVLock("testdata/pan-uv.lock")
	if err != nil {
		t.Fatal(err)
	}

	if lock.Project != "pan" {
		t.Fatalf("project = %q, want pan", lock.Project)
	}

	prod := lock.Closure(lock.Direct)

	if got := prod["filelock"]; !reflect.DeepEqual(got, []string{"torch", "filelock"}) {
		t.Errorf("filelock via %v, want [torch filelock]", got)
	}

	if _, ok := prod["pytest"]; ok {
		t.Error("pytest is dev-only but landed in the production closure")
	}

	dev := lock.Closure(lock.DevDirect)
	if _, ok := dev["pytest"]; !ok {
		t.Error("pytest missing from the dev closure")
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Python_Dotenv":         "python-dotenv",
		"zope.interface":        "zope-interface",
		"sentence-transformers": "sentence-transformers",
	} {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.2.1", "4.1.0", 1},
		{"2026.7.22", "2026.10.18", -1},
		{"2.15.0+cpu", "2.15.0", 0},
		{"1.0", "1.0.0", 0},
	}

	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
