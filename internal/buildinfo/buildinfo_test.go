package buildinfo

import "testing"

func TestCurrent(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })

	Version = DefaultVersion
	if got := Current(); got == "" {
		t.Fatal("Current returned an empty version")
	}

	Version = "v9.9.9-test"
	if got := Current(); got != Version {
		t.Errorf("Current() = %q, want the ldflags version %q", got, Version)
	}
}
