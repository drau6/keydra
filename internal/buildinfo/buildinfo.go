// Package buildinfo holds values injected at build time via -ldflags.
package buildinfo

import "runtime/debug"

// DefaultVersion is the version compiled into a plain `go build` or `go test`.
const DefaultVersion = "v1.1.0"

// Version is the default shown in the banner and the User-Agent. It is
// overridden at build time with, e.g.:
//
//	-ldflags "-X github.com/drau6/keydra/internal/buildinfo.Version=v1.2.3"
//
// `make build`/`make install` stamp it from `git describe --tags`, so a
// tagged checkout reports its real version and an untagged tree reports a
// short commit hash.
var Version = DefaultVersion

// Current returns the best version available: an ldflags-injected Version,
// otherwise the module version recorded by `go install ...@latest`, otherwise
// DefaultVersion.
func Current() string {
	if Version != "" && Version != DefaultVersion {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	if Version != "" {
		return Version
	}
	return DefaultVersion
}
