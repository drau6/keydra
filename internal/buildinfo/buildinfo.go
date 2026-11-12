// Package buildinfo holds values injected at build time via -ldflags.
package buildinfo

// Version is the default shown in the banner and the User-Agent. It is
// overridden at build time with, e.g.:
//
//	-ldflags "-X github.com/drau6/keydra/internal/buildinfo.Version=v1.2.3"
//
// `make build`/`make install` stamp it from `git describe --tags`, so a
// tagged checkout reports its real version and an untagged tree reports a
// short commit hash.
var Version = "v1.0.0"
