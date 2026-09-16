// Package version defines the version and build metadata for tsproxy.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Default version if not set via ldflags.
var (
	// Version is the semver version string (e.g. "0.1.0").
	Version = "0.1.0"
	// GitCommit is the git commit hash, set via ldflags.
	GitCommit = ""
	// BuildDate is the build timestamp, set via ldflags.
	BuildDate = ""
)

// String returns a human-readable version summary.
func String() string {
	v := Version
	if v == "" {
		v = "0.1.0"
	}

	commit := GitCommit
	if commit == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && len(s.Value) >= 7 {
					commit = s.Value[:7]
					break
				}
			}
		}
	}

	if commit != "" {
		return fmt.Sprintf("%s (%s, %s/%s)", v, commit, runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("%s (%s/%s)", v, runtime.GOOS, runtime.GOARCH)
}

// Full returns detailed version and build information.
func Full() string {
	s := fmt.Sprintf("tsproxy version %s\n", Version)
	s += fmt.Sprintf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	s += fmt.Sprintf("  Go version: %s\n", runtime.Version())
	if GitCommit != "" {
		s += fmt.Sprintf("  Git commit: %s\n", GitCommit)
	}
	if BuildDate != "" {
		s += fmt.Sprintf("  Built:      %s\n", BuildDate)
	}
	return s
}
