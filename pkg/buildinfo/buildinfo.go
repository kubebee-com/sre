// Package buildinfo contains values injected by the release build.
package buildinfo

import "fmt"

var (
	Version   = "dev"
	Revision  = "unknown"
	BuildDate = "unknown"
)

// String returns a stable, human-readable build identity.
func String() string {
	return fmt.Sprintf("%s (revision %s, built %s)", Version, Revision, BuildDate)
}
