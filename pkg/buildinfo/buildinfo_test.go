package buildinfo

import (
	"strings"
	"testing"
)

func TestStringIncludesBuildIdentity(t *testing.T) {
	oldVersion, oldRevision, oldBuildDate := Version, Revision, BuildDate
	t.Cleanup(func() {
		Version, Revision, BuildDate = oldVersion, oldRevision, oldBuildDate
	})
	Version = "1.2.3"
	Revision = "abc123"
	BuildDate = "2026-09-05T00:00:00Z"

	value := String()
	for _, part := range []string{Version, Revision, BuildDate} {
		if !strings.Contains(value, part) {
			t.Fatalf("build identity %q does not contain %q", value, part)
		}
	}
}
