package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"testing"
)

func TestLegacyImportReportCannotCreateAuthority(t *testing.T) {
	raw := []byte(`{"schema":"kubebee.sre/proposals","version":1,"proposals":[{"id":"old","status":"APPROVED","approved_by":"claimed-admin"}]}`)
	scope := identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}
	if _, err := PreviewLegacyImport(raw, LegacyBinding{Scope: scope}); err == nil {
		t.Fatal("unverified cluster binding accepted")
	}
	binding := LegacyBinding{Scope: scope, VerifiedClusterFingerprint: "verified-cluster-fingerprint"}
	a, err := PreviewLegacyImport(raw, binding)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PreviewLegacyImport(raw, binding)
	if err != nil {
		t.Fatal(err)
	}
	if a.SourceSHA256 != b.SourceSHA256 || a.Records != 1 || a.Quarantined != 1 || a.ExecutableApprovals != 0 {
		t.Fatalf("unsafe report: %#v", a)
	}
	for _, bad := range [][]byte{[]byte(`{`), []byte(`{"unrelated":[]}`), []byte(`{"schema":"kubebee.sre/proposals","version":999,"proposals":[]}`)} {
		if _, err := PreviewLegacyImport(bad, binding); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
}
