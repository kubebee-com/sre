package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
)

// LegacyBinding records a separately verified administrator binding. Previewing
// does not enroll a cluster, authorize an actor, or import executable state.
type LegacyBinding struct {
	Scope                      identity.Scope `json:"scope"`
	VerifiedClusterFingerprint string         `json:"verified_cluster_fingerprint"`
}
type LegacyImportReport struct {
	SourceSHA256        string        `json:"source_sha256"`
	Binding             LegacyBinding `json:"binding"`
	Records             int           `json:"records"`
	Quarantined         int           `json:"quarantined"`
	ExecutableApprovals int           `json:"executable_approvals"`
	Reasons             []string      `json:"reasons"`
}

var ErrInvalidLegacySource = errors.New("unsupported legacy source or unverified scope binding")

// PreviewLegacyImport is side-effect free. All historical assertions require
// fresh collection/review, and shared-token approvals never become authority.
func PreviewLegacyImport(raw []byte, binding LegacyBinding) (LegacyImportReport, error) {
	if binding.Scope.Validate() != nil || !identity.ValidID(binding.VerifiedClusterFingerprint) || len(raw) == 0 || len(raw) > 16<<20 {
		return LegacyImportReport{}, ErrInvalidLegacySource
	}
	var envelope struct {
		Schema        string                     `json:"schema"`
		Version       int                        `json:"version"`
		SchemaVersion string                     `json:"schema_version"`
		Proposals     []json.RawMessage          `json:"proposals"`
		Entries       map[string]json.RawMessage `json:"entries"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return LegacyImportReport{}, ErrInvalidLegacySource
	}
	count := 0
	switch {
	case envelope.Schema == "kubebee.sre/proposals" && envelope.Version == 1 && envelope.Proposals != nil:
		count = len(envelope.Proposals)
	case envelope.SchemaVersion == "scan-history/v1" && envelope.Entries != nil:
		count = len(envelope.Entries)
	default:
		return LegacyImportReport{}, ErrInvalidLegacySource
	}
	digest := sha256.Sum256(raw)
	return LegacyImportReport{SourceSHA256: hex.EncodeToString(digest[:]), Binding: binding, Records: count, Quarantined: count, Reasons: []string{"Legacy records lack orchestrator provenance and remain quarantined.", "Historical approvals and asserted actor strings grant no executable authority."}}, nil
}
