package playbook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"k8s.io/apimachinery/pkg/labels"
)

var (
	ErrCatalogNotFound    = errors.New("catalog record not found")
	ErrCatalogConflict    = errors.New("catalog immutable record conflicts")
	ErrCatalogUnavailable = errors.New("catalog unavailable")
	ErrCatalogInvalid     = errors.New("invalid catalog record")
	ErrInvalidTransition  = errors.New("invalid catalog lifecycle transition")
)

// Catalog persists sanitized, immutable versions; lifecycle is a separate projection.
type Catalog interface {
	PrepareSource(SourceArtifact) (SourceArtifact, error)
	SaveSource(context.Context, SourceArtifact) error
	SaveDigest(context.Context, PlaybookDigest) error
	SavePlaybook(context.Context, NormalizedPlaybook) error
	ListActive(context.Context, MatchQuery) ([]NormalizedPlaybook, error)
	Transition(context.Context, string, int, LifecycleState, string) error
	RecordLearningCandidate(context.Context, LearningCandidate) error
	Stats(context.Context) (CatalogStats, error)
	List(context.Context, int) ([]NormalizedPlaybook, error)
	GetPlaybook(context.Context, string, int) (NormalizedPlaybook, error)
	GetPlaybookByHash(context.Context, string) (NormalizedPlaybook, error)
	GetSourceByChecksum(context.Context, string) (SourceArtifact, error)
	GetLearningCandidate(context.Context, string) (LearningCandidate, error)
	RecordRelation(context.Context, Relation) error
	RecordResolution(context.Context, ResolutionPlan) error
	GetResolution(context.Context, string) (ResolutionPlan, error)
	RecordResolutionOutcome(context.Context, ResolutionOutcomeRecord) error
	RecordFinding(context.Context, FindingRecord) error
	RecordEvidence(context.Context, EvidenceRef) error
}

type Relation struct {
	ID     string `json:"id"`
	FromID string `json:"from_id"`
	ToID   string `json:"to_id"`
	Kind   string `json:"kind"`
}
type FindingRecord struct {
	ID       string        `json:"id"`
	Query    MatchQuery    `json:"query"`
	Evidence []EvidenceRef `json:"evidence,omitempty"`
	Summary  string        `json:"summary"`
}
type LifecycleAudit struct {
	PlaybookID string         `json:"playbook_id"`
	Version    int            `json:"version"`
	From       LifecycleState `json:"from"`
	To         LifecycleState `json:"to"`
	Actor      string         `json:"actor"`
	At         time.Time      `json:"at"`
}

type CatalogOption func(*catalog)

func WithCatalogSecrets(secrets ...string) CatalogOption {
	return func(c *catalog) {
		c.secrets = append(c.secrets, secrets...)
		c.redactor = sanitizer.RedactorForSecrets(c.secrets...)
	}
}

type catalog struct {
	backend  catalogBackend
	redactor *sanitizer.Redactor
	secrets  []string
}
type catalogRow struct {
	ID      string
	Version int
	Lookup  string
	State   LifecycleState
	Hash    string
	Payload []byte
}
type catalogTx interface {
	get(context.Context, string, string, int) (catalogRow, error)
	lookup(context.Context, string, string) (catalogRow, error)
	each(context.Context, string, LifecycleState, func(catalogRow) (bool, error)) error
	insert(context.Context, string, catalogRow) error
	replaceFinding(context.Context, catalogRow) error
	state(context.Context, string, int, LifecycleState) error
	count(context.Context, string, LifecycleState) (int, error)
}
type catalogBackend interface {
	read(context.Context, func(catalogTx) error) error
	write(context.Context, func(catalogTx) error) error
}

func newCatalog(b catalogBackend, options []CatalogOption) *catalog {
	c := &catalog{backend: b, redactor: sanitizer.DefaultRedactor()}
	for _, o := range options {
		if o != nil {
			o(c)
		}
	}
	return c
}

// SourceChecksum identifies sanitized source bytes, independently of caller IDs.
func SourceChecksum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
func (c *catalog) clean(input, output any) error {
	data, err := json.Marshal(input)
	if err != nil || len(data) > 4*1024*1024 {
		return ErrCatalogInvalid
	}
	var value any
	if json.Unmarshal(data, &value) != nil {
		return ErrCatalogInvalid
	}
	data, err = json.Marshal(c.cleanURLs(c.redactor.SanitizeValue(value)))
	if err != nil || json.Unmarshal(data, output) != nil {
		return ErrCatalogInvalid
	}
	return nil
}
func rowFor(id string, version int, lookup string, state LifecycleState, value any) (catalogRow, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return catalogRow{}, ErrCatalogInvalid
	}
	hash := SourceChecksum(string(data))
	return catalogRow{ID: id, Version: version, Lookup: lookup, State: state, Hash: hash, Payload: data}, nil
}
func insertImmutable(ctx context.Context, tx catalogTx, table string, row catalogRow) error {
	existing, err := tx.get(ctx, table, row.ID, row.Version)
	if err == nil {
		if existing.Hash == row.Hash {
			return nil
		}
		return ErrCatalogConflict
	}
	if !errors.Is(err, ErrCatalogNotFound) {
		return err
	}
	return tx.insert(ctx, table, row)
}

// PrepareSource returns the exact sanitized source and checksum used by SaveSource.
// It is idempotent and performs no database operations.
func (c *catalog) PrepareSource(input SourceArtifact) (SourceArtifact, error) {
	if len(input.SanitizedContent) > MaxSourceBytes {
		return SourceArtifact{}, ErrCatalogInvalid
	}
	var s SourceArtifact
	safeText, err := (&textSanitizer{redactor: c.redactor}).sanitizeServiceText(input.SanitizedContent)
	if err != nil {
		return SourceArtifact{}, ErrCatalogInvalid
	}
	input.SanitizedContent = safeText
	if err := c.clean(input, &s); err != nil {
		return s, err
	}
	s.Checksum = SourceChecksum(s.SanitizedContent)
	if s.Validate() != nil {
		return SourceArtifact{}, ErrCatalogInvalid
	}
	return s, nil
}
func (c *catalog) SaveSource(ctx context.Context, input SourceArtifact) error {
	s, err := c.PrepareSource(input)
	if err != nil {
		return err
	}
	row, _ := rowFor(s.ID, 0, s.Checksum, "", s)
	return c.backend.write(ctx, func(tx catalogTx) error {
		old, err := tx.lookup(ctx, "sources", s.Checksum)
		if err == nil {
			if old.ID == s.ID {
				return nil
			}
			if _, idErr := tx.get(ctx, "sources", s.ID, 0); idErr == nil {
				return ErrCatalogConflict
			} else if !errors.Is(idErr, ErrCatalogNotFound) {
				return idErr
			}
			return nil
		}
		if !errors.Is(err, ErrCatalogNotFound) {
			return err
		}
		return insertImmutable(ctx, tx, "sources", row)
	})
}
func (c *catalog) GetSourceByChecksum(ctx context.Context, checksum string) (out SourceArtifact, err error) {
	err = c.backend.read(ctx, func(tx catalogTx) error {
		row, e := tx.lookup(ctx, "sources", checksum)
		if e != nil {
			return e
		}
		return decodeRow(row, &out)
	})
	return
}
func decodeRow(row catalogRow, out any) error {
	if json.Unmarshal(row.Payload, out) != nil {
		return ErrCatalogUnavailable
	}
	return nil
}
func (c *catalog) SaveDigest(ctx context.Context, input PlaybookDigest) error {
	var d PlaybookDigest
	if err := c.clean(input, &d); err != nil {
		return err
	}
	d.ContentHash = ""
	d.ContentHash, _ = CanonicalHash(d)
	if d.Validate() != nil {
		return ErrCatalogInvalid
	}
	row, _ := rowFor(d.ID, 0, "", "", d)
	return c.backend.write(ctx, func(tx catalogTx) error {
		if _, err := tx.get(ctx, "sources", d.SourceID, 0); err != nil {
			return err
		}
		return insertImmutable(ctx, tx, "digests", row)
	})
}
func (c *catalog) preparePlaybook(input NormalizedPlaybook) (NormalizedPlaybook, error) {
	var p NormalizedPlaybook
	if err := c.clean(input, &p); err != nil {
		return p, err
	}
	p.CanonicalHash = ""
	p.CanonicalHash, _ = CanonicalHash(p)
	if p.Validate() != nil {
		return p, ErrCatalogInvalid
	}
	if p.Lifecycle != LifecycleNormalized {
		return p, ErrInvalidTransition
	}
	return p, nil
}
func savePlaybook(ctx context.Context, tx catalogTx, p NormalizedPlaybook) error {
	for _, sourceID := range p.SourceIDs {
		if _, err := tx.get(ctx, "sources", sourceID, 0); err != nil {
			return err
		}
	}
	if existing, err := tx.lookup(ctx, "playbooks", p.CanonicalHash); err == nil {
		if existing.ID != p.ID || existing.Version != p.Version {
			return ErrCatalogConflict
		}
	} else if !errors.Is(err, ErrCatalogNotFound) {
		return err
	}
	row, _ := rowFor(p.ID, p.Version, p.CanonicalHash, p.Lifecycle, p)
	if err := insertImmutable(ctx, tx, "playbooks", row); err != nil {
		return err
	}
	for _, step := range p.Steps {
		r, _ := rowFor(catalogTupleID(p.ID, step.ID), p.Version, p.ID, "", step)
		if err := insertImmutable(ctx, tx, "steps", r); err != nil {
			return err
		}
	}
	for i, binding := range p.Applicability {
		r, _ := rowFor(catalogTupleID(p.ID, fmt.Sprint(i)), p.Version, p.ID, "", binding)
		if err := insertImmutable(ctx, tx, "bindings", r); err != nil {
			return err
		}
	}
	return nil
}
func (c *catalog) SavePlaybook(ctx context.Context, input NormalizedPlaybook) error {
	p, err := c.preparePlaybook(input)
	if err != nil {
		return err
	}
	return c.backend.write(ctx, func(tx catalogTx) error { return savePlaybook(ctx, tx, p) })
}
func (c *catalog) GetPlaybook(ctx context.Context, id string, version int) (out NormalizedPlaybook, err error) {
	if requireIdentifier("id", id) != nil || version <= 0 {
		return out, ErrCatalogInvalid
	}
	err = c.backend.read(ctx, func(tx catalogTx) error {
		row, e := tx.get(ctx, "playbooks", id, version)
		if e != nil {
			return e
		}
		if e = decodeRow(row, &out); e != nil {
			return e
		}
		out.Lifecycle = row.State
		return nil
	})
	return
}

func (c *catalog) GetPlaybookByHash(ctx context.Context, hash string) (out NormalizedPlaybook, err error) {
	if len(hash) != 64 {
		return out, ErrCatalogInvalid
	}
	err = c.backend.read(ctx, func(tx catalogTx) error {
		row, e := tx.lookup(ctx, "playbooks", hash)
		if e != nil {
			return e
		}
		if e = decodeRow(row, &out); e != nil {
			return e
		}
		out.Lifecycle = row.State
		return nil
	})
	return
}

func catalogTupleID(parts ...string) string {
	data, _ := json.Marshal(parts)
	return "record-" + SourceChecksum(string(data))
}
func legalTransition(from, to LifecycleState) bool {
	switch from {
	case LifecycleNormalized:
		return to == LifecycleReview
	case LifecycleReview:
		return to == LifecycleActive || to == LifecycleRejected
	case LifecycleActive:
		return to == LifecycleRetired
	}
	return false
}
func transition(ctx context.Context, tx catalogTx, id string, version int, to LifecycleState, actor string) error {
	if requireIdentifier("id", id) != nil || version <= 0 || strings.TrimSpace(actor) == "" || len(actor) > MaxIdentifierBytes || strings.ContainsAny(actor, "\r\n\x00") {
		return ErrCatalogInvalid
	}
	row, err := tx.get(ctx, "playbooks", id, version)
	if err != nil {
		return err
	}
	if !legalTransition(row.State, to) {
		return ErrInvalidTransition
	}
	audit := LifecycleAudit{id, version, row.State, to, actor, time.Now().UTC()}
	r, _ := rowFor(catalogTupleID(id, string(to)), version, id, "", audit)
	if err := tx.insert(ctx, "approvals", r); err != nil {
		return err
	}
	return tx.state(ctx, id, version, to)
}
func (c *catalog) Transition(ctx context.Context, id string, version int, to LifecycleState, actor string) error {
	return c.backend.write(ctx, func(tx catalogTx) error { return transition(ctx, tx, id, version, to, c.redactor.SanitizeText(actor)) })
}
func catalogLimit(limit int) (int, error) {
	if limit < 0 || limit > MaxCollectionItems {
		return 0, ErrCatalogInvalid
	}
	if limit == 0 {
		return MaxCollectionItems, nil
	}
	return limit, nil
}
func (c *catalog) List(ctx context.Context, limit int) ([]NormalizedPlaybook, error) {
	return c.list(ctx, MatchQuery{Limit: limit}, false)
}
func (c *catalog) ListActive(ctx context.Context, q MatchQuery) ([]NormalizedPlaybook, error) {
	if q.Validate() != nil {
		return nil, ErrCatalogInvalid
	}
	return c.list(ctx, q, true)
}
func (c *catalog) list(ctx context.Context, q MatchQuery, active bool) ([]NormalizedPlaybook, error) {
	limit, err := catalogLimit(q.Limit)
	if err != nil {
		return nil, err
	}
	out := make([]NormalizedPlaybook, 0)
	state := LifecycleState("")
	if active {
		state = LifecycleActive
	}
	err = c.backend.read(ctx, func(tx catalogTx) error {
		return tx.each(ctx, "playbooks", state, func(row catalogRow) (bool, error) {
			var p NormalizedPlaybook
			if err := decodeRow(row, &p); err != nil {
				return false, err
			}
			p.Lifecycle = row.State
			if !active || matchesPlaybook(p, q) {
				out = append(out, p)
			}
			return len(out) < limit, nil
		})
	})
	return out, err
}
func matchesPlaybook(p NormalizedPlaybook, q MatchQuery) bool {
	if p.Lifecycle != LifecycleActive || p.Confidence < q.MinConfidence {
		return false
	}
	if len(p.FailureCategories) > 0 {
		matched := false
		for _, category := range p.FailureCategories {
			if category == q.FailureCategory {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	for _, selector := range q.Selectors {
		if !selectorMatchesQuery(selector, q) {
			return false
		}
	}
	if len(p.Applicability) == 0 {
		return true
	}
	for _, s := range p.Applicability {
		if selectorMatchesQuery(s, q) {
			return true
		}
	}

	return false
}
func (c *catalog) RecordLearningCandidate(ctx context.Context, input LearningCandidate) error {
	var candidate LearningCandidate
	if err := c.clean(input, &candidate); err != nil {
		return err
	}
	p, err := c.preparePlaybook(candidate.Playbook)
	if err != nil {
		return err
	}
	candidate.Playbook = p
	if candidate.Validate() != nil {
		return ErrCatalogInvalid
	}
	row, _ := rowFor(candidate.ID, 0, candidate.IdempotencyKey, "", candidate)
	return c.backend.write(ctx, func(tx catalogTx) error {
		if _, err := tx.get(ctx, "resolution_runs", candidate.SourceRunID, 0); err != nil {
			return err
		}
		if candidate.Outcome != LearningOutcomeVerifiedSuccess {
			return ErrCatalogInvalid
		}
		old, err := tx.lookup(ctx, "learning_candidates", candidate.IdempotencyKey)
		if err == nil {
			if old.Hash == row.Hash {
				return nil
			}
			return ErrCatalogConflict
		}
		if !errors.Is(err, ErrCatalogNotFound) {
			return err
		}
		if _, err := tx.get(ctx, "playbooks", p.ID, p.Version); err == nil {
			return ErrCatalogConflict
		} else if !errors.Is(err, ErrCatalogNotFound) {
			return err
		}
		if err := tx.insert(ctx, "learning_candidates", row); err != nil {
			return err
		}
		if err := savePlaybook(ctx, tx, p); err != nil {
			return err
		}
		if err := transition(ctx, tx, p.ID, p.Version, LifecycleReview, "learning"); err != nil {
			return err
		}
		relation := Relation{ID: catalogTupleID(candidate.ID, "lineage"), FromID: candidate.SourceRunID, ToID: p.ID, Kind: "learned_from"}
		r, _ := rowFor(relation.ID, 0, "", "", relation)
		return tx.insert(ctx, "relations", r)
	})
}
func (c *catalog) GetLearningCandidate(ctx context.Context, key string) (out LearningCandidate, err error) {
	err = c.backend.read(ctx, func(tx catalogTx) error {
		row, e := tx.lookup(ctx, "learning_candidates", key)
		if e != nil {
			return e
		}
		return decodeRow(row, &out)
	})
	return
}
func (c *catalog) RecordRelation(ctx context.Context, input Relation) error {
	var v Relation
	if err := c.clean(input, &v); err != nil {
		return err
	}
	for _, id := range []string{v.ID, v.FromID, v.ToID, v.Kind} {
		if requireIdentifier("relation", id) != nil {
			return ErrCatalogInvalid
		}
	}
	return c.record(ctx, "relations", v.ID, v)
}

// RecordFinding refreshes the current finding projection. Evidence and resolution
// records remain immutable snapshots with independently scoped IDs.
func (c *catalog) RecordFinding(ctx context.Context, input FindingRecord) error {
	var v FindingRecord
	if err := c.clean(input, &v); err != nil {
		return err
	}
	if requireIdentifier("finding", v.ID) != nil || v.Query.Validate() != nil || validateEvidenceRefs("finding", v.Evidence) != nil || boundText("summary", v.Summary) != nil {
		return ErrCatalogInvalid
	}
	row, err := rowFor(v.ID, 0, "", "", v)
	if err != nil {
		return err
	}
	return c.backend.write(ctx, func(tx catalogTx) error { return tx.replaceFinding(ctx, row) })
}
func (c *catalog) RecordEvidence(ctx context.Context, input EvidenceRef) error {
	var v EvidenceRef
	if err := c.clean(input, &v); err != nil {
		return err
	}
	v.Hash = ""
	v.Hash, _ = CanonicalHash(v)
	if v.Validate() != nil {
		return ErrCatalogInvalid
	}
	return c.record(ctx, "evidence_snapshots", v.ID, v)
}
func (c *catalog) record(ctx context.Context, table, id string, v any) error {
	row, err := rowFor(id, 0, "", "", v)
	if err != nil {
		return err
	}
	return c.backend.write(ctx, func(tx catalogTx) error { return insertImmutable(ctx, tx, table, row) })
}
func (c *catalog) RecordResolution(ctx context.Context, input ResolutionPlan) error {
	var v ResolutionPlan
	if err := c.clean(input, &v); err != nil {
		return err
	}
	if v.Validate() != nil {
		return ErrCatalogInvalid
	}
	row, _ := rowFor(v.ID, 0, v.FindingID, "", v)
	return c.backend.write(ctx, func(tx catalogTx) error {
		if _, err := tx.get(ctx, "playbooks", v.PlaybookID, v.PlaybookVersion); err != nil {
			return err
		}
		if _, err := tx.get(ctx, "findings", v.FindingID, 0); err != nil {
			return err
		}
		if err := insertImmutable(ctx, tx, "resolution_runs", row); err != nil {
			return err
		}
		for _, s := range v.Steps {
			r, _ := rowFor(catalogTupleID(v.ID, s.ID), 0, v.ID, "", s)
			if err := insertImmutable(ctx, tx, "resolution_steps", r); err != nil {
				return err
			}
		}
		for _, e := range v.Evidence {
			e.Hash = ""
			e.Hash, _ = CanonicalHash(e)
			r, _ := rowFor(e.ID, 0, "", "", e)
			if err := insertImmutable(ctx, tx, "evidence_snapshots", r); err != nil {
				return err
			}
		}
		return nil
	})
}
func (c *catalog) Stats(ctx context.Context) (out CatalogStats, err error) {
	err = c.backend.read(ctx, func(tx catalogTx) error {
		for _, item := range []struct {
			table string
			state LifecycleState
			dest  *int
		}{{"sources", "", &out.Sources}, {"digests", "", &out.Digests}, {"playbooks", "", &out.Playbooks}, {"playbooks", LifecycleActive, &out.ActivePlaybooks}, {"playbooks", LifecycleReview, &out.ReviewPlaybooks}, {"playbooks", LifecycleRejected, &out.RejectedPlaybooks}, {"playbooks", LifecycleRetired, &out.RetiredPlaybooks}, {"learning_candidates", "", &out.LearningCandidates}} {
			n, e := tx.count(ctx, item.table, item.state)
			if e != nil {
				return e
			}
			*item.dest = n
		}
		return nil
	})
	return
}

type ResolutionOutcomeRecord struct {
	RunID        string `json:"run_id"`
	ProposalID   string `json:"proposal_id"`
	Status       string `json:"status"`
	Verification string `json:"verification"`
	Message      string `json:"message"`
}

func (c *catalog) GetResolution(ctx context.Context, id string) (out ResolutionPlan, err error) {
	err = c.backend.read(ctx, func(tx catalogTx) error {
		row, e := tx.get(ctx, "resolution_runs", id, 0)
		if e != nil {
			return e
		}
		return decodeRow(row, &out)
	})
	return
}
func (c *catalog) RecordResolutionOutcome(ctx context.Context, input ResolutionOutcomeRecord) error {
	var v ResolutionOutcomeRecord
	if err := c.clean(input, &v); err != nil {
		return err
	}
	if requireIdentifier("run", v.RunID) != nil || requireIdentifier("proposal", v.ProposalID) != nil || requireIdentifier("status", v.Status) != nil || boundText("verification", v.Verification) != nil || boundText("message", v.Message) != nil {
		return ErrCatalogInvalid
	}
	if !validCatalogOutcome(v) {
		return ErrCatalogInvalid
	}
	row, _ := rowFor(catalogTupleID(v.RunID, v.ProposalID), 0, v.RunID, "", v)
	return c.backend.write(ctx, func(tx catalogTx) error {
		if _, err := tx.get(ctx, "resolution_runs", v.RunID, 0); err != nil {
			return err
		}
		return insertImmutable(ctx, tx, "feedback", row)
	})
}

func validCatalogOutcome(v ResolutionOutcomeRecord) bool {
	switch v.Status {
	case "COMPLETED", "FAILED", "STALE", "REJECTED", "EXPIRED":
	default:
		return false
	}
	switch v.Verification {
	case "VERIFIED":
		return v.Status == "COMPLETED"
	case "FAILED", "UNAVAILABLE", "UNVERIFIED", "":
		return true
	default:
		return false
	}
}

var catalogURLPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)

func (c *catalog) cleanURLs(value any) any {
	switch v := value.(type) {
	case string:
		return catalogURLPattern.ReplaceAllStringFunc(v, c.redactor.SanitizeURL)
	case map[string]any:
		for k, item := range v {
			v[k] = c.cleanURLs(item)
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = c.cleanURLs(item)
		}
		return v
	default:
		return v
	}
}
func selectorMatchesQuery(s ResourceSelector, q MatchQuery) bool {
	if s.Namespace != "" && s.Namespace != q.Namespace || s.Kind != "" && canonicalKind(s.Kind) != canonicalKind(q.Kind) || s.Name != "" && s.Name != q.Name {
		return false
	}
	selector, err := labels.Parse(s.LabelSelector)
	return err == nil && selector.Matches(labels.Set(q.Labels))
}
