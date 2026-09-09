package playbook

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
)

const (
	MaxIdentifierBytes = 256
	MaxTextBytes       = 64 * 1024
	MaxSourceBytes     = 1 << 20
	MaxCollectionItems = 256
	MaxCatalogCount    = 1_000_000_000
)

type LifecycleState string

const (
	LifecycleReceived   LifecycleState = "RECEIVED"
	LifecycleDigested   LifecycleState = "DIGESTED"
	LifecycleNormalized LifecycleState = "NORMALIZED"
	LifecycleReview     LifecycleState = "REVIEW"
	LifecycleActive     LifecycleState = "ACTIVE"
	LifecycleRejected   LifecycleState = "REJECTED"
	LifecycleRetired    LifecycleState = "RETIRED"
)

func (s LifecycleState) Validate() error {
	switch s {
	case LifecycleReceived, LifecycleDigested, LifecycleNormalized, LifecycleReview,
		LifecycleActive, LifecycleRejected, LifecycleRetired:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidLifecycleState, s)
	}
}

type SourceArtifact struct {
	ID               string            `json:"id"`
	Kind             string            `json:"kind"`
	Origin           string            `json:"origin"`
	MediaType        string            `json:"media_type"`
	Checksum         string            `json:"checksum"`
	ParserVersion    string            `json:"parser_version"`
	Provenance       map[string]string `json:"provenance,omitempty"`
	SanitizedContent string            `json:"sanitized_content"`
	ImportedAt       time.Time         `json:"imported_at,omitempty"`
}

func (s SourceArtifact) Validate() error {
	if err := requireIdentifier("source id", s.ID); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"source kind", s.Kind},
		{"source origin", s.Origin},
		{"source media type", s.MediaType},
		{"source checksum", s.Checksum},
		{"parser version", s.ParserVersion},
	} {
		if err := requireText(field.name, field.value); err != nil {
			return err
		}
	}
	if err := validateStringMap("source provenance", s.Provenance); err != nil {
		return err
	}
	if strings.TrimSpace(s.SanitizedContent) == "" {
		return fmt.Errorf("%w: sanitized content", ErrMissingRequired)
	}
	if len(s.SanitizedContent) > MaxSourceBytes {
		return fmt.Errorf("%w: sanitized content", ErrTextTooLong)
	}
	return nil
}

type ResourceSelector struct {
	Namespace     string `json:"namespace,omitempty"`
	Kind          string `json:"kind,omitempty"`
	Name          string `json:"name,omitempty"`
	LabelSelector string `json:"label_selector,omitempty"`
}

func (s ResourceSelector) Validate() error {
	if err := optionalKubernetesNamespace("selector namespace", s.Namespace); err != nil {
		return err
	}
	if err := optionalKubernetesKind("selector kind", s.Kind); err != nil {
		return err
	}
	if err := optionalKubernetesName("selector name", s.Name); err != nil {
		return err
	}
	return validateLabelSelector("selector label selector", s.LabelSelector)
}

type EvidenceRef struct {
	ID              string `json:"id"`
	SourceID        string `json:"source_id,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name,omitempty"`
	UID             string `json:"uid,omitempty"`
	ResourceVersion string `json:"resource_version,omitempty"`
	FieldPath       string `json:"field_path,omitempty"`
	Summary         string `json:"summary,omitempty"`
	Hash            string `json:"hash,omitempty"`
}

func (e EvidenceRef) Validate() error {
	if err := requireIdentifier("evidence id", e.ID); err != nil {
		return err
	}
	if err := optionalIdentifier("evidence source id", e.SourceID); err != nil {
		return err
	}
	if err := optionalKubernetesKind("evidence kind", e.Kind); err != nil {
		return err
	}
	if err := optionalKubernetesNamespace("evidence namespace", e.Namespace); err != nil {
		return err
	}
	if err := optionalKubernetesName("evidence name", e.Name); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"evidence uid", e.UID},
		{"evidence resource version", e.ResourceVersion},
		{"evidence hash", e.Hash},
	} {
		if err := optionalIdentifier(field.name, field.value); err != nil {
			return err
		}
	}
	return boundTexts([]namedString{
		{"evidence field path", e.FieldPath},
		{"evidence summary", e.Summary},
	})
}

type DigestStep struct {
	ID             string             `json:"id,omitempty"`
	Order          int                `json:"order,omitempty"`
	Title          string             `json:"title,omitempty"`
	Description    string             `json:"description,omitempty"`
	Action         string             `json:"action,omitempty"`
	Command        string             `json:"command,omitempty"`
	TargetReplicas *int32             `json:"target_replicas,omitempty"`
	Targets        []ResourceSelector `json:"targets,omitempty"`
	EvidenceRefs   []string           `json:"evidence_refs,omitempty"`
	Preconditions  []string           `json:"preconditions,omitempty"`
	Postconditions []string           `json:"postconditions,omitempty"`
	ObserveOnly    bool               `json:"observe_only,omitempty"`
	Confidence     float64            `json:"confidence,omitempty"`
}

func (s DigestStep) Validate() error {
	if err := validateTargetReplicas(s.Action, s.TargetReplicas); err != nil {
		return err
	}
	if err := validateConfidence("digest step confidence", s.Confidence); err != nil {
		return err
	}
	if err := optionalIdentifier("digest step id", s.ID); err != nil {
		return err
	}
	if err := boundTexts([]namedString{
		{"digest step title", s.Title},
		{"digest step description", s.Description},
		{"digest step action", s.Action},
		{"digest step command", s.Command},
	}); err != nil {
		return err
	}
	if err := validateSelectors("digest step targets", s.Targets); err != nil {
		return err
	}
	if err := validateIdentifierSlices([]namedStringSlice{
		{"digest step evidence refs", s.EvidenceRefs},
	}); err != nil {
		return err
	}
	return validateStringSlices([]namedStringSlice{
		{"digest step preconditions", s.Preconditions},
		{"digest step postconditions", s.Postconditions},
	})
}

type PlaybookDigest struct {
	ID                  string            `json:"id"`
	SourceID            string            `json:"source_id"`
	Title               string            `json:"title"`
	Summary             string            `json:"summary"`
	Lineage             []string          `json:"lineage,omitempty"`
	FailureCategories   []string          `json:"failure_categories,omitempty"`
	TriggerConditions   []string          `json:"trigger_conditions,omitempty"`
	Evidence            []EvidenceRef     `json:"evidence,omitempty"`
	RootCauseHypotheses []string          `json:"root_cause_hypotheses,omitempty"`
	Preconditions       []string          `json:"preconditions,omitempty"`
	Steps               []DigestStep      `json:"steps,omitempty"`
	Postconditions      []string          `json:"postconditions,omitempty"`
	Rollback            string            `json:"rollback,omitempty"`
	ApprovalIntent      string            `json:"approval_intent,omitempty"`
	Unknowns            []string          `json:"unknowns,omitempty"`
	Confidence          float64           `json:"confidence"`
	Model               string            `json:"model,omitempty"`
	Task                string            `json:"task,omitempty"`
	PromptSchemaVersion string            `json:"prompt_schema_version,omitempty"`
	ContentHash         string            `json:"content_hash,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	CreatedAt           time.Time         `json:"created_at,omitempty"`
}

func (d PlaybookDigest) Validate() error {
	if err := requireIdentifier("digest id", d.ID); err != nil {
		return err
	}
	if err := requireIdentifier("digest source id", d.SourceID); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"digest title", d.Title},
		{"digest summary", d.Summary},
	} {
		if err := requireText(field.name, field.value); err != nil {
			return err
		}
	}
	if err := validateConfidence("digest confidence", d.Confidence); err != nil {
		return err
	}
	if err := boundTexts([]namedString{
		{"digest rollback", d.Rollback},
		{"digest approval intent", d.ApprovalIntent},
		{"digest model", d.Model},
		{"digest task", d.Task},
		{"digest prompt schema", d.PromptSchemaVersion},
	}); err != nil {
		return err
	}
	if err := optionalIdentifier("digest content hash", d.ContentHash); err != nil {
		return err
	}
	if err := validateIdentifierSlices([]namedStringSlice{
		{"digest lineage", d.Lineage},
	}); err != nil {
		return err
	}
	if err := validateStringSlices([]namedStringSlice{
		{"digest failure categories", d.FailureCategories},
		{"digest trigger conditions", d.TriggerConditions},
		{"digest root cause hypotheses", d.RootCauseHypotheses},
		{"digest preconditions", d.Preconditions},
		{"digest postconditions", d.Postconditions},
		{"digest unknowns", d.Unknowns},
	}); err != nil {
		return err
	}
	if err := validateEvidenceRefs("digest evidence", d.Evidence); err != nil {
		return err
	}
	if err := validateDigestSteps("digest steps", d.Steps); err != nil {
		return err
	}
	return validateStringMap("digest metadata", d.Metadata)
}

type NormalizedStep struct {
	ID             string             `json:"id"`
	Order          int                `json:"order"`
	Title          string             `json:"title,omitempty"`
	Description    string             `json:"description,omitempty"`
	Action         string             `json:"action"`
	Command        string             `json:"command,omitempty"`
	TargetReplicas *int32             `json:"target_replicas,omitempty"`
	Targets        []ResourceSelector `json:"targets,omitempty"`
	EvidenceRefs   []string           `json:"evidence_refs,omitempty"`
	Preconditions  []string           `json:"preconditions,omitempty"`
	Postconditions []string           `json:"postconditions,omitempty"`
	ObserveOnly    bool               `json:"observe_only,omitempty"`
	RequiresReview bool               `json:"requires_review,omitempty"`
	Confidence     float64            `json:"confidence,omitempty"`
}

func (s NormalizedStep) Validate() error {
	if err := validateTargetReplicas(s.Action, s.TargetReplicas); err != nil {
		return err
	}
	if err := requireIdentifier("step id", s.ID); err != nil {
		return err
	}
	if strings.TrimSpace(s.Action) == "" {
		return fmt.Errorf("%w: step action", ErrMissingRequired)
	}
	if err := validateConfidence("step confidence", s.Confidence); err != nil {
		return err
	}
	if err := boundTexts([]namedString{
		{"step title", s.Title},
		{"step description", s.Description},
		{"step action", s.Action},
		{"step command", s.Command},
	}); err != nil {
		return err
	}
	if err := validateSelectors("step targets", s.Targets); err != nil {
		return err
	}
	if err := validateIdentifierSlices([]namedStringSlice{
		{"step evidence refs", s.EvidenceRefs},
	}); err != nil {
		return err
	}
	return validateStringSlices([]namedStringSlice{
		{"step preconditions", s.Preconditions},
		{"step postconditions", s.Postconditions},
	})
}

type NormalizedPlaybook struct {
	ID                string             `json:"id"`
	Version           int                `json:"version"`
	Lifecycle         LifecycleState     `json:"lifecycle"`
	Title             string             `json:"title"`
	Summary           string             `json:"summary"`
	SourceIDs         []string           `json:"source_ids,omitempty"`
	Lineage           []string           `json:"lineage,omitempty"`
	FailureCategories []string           `json:"failure_categories,omitempty"`
	TriggerConditions []string           `json:"trigger_conditions,omitempty"`
	Applicability     []ResourceSelector `json:"applicability,omitempty"`
	Evidence          []EvidenceRef      `json:"evidence,omitempty"`
	Preconditions     []string           `json:"preconditions,omitempty"`
	Steps             []NormalizedStep   `json:"steps,omitempty"`
	Postconditions    []string           `json:"postconditions,omitempty"`
	Rollback          string             `json:"rollback,omitempty"`
	ApprovalPolicy    string             `json:"approval_policy,omitempty"`
	Unknowns          []string           `json:"unknowns,omitempty"`
	Confidence        float64            `json:"confidence"`
	CanonicalHash     string             `json:"canonical_hash,omitempty"`
	CreatedAt         time.Time          `json:"created_at,omitempty"`
}

func (p NormalizedPlaybook) Validate() error {
	if err := requireIdentifier("playbook id", p.ID); err != nil {
		return err
	}
	if p.Version <= 0 {
		return fmt.Errorf("%w: playbook version", ErrInvalidIdentifier)
	}
	if err := p.Lifecycle.Validate(); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"playbook title", p.Title},
		{"playbook summary", p.Summary},
	} {
		if err := requireText(field.name, field.value); err != nil {
			return err
		}
	}
	if err := validateConfidence("playbook confidence", p.Confidence); err != nil {
		return err
	}
	if len(p.Steps) == 0 {
		return fmt.Errorf("%w: playbook steps", ErrMissingRequired)
	}
	if err := boundTexts([]namedString{
		{"playbook rollback", p.Rollback},
		{"playbook approval policy", p.ApprovalPolicy},
	}); err != nil {
		return err
	}
	if err := optionalIdentifier("playbook canonical hash", p.CanonicalHash); err != nil {
		return err
	}
	if err := validateIdentifierSlices([]namedStringSlice{
		{"playbook source ids", p.SourceIDs},
		{"playbook lineage", p.Lineage},
	}); err != nil {
		return err
	}
	if err := validateStringSlices([]namedStringSlice{
		{"playbook failure categories", p.FailureCategories},
		{"playbook trigger conditions", p.TriggerConditions},
		{"playbook preconditions", p.Preconditions},
		{"playbook postconditions", p.Postconditions},
		{"playbook unknowns", p.Unknowns},
	}); err != nil {
		return err
	}
	if err := validateSelectors("playbook applicability", p.Applicability); err != nil {
		return err
	}
	if err := validateEvidenceRefs("playbook evidence", p.Evidence); err != nil {
		return err
	}
	if err := validateNormalizedSteps("playbook steps", p.Steps); err != nil {
		return err
	}
	return nil
}

type ResolutionPlan struct {
	ID               string           `json:"id"`
	FindingID        string           `json:"finding_id"`
	PlaybookID       string           `json:"playbook_id"`
	PlaybookVersion  int              `json:"playbook_version"`
	Target           ResourceSelector `json:"target"`
	TargetUID        string           `json:"target_uid"`
	ResourceVersion  string           `json:"resource_version"`
	Evidence         []EvidenceRef    `json:"evidence,omitempty"`
	Rationale        string           `json:"rationale"`
	Steps            []NormalizedStep `json:"steps"`
	RequiresApproval bool             `json:"requires_approval"`
	Confidence       float64          `json:"confidence"`
	Uncertainties    []string         `json:"uncertainties,omitempty"`
	Preconditions    []string         `json:"preconditions,omitempty"`
	Postconditions   []string         `json:"postconditions,omitempty"`
	Verification     []string         `json:"verification,omitempty"`
	CreatedAt        time.Time        `json:"created_at,omitempty"`
}

func (p ResolutionPlan) Validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"resolution id", p.ID},
		{"finding id", p.FindingID},
		{"playbook id", p.PlaybookID},
		{"target uid", p.TargetUID},
		{"resource version", p.ResourceVersion},
	} {
		if err := requireIdentifier(field.name, field.value); err != nil {
			return err
		}
	}
	if err := requireText("resolution rationale", p.Rationale); err != nil {
		return err
	}
	if p.PlaybookVersion <= 0 {
		return fmt.Errorf("%w: playbook version", ErrInvalidIdentifier)
	}
	if len(p.Evidence) == 0 {
		return fmt.Errorf("%w: resolution evidence", ErrMissingRequired)
	}
	if len(p.Steps) == 0 {
		return fmt.Errorf("%w: resolution steps", ErrMissingRequired)
	}
	if err := validateConfidence("resolution confidence", p.Confidence); err != nil {
		return err
	}
	if err := p.Target.Validate(); err != nil {
		return err
	}
	if err := validateEvidenceRefs("resolution evidence", p.Evidence); err != nil {
		return err
	}
	if err := validateNormalizedSteps("resolution steps", p.Steps); err != nil {
		return err
	}
	if err := validateResolutionSteps(p); err != nil {
		return err
	}
	if err := validateStringSlices([]namedStringSlice{{"resolution uncertainties", p.Uncertainties}}); err != nil {
		return err
	}
	for _, criteria := range []namedStringSlice{
		{"resolution preconditions", p.Preconditions},
		{"resolution postconditions", p.Postconditions},
		{"resolution verification", p.Verification},
	} {
		if err := validateRequiredTextSlice(criteria.name, criteria.values); err != nil {
			return err
		}
	}
	return nil
}

type LearningOutcome string

const (
	LearningOutcomeVerifiedSuccess LearningOutcome = "VERIFIED_SUCCESS"
	LearningOutcomeVerifiedFailure LearningOutcome = "VERIFIED_FAILURE"
	LearningOutcomeAmbiguous       LearningOutcome = "AMBIGUOUS"
)

func (o LearningOutcome) Validate() error {
	switch o {
	case LearningOutcomeVerifiedSuccess, LearningOutcomeVerifiedFailure, LearningOutcomeAmbiguous:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidLearningOutcome, o)
	}
}

type LearningCandidate struct {
	ID             string             `json:"id"`
	SourceRunID    string             `json:"source_run_id"`
	Outcome        LearningOutcome    `json:"outcome"`
	Playbook       NormalizedPlaybook `json:"playbook"`
	BeforeEvidence []EvidenceRef      `json:"before_evidence,omitempty"`
	AfterEvidence  []EvidenceRef      `json:"after_evidence,omitempty"`
	ExecutedSteps  []NormalizedStep   `json:"executed_steps,omitempty"`
	UserFeedback   string             `json:"user_feedback,omitempty"`
	Model          string             `json:"model,omitempty"`
	Task           string             `json:"task,omitempty"`
	IdempotencyKey string             `json:"idempotency_key,omitempty"`
	CreatedAt      time.Time          `json:"created_at,omitempty"`
}

func (c LearningCandidate) Validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"learning candidate id", c.ID},
		{"source run id", c.SourceRunID},
		{"idempotency key", c.IdempotencyKey},
	} {
		if err := requireIdentifier(field.name, field.value); err != nil {
			return err
		}
	}
	if err := c.Outcome.Validate(); err != nil {
		return err
	}
	if err := c.Playbook.Validate(); err != nil {
		return err
	}
	if err := boundTexts([]namedString{
		{"user feedback", c.UserFeedback},
		{"model", c.Model},
		{"task", c.Task},
	}); err != nil {
		return err
	}
	if err := validateEvidenceRefs("learning before evidence", c.BeforeEvidence); err != nil {
		return err
	}
	if err := validateEvidenceRefs("learning after evidence", c.AfterEvidence); err != nil {
		return err
	}
	if err := validateNormalizedSteps("learning executed steps", c.ExecutedSteps); err != nil {
		return err
	}
	return nil
}

type MatchQuery struct {
	FindingID       string             `json:"finding_id,omitempty"`
	FailureCategory string             `json:"failure_category,omitempty"`
	Namespace       string             `json:"namespace,omitempty"`
	Kind            string             `json:"kind,omitempty"`
	Name            string             `json:"name,omitempty"`
	Labels          map[string]string  `json:"labels,omitempty"`
	Selectors       []ResourceSelector `json:"selectors,omitempty"`
	MinConfidence   float64            `json:"min_confidence,omitempty"`
	Limit           int                `json:"limit,omitempty"`
}

func (q MatchQuery) Validate() error {
	if err := validateConfidence("match query confidence", q.MinConfidence); err != nil {
		return err
	}
	if err := optionalIdentifier("finding id", q.FindingID); err != nil {
		return err
	}
	if err := optionalKubernetesNamespace("query namespace", q.Namespace); err != nil {
		return err
	}
	if err := optionalKubernetesKind("query kind", q.Kind); err != nil {
		return err
	}
	if err := optionalKubernetesName("query name", q.Name); err != nil {
		return err
	}
	if err := boundTexts([]namedString{
		{"failure category", q.FailureCategory},
	}); err != nil {
		return err
	}
	if err := validateStringMap("match labels", q.Labels); err != nil {
		return err
	}
	if err := validateSelectors("match selectors", q.Selectors); err != nil {
		return err
	}
	if q.Limit < 0 || q.Limit > MaxCollectionItems {
		return fmt.Errorf("%w: match query limit", ErrInvalidCount)
	}
	return nil
}

func (s CatalogStats) Validate() error {
	counts := []struct {
		name  string
		value int
	}{
		{"sources", s.Sources},
		{"digests", s.Digests},
		{"playbooks", s.Playbooks},
		{"active playbooks", s.ActivePlaybooks},
		{"review playbooks", s.ReviewPlaybooks},
		{"rejected playbooks", s.RejectedPlaybooks},
		{"retired playbooks", s.RetiredPlaybooks},
		{"learning candidates", s.LearningCandidates},
	}
	for _, count := range counts {
		if count.value < 0 || count.value > MaxCatalogCount {
			return fmt.Errorf("%w: %s", ErrInvalidCount, count.name)
		}
	}
	return nil
}

type namedString struct {
	name  string
	value string
}

type namedStringSlice struct {
	name   string
	values []string
}

func validateStringSlices(slices []namedStringSlice) error {
	for _, slice := range slices {
		if len(slice.values) > MaxCollectionItems {
			return fmt.Errorf("%w: %s", ErrTooManyItems, slice.name)
		}
		for index, value := range slice.values {
			if err := boundText(fmt.Sprintf("%s[%d]", slice.name, index), value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateIdentifierSlices(slices []namedStringSlice) error {
	for _, slice := range slices {
		if len(slice.values) > MaxCollectionItems {
			return fmt.Errorf("%w: %s", ErrTooManyItems, slice.name)
		}
		seen := make(map[string]struct{}, len(slice.values))
		for index, value := range slice.values {
			if err := requireIdentifier(fmt.Sprintf("%s[%d]", slice.name, index), value); err != nil {
				return err
			}
			normalized := strings.TrimSpace(value)
			if _, ok := seen[normalized]; ok {
				return fmt.Errorf("%w: %s[%d]", ErrDuplicateIdentifier, slice.name, index)
			}
			seen[normalized] = struct{}{}
		}
	}
	return nil
}

func validateStringMap(field string, values map[string]string) error {
	if len(values) > MaxCollectionItems {
		return fmt.Errorf("%w: %s", ErrTooManyItems, field)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := boundText(field+" key", key); err != nil {
			return err
		}
		if err := boundText(field+" value", values[key]); err != nil {
			return err
		}
	}
	return nil
}

func validateSelectors(field string, selectors []ResourceSelector) error {
	if len(selectors) > MaxCollectionItems {
		return fmt.Errorf("%w: %s", ErrTooManyItems, field)
	}
	for _, selector := range selectors {
		if err := selector.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceRefs(field string, evidenceRefs []EvidenceRef) error {
	if len(evidenceRefs) > MaxCollectionItems {
		return fmt.Errorf("%w: %s", ErrTooManyItems, field)
	}
	seen := make(map[string]struct{}, len(evidenceRefs))
	for _, evidence := range evidenceRefs {
		if err := evidence.Validate(); err != nil {
			return err
		}
		id := strings.TrimSpace(evidence.ID)
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicateIdentifier, field)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateDigestSteps(field string, steps []DigestStep) error {
	if len(steps) > MaxCollectionItems {
		return fmt.Errorf("%w: %s", ErrTooManyItems, field)
	}
	seen := make(map[string]struct{}, len(steps))
	for _, step := range steps {
		if err := step.Validate(); err != nil {
			return err
		}
		id := strings.TrimSpace(step.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicateIdentifier, field)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateNormalizedSteps(field string, steps []NormalizedStep) error {
	if len(steps) > MaxCollectionItems {
		return fmt.Errorf("%w: %s", ErrTooManyItems, field)
	}
	seen := make(map[string]struct{}, len(steps))
	for _, step := range steps {
		if err := step.Validate(); err != nil {
			return err
		}
		id := strings.TrimSpace(step.ID)
		if _, ok := seen[id]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicateIdentifier, field)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateResolutionSteps(plan ResolutionPlan) error {
	evidenceIDs := make(map[string]struct{}, len(plan.Evidence))
	for _, evidence := range plan.Evidence {
		evidenceIDs[strings.TrimSpace(evidence.ID)] = struct{}{}
	}
	requiresApproval := false
	for _, step := range plan.Steps {
		action, ok := knownActions[strings.TrimSpace(step.Action)]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownAction, step.Action)
		}
		if action == knownActions["ScaleWorkload"] && step.TargetReplicas == nil {
			return fmt.Errorf("%w: target replicas", ErrMissingRequired)
		}
		if step.ObserveOnly && actionRequiresApproval(action) {
			return fmt.Errorf("%w: %s", ErrObserveOnlyMutation, step.ID)
		}
		if strings.TrimSpace(step.Command) != "" {
			return fmt.Errorf("%w: step command", ErrUnsafeCommand)
		}
		if len(step.EvidenceRefs) == 0 {
			return fmt.Errorf("%w: step evidence refs", ErrMissingRequired)
		}
		for _, evidenceRef := range step.EvidenceRefs {
			if _, ok := evidenceIDs[strings.TrimSpace(evidenceRef)]; !ok {
				return fmt.Errorf("%w: step evidence refs", ErrUnresolvedReference)
			}
		}
		if err := validateRequiredTextSlice("step preconditions", step.Preconditions); err != nil {
			return err
		}
		if err := validateRequiredTextSlice("step postconditions", step.Postconditions); err != nil {
			return err
		}
		if actionRequiresApproval(action) {
			requiresApproval = true
		}
		if actionRequiresConcreteTarget(action) && !hasConcreteTarget(action, step.Targets) {
			return fmt.Errorf("%w: mutation target", ErrMissingRequired)
		}
		if actionRequiresConcreteTarget(action) && !targetsMatchSnapshot(action, step.Targets, plan.Target) {
			return fmt.Errorf("%w: mutation target snapshot", ErrUnresolvedReference)
		}
	}
	if requiresApproval && !plan.RequiresApproval {
		return fmt.Errorf("%w: resolution approval", ErrMissingRequired)
	}
	return nil
}

func validateRequiredTextSlice(field string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("%w: %s", ErrMissingRequired, field)
	}
	if len(values) > MaxCollectionItems {
		return fmt.Errorf("%w: %s", ErrTooManyItems, field)
	}
	for index, value := range values {
		if err := requireText(fmt.Sprintf("%s[%d]", field, index), value); err != nil {
			return err
		}
	}
	return nil
}

func validateLabelSelector(field, value string) error {
	if err := boundText(field, value); err != nil {
		return err
	}
	if value == "" {
		return nil
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.Contains(trimmed, "*") || strings.ContainsAny(trimmed, ";&|`$<>\\") {
		return fmt.Errorf("%w: %s", ErrInvalidLabelSelector, field)
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s", ErrInvalidLabelSelector, field)
		}
	}
	selector, err := labels.Parse(trimmed)
	if err != nil || selector.Empty() {
		return fmt.Errorf("%w: %s", ErrInvalidLabelSelector, field)
	}
	requirements, selectable := selector.Requirements()
	if !selectable || len(requirements) == 0 {
		return fmt.Errorf("%w: %s", ErrInvalidLabelSelector, field)
	}
	for _, requirement := range requirements {
		switch requirement.Operator() {
		case selection.Equals, selection.DoubleEquals, selection.In:
		default:
			return fmt.Errorf("%w: %s", ErrInvalidLabelSelector, field)
		}
		values := requirement.ValuesUnsorted()
		if len(values) == 0 {
			return fmt.Errorf("%w: %s", ErrInvalidLabelSelector, field)
		}
		for _, item := range values {
			if strings.TrimSpace(item) == "" || strings.Contains(item, "*") {
				return fmt.Errorf("%w: %s", ErrInvalidLabelSelector, field)
			}
		}
	}
	return nil
}

func optionalKubernetesNamespace(field, value string) error {
	if value == "" {
		return nil
	}
	if strings.TrimSpace(value) != value || len(utilvalidation.IsDNS1123Label(value)) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidIdentifier, field)
	}
	return nil
}

func optionalKubernetesName(field, value string) error {
	if value == "" {
		return nil
	}
	if strings.TrimSpace(value) != value || len(utilvalidation.IsDNS1123Subdomain(value)) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidIdentifier, field)
	}
	return nil
}

func optionalKubernetesKind(field, value string) error {
	if value == "" {
		return nil
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s", ErrInvalidIdentifier, field)
	}
	kind := canonicalKind(value)
	if len(kind) == 0 || len(kind) > MaxIdentifierBytes || kind[0] < 'A' || kind[0] > 'Z' {
		return fmt.Errorf("%w: %s", ErrInvalidIdentifier, field)
	}
	for _, r := range kind[1:] {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		return fmt.Errorf("%w: %s", ErrInvalidIdentifier, field)
	}
	return nil
}

func optionalIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if !validIdentifierText(value) {
		return fmt.Errorf("%w: %s", ErrInvalidIdentifier, field)
	}
	return nil
}

func requireIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" || !validIdentifierText(value) {
		return fmt.Errorf("%w: %s", ErrInvalidIdentifier, field)
	}
	return nil
}

func validIdentifierText(value string) bool {
	if len(value) == 0 || len(value) > MaxIdentifierBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '.', '_', '-', ':':
			continue
		default:
			return false
		}
	}
	return true
}

func requireText(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s", ErrMissingRequired, field)
	}
	return boundText(field, value)
}

func boundTexts(values []namedString) error {
	for _, value := range values {
		if err := boundText(value.name, value.value); err != nil {
			return err
		}
	}
	return nil
}

func boundText(field, value string) error {
	if len(value) > MaxTextBytes {
		return fmt.Errorf("%w: %s", ErrTextTooLong, field)
	}
	return nil
}

func validateConfidence(field string, confidence float64) error {
	if math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0 || confidence > 1 {
		return fmt.Errorf("%w: %s", ErrInvalidConfidence, field)
	}
	return nil
}

type CatalogStats struct {
	Sources            int `json:"sources"`
	Digests            int `json:"digests"`
	Playbooks          int `json:"playbooks"`
	ActivePlaybooks    int `json:"active_playbooks"`
	ReviewPlaybooks    int `json:"review_playbooks"`
	RejectedPlaybooks  int `json:"rejected_playbooks"`
	RetiredPlaybooks   int `json:"retired_playbooks"`
	LearningCandidates int `json:"learning_candidates"`
}

func validateTargetReplicas(action string, replicas *int32) error {
	if replicas == nil {
		return nil
	}
	if strings.TrimSpace(action) != "ScaleWorkload" || *replicas < 0 || *replicas > 10000 {
		return fmt.Errorf("%w: target replicas", ErrInvalidCount)
	}
	return nil
}
