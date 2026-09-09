package playbook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func validateSource(req ImportRequest, v ServiceSettings) (string, error) {
	if len(req.Content) == 0 || len(req.Content) > v.MaxSourceBytes || len(req.Origin) > MaxTextBytes {
		return "", ErrServiceInvalid
	}
	media, _, err := mime.ParseMediaType(req.MediaType)
	if err != nil {
		return "", ErrServiceInvalid
	}
	switch media {
	case "text/markdown":
	case "application/json":
		var value any
		if strictDecode(req.Content, &value) != nil {
			return "", ErrServiceInvalid
		}
		switch value.(type) {
		case map[string]any, []any:
		default:
			return "", ErrServiceInvalid
		}
	case "application/yaml", "application/x-yaml", "text/yaml":
		var node yaml.Node
		d := yaml.NewDecoder(strings.NewReader(req.Content))
		if d.Decode(&node) != nil || len(node.Content) != 1 {
			return "", ErrServiceInvalid
		}
		var extra yaml.Node
		if d.Decode(&extra) != io.EOF {
			return "", ErrServiceInvalid
		}
		if node.Content[0].Kind != yaml.MappingNode && node.Content[0].Kind != yaml.SequenceNode {
			return "", ErrServiceInvalid
		}
		count := 0
		var check func(*yaml.Node, int) bool
		check = func(n *yaml.Node, depth int) bool {
			count++
			if depth > 32 || count > 4096 || n.Kind == yaml.AliasNode {
				return false
			}
			keys := map[string]bool{}
			for i, c := range n.Content {
				if n.Kind == yaml.MappingNode && i%2 == 0 {
					if keys[c.Value] {
						return false
					}
					keys[c.Value] = true
				}
				if !check(c, depth+1) {
					return false
				}
			}
			return true
		}
		if !check(&node, 0) {
			return "", ErrServiceInvalid
		}
	default:
		return "", ErrServiceInvalid
	}
	return media, nil
}

// Import preserves sanitized provenance and produces only a REVIEW version.
func (s *Service) Import(ctx context.Context, req ImportRequest, actor string) (ImportResult, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	v := s.Settings()
	out := ImportResult{}
	if err := s.available(v); err != nil {
		return out, err
	}
	if !validActor(actor) {
		return out, ErrServiceInvalid
	}
	media, err := validateSource(req, v)
	if err != nil {
		return out, err
	}
	origin := req.Origin
	if origin == "" {
		origin = "operator-import"
	}
	source := SourceArtifact{ID: "source-pending", Kind: "import", Origin: origin, MediaType: media, ParserVersion: "v1", SanitizedContent: req.Content, Provenance: map[string]string{"actor": actor}}
	if err = s.clean(source, &source); err != nil {
		return out, err
	}
	// PrepareSource is the authoritative repository redaction/checksum boundary.
	source, err = s.catalog.PrepareSource(source)
	if err != nil {
		return out, err
	}
	source.ID = "source-" + source.Checksum
	existing, err := s.catalog.GetSourceByChecksum(ctx, source.Checksum)
	if err == nil {
		source = existing
	} else if !errors.Is(err, ErrCatalogNotFound) {
		return out, err
	}
	out.Source = source
	id := "playbook-" + source.Checksum
	if p, e := s.catalog.GetPlaybook(ctx, id, 1); e == nil {
		out.Playbook = p
		out.Duplicate = true
		out.Guardrails = s.guardrails(v, p)
		return out, nil
	} else if !errors.Is(e, ErrCatalogNotFound) {
		return out, e
	}
	if err = s.catalog.SaveSource(ctx, source); err != nil {
		return out, err
	}
	var digest PlaybookDigest
	err = s.run(ctx, "digest", map[string]any{"source": source, "output_example": digestOutputExample()}, &digest, v)
	if err != nil {
		if errors.Is(err, ErrServiceInvalid) {
			s.rejectImport(ctx, source, id, "digest_invalid")
		}
		return out, err
	}
	digest, err = s.prepareDigest(digest, id, source.ID, "digest", v)
	if err != nil {
		s.rejectImport(ctx, source, id, "digest_invalid")
		return out, err
	}
	p, err := NormalizeDigest(digest)
	if err != nil {
		s.rejectImport(ctx, source, id, "normalization_invalid")
		return out, ErrServiceInvalid
	}
	s.finishNormalized(&p)
	if reused, found, err := s.reuseImport(ctx, out, p.CanonicalHash, v, actor); err != nil || found {
		return reused, err
	}
	if err = s.catalog.SaveDigest(ctx, digest); err != nil {
		return out, err
	}
	out.Guardrails = s.guardrails(v, p)
	if err = s.catalog.SavePlaybook(ctx, p); err != nil {
		if errors.Is(err, ErrCatalogConflict) {
			if reused, found, lookupErr := s.reuseImport(ctx, out, p.CanonicalHash, v, actor); lookupErr != nil || found {
				return reused, lookupErr
			}
		}
		return out, err
	}
	if err = s.catalog.Transition(ctx, p.ID, p.Version, LifecycleReview, s.safeActor(actor)); err != nil {
		return out, err
	}
	p.Lifecycle = LifecycleReview
	out.Playbook = p
	s.outcome("digest", "imported")
	if !out.Guardrails.Allowed {
		s.outcome("digest", "guardrail_rejected")
	}
	return out, nil
}
func digestOutputExample() PlaybookDigest {
	return PlaybookDigest{ID: "service-assigned", SourceID: "service-assigned", Title: "Concise title", Summary: "Evidence-grounded summary", FailureCategories: []string{"exact scanner category"}, Evidence: []EvidenceRef{{ID: "source-evidence", Summary: "Source observation"}}, Preconditions: []string{"condition"}, Postconditions: []string{"condition"}, Confidence: .8, Steps: []DigestStep{{ID: "step-1", Action: "Manual", Description: "Review unsupported operations", Targets: []ResourceSelector{{Namespace: "default", Kind: "Pod", Name: "exact-name"}}, EvidenceRefs: []string{"source-evidence"}, Preconditions: []string{"condition"}, Postconditions: []string{"condition"}, Confidence: .8}}}
}
func (s *Service) prepareDigest(d PlaybookDigest, id, source, task string, v ServiceSettings) (PlaybookDigest, error) {
	d.ID = id
	d.SourceID = source
	d.Lineage = []string{source}
	d.ContentHash = ""
	d.CreatedAt = time.Time{}
	d.Model = s.provider
	d.Task = "playbook." + task
	d.PromptSchemaVersion = "v1"
	d.Metadata = nil
	evidenceIDs := make(map[string]string, len(d.Evidence))
	for i := range d.Evidence {
		evidence := &d.Evidence[i]
		oldID := evidence.ID
		if _, exists := evidenceIDs[oldID]; exists {
			return d, ErrServiceInvalid
		}
		evidence.SourceID = source
		evidence.ID = ""
		evidence.Hash = ""
		data, _ := json.Marshal(evidence)
		evidence.ID = "evidence-" + SourceChecksum(string(data))
		evidence.Hash, _ = CanonicalHash(*evidence)
		evidenceIDs[oldID] = evidence.ID
	}
	for i := range d.Steps {
		step := &d.Steps[i]
		step.ID = fmt.Sprintf("step-%03d", i+1)
		step.Order = i + 1
		if _, ok := knownActions[step.Action]; !ok || strings.TrimSpace(step.Command) != "" {
			step.Action = "Manual"
			step.Description = "Operator review required: " + step.Description
			step.ObserveOnly = true
			step.TargetReplicas = nil
		}
		for j, ref := range step.EvidenceRefs {
			replacement, ok := evidenceIDs[ref]
			if !ok {
				return d, ErrServiceInvalid
			}
			step.EvidenceRefs[j] = replacement
		}
		step.Command = ""
	}
	if len(d.Steps) > v.MaxSteps {
		return d, ErrServiceInvalid
	}
	b, e := json.Marshal(d)
	if e != nil || len(b) > v.MaxTotalTextBytes || d.Validate() != nil {
		return d, ErrServiceInvalid
	}
	return d, nil
}
func (s *Service) finishNormalized(p *NormalizedPlaybook) {
	for i := range p.Steps {
		step := &p.Steps[i]
		if step.Action == "Manual" || step.Action == "GitOpsPR" {
			step.RequiresReview = true
		}
		p.Applicability = append(p.Applicability, step.Targets...)
	}
	p.Applicability = normalizeSelectors(p.Applicability)
	p.CanonicalHash, _ = CanonicalHash(*p)
}

// Rejections persist a bounded, safe review record without retaining rejected model text.
func (s *Service) rejectImport(ctx context.Context, source SourceArtifact, id, reason string) {
	d := PlaybookDigest{ID: id, SourceID: source.ID, Title: "Rejected import", Summary: reason, Lineage: []string{source.ID}, Confidence: 0, Steps: []DigestStep{{ID: "review", Action: "Manual", Description: "Review source before retrying", ObserveOnly: true}}, Unknowns: []string{reason}}
	if s.catalog.SaveDigest(ctx, d) != nil {
		return
	}
	p, err := NormalizeDigest(d)
	if err != nil {
		return
	}
	if s.catalog.SavePlaybook(ctx, p) != nil {
		return
	}
	if s.catalog.Transition(ctx, id, 1, LifecycleReview, "playbook-service") != nil {
		return
	}
	_ = s.catalog.Transition(ctx, id, 1, LifecycleRejected, "playbook-service")
	s.outcome("digest", "rejected")
}

func (s *Service) reuseImport(ctx context.Context, out ImportResult, hash string, v ServiceSettings, actor string) (ImportResult, bool, error) {
	existing, err := s.catalog.GetPlaybookByHash(ctx, hash)
	if errors.Is(err, ErrCatalogNotFound) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if existing.Lifecycle == LifecycleNormalized {
		if err = s.catalog.Transition(ctx, existing.ID, existing.Version, LifecycleReview, s.safeActor(actor)); err != nil {
			return out, false, err
		}
		existing.Lifecycle = LifecycleReview
	}
	relation := Relation{ID: "import-" + SourceChecksum(out.Source.ID+":"+existing.ID+":"+fmt.Sprint(existing.Version)), FromID: out.Source.ID, ToID: existing.ID, Kind: "imported_from"}
	if err = s.catalog.RecordRelation(ctx, relation); err != nil {
		return out, false, err
	}
	out.Playbook = existing
	out.Duplicate = true
	out.Guardrails = s.guardrails(v, existing)
	return out, true, nil
}
