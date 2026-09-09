package executor

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/agent/collection"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"net/http"
	"time"
)

// Run polls at a fixed bounded rate and stops on failures. Authentication rejection
// requires operator re-enrollment and never consumes a new bootstrap automatically.
func (r *Runtime) Run(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if err := r.Poll(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (r *Runtime) Poll(ctx context.Context) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrReenrollment
	}
	defer func() {
		if err == ErrReenrollment {
			r.stopped = true
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if r.verifyCluster(ctx) != nil {
		return ErrRuntime
	}
	// Flush old receipts before rotating credentials; generation is part of claim authority.
	if r.credential.Token == "" {
		if c, e := loadCredential(r.config.CredentialFile); e == nil {
			if !r.validCredential(c) {
				return ErrReenrollment
			}
			r.credential = c
		}
	}
	for id, a := range r.journal {
		if !a.Acknowledged {
			if !r.validCredential(r.credential) {
				return ErrReenrollment
			}
			if err = r.receipt(ctx, id, a); err != nil {
				return err
			}
		}
	}
	if err := r.compactJournal(); err != nil {
		return err
	}
	if err = r.authorize(ctx); err != nil {
		return err
	}
	var actions []incident.Action
	if err = r.client.request(ctx, http.MethodGet, "/agent/actions", r.credential.Token, nil, &actions); err != nil {
		return err
	}
	if len(actions) > 100 {
		return ErrRuntime
	}
	for _, a := range actions {
		if _, seen := r.journal[a.Plan.ID]; seen {
			continue
		}
		if a.State != "APPROVED" || a.ApprovedBy == "" || !a.ApprovalExpiresAt.After(time.Now()) {
			continue
		}
		if _, e := r.validate(ctx, a); e != nil {
			continue
		}
		encodedJournal, _ := json.Marshal(r.journal)
		if len(r.journal) >= 256 || len(encodedJournal)+512 > maxWireBytes {
			return ErrRuntime
		}
		var claim execution.Claim
		if err = r.client.post(ctx, "/agent/actions/"+a.Plan.ID+"/claim", r.credential.Token, struct{}{}, &claim); err != nil {
			return err
		}
		if len(claim.ReceiptToken) != 64 {
			return ErrRuntime
		}
		pending := attempt{ReceiptToken: claim.ReceiptToken, Outcome: "AMBIGUOUS"}
		r.journal[a.Plan.ID] = pending
		// Durable before any mutation. A crash at any subsequent point is never replayed.
		if err = r.persistJournal(); err != nil {
			return err
		}
		outcome := "PRECONDITION_FAILED"
		if claim.Action.State == "SUBMITTED" && claim.Action.Hash == a.Hash && claim.Action.Plan.Hash() == a.Hash && claim.Action.Version == a.Version+1 {
			target, e := r.validate(ctx, claim.Action)
			if e == nil && r.deletePod != nil {
				uid := types.UID(target.UID)
				rv := target.ResourceVersion
				options := meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid, ResourceVersion: &rv}, DryRun: []string{meta.DryRunAll}}
				if e = r.deletePod(ctx, target, options); e == nil {
					// The dry run can consume time; re-check identity and approval expiry immediately before the real write.
					if _, e = r.validate(ctx, claim.Action); e == nil {
						options.DryRun = nil
						e = r.deletePod(ctx, target, options)
						outcome = "APPLIED"
						if e != nil {
							outcome = "AMBIGUOUS"
							if apierrors.IsForbidden(e) || apierrors.IsUnauthorized(e) {
								outcome = "DENIED"
							}
							if apierrors.IsConflict(e) || apierrors.IsNotFound(e) || apierrors.IsInvalid(e) {
								outcome = "PRECONDITION_FAILED"
							}
						}
					}
				} else {
					outcome = "DENIED"
					if apierrors.IsConflict(e) || apierrors.IsNotFound(e) || apierrors.IsInvalid(e) {
						outcome = "PRECONDITION_FAILED"
					}
				}
			}
		}
		pending.Outcome = outcome
		r.journal[a.Plan.ID] = pending
		if err = r.persistJournal(); err != nil {
			return err
		}
		if err = r.receipt(ctx, a.Plan.ID, pending); err != nil {
			return err
		}
	}
	return nil
}
func (r *Runtime) validate(ctx context.Context, a incident.Action) (collection.LocalTarget, error) {
	p := a.Plan
	c := r.credential.Agent
	if !identity.ValidID(p.ID) || p.Kind != "REPLACE_POD" || p.Scope != r.config.Scope || p.ExecutorID != c.ID || p.ExecutorGeneration != c.Generation || p.Epoch != c.Epoch || p.SourceGeneration < 1 || a.Hash != p.Hash() || !p.ExpiresAt.After(time.Now()) || !r.validCredential(r.credential) || !a.ApprovalExpiresAt.After(time.Now()) {
		return collection.LocalTarget{}, ErrRuntime
	}
	t, e := r.registry.Resolve(p.ResourceHandle, p.TargetCommitment)
	if e != nil || t.Kind != "Pod" || t.Scope != p.Scope || t.Epoch != p.Epoch || t.Generation != p.SourceGeneration || t.UID == "" || t.ResourceVersion == "" {
		return collection.LocalTarget{}, ErrRuntime
	}
	allowed := false
	for _, ns := range r.config.Namespaces {
		if ns == t.Namespace {
			allowed = true
		}
	}
	if t.Namespace == "kube-system" || t.Namespace == "kube-public" || t.Namespace == "kube-node-lease" {
		allowed = false
	}
	for _, ns := range r.config.ProtectedNamespaces {
		if ns == t.Namespace {
			allowed = false
		}
	}
	if !allowed || r.verifyCluster(ctx) != nil {
		return collection.LocalTarget{}, ErrRuntime
	}
	pod, e := r.kube.CoreV1().Pods(t.Namespace).Get(ctx, t.Name, meta.GetOptions{})
	if e != nil || pod.Namespace != t.Namespace || pod.Name != t.Name || string(pod.UID) != t.UID || pod.ResourceVersion != t.ResourceVersion || pod.DeletionTimestamp != nil {
		return collection.LocalTarget{}, ErrRuntime
	}
	if pod.Labels["sre.component"] != "" || pod.Labels["sre.kubebee.com/protected"] == "true" {
		return collection.LocalTarget{}, ErrRuntime
	}
	unhealthy := pod.Status.Phase == core.PodFailed || collection.PodRestarting(pod, time.Now())
	ready := false
	for _, condition := range pod.Status.Conditions {
		if condition.Type == core.PodReady && condition.Status == core.ConditionTrue {
			ready = true
		}
	}
	for _, status := range append(append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
		if status.State.Waiting != nil && status.State.Waiting.Reason == "CrashLoopBackOff" {
			unhealthy = true
		}
	}
	if !unhealthy || ready {
		return collection.LocalTarget{}, ErrRuntime
	}
	if _, ok := pod.Annotations["kubernetes.io/config.mirror"]; ok {
		return collection.LocalTarget{}, ErrRuntime
	}
	if source, ok := pod.Annotations["kubernetes.io/config.source"]; ok && source != "api" {
		return collection.LocalTarget{}, ErrRuntime
	}
	owners := 0
	for _, o := range pod.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if o.UID == "" {
			return collection.LocalTarget{}, ErrRuntime
		}
		if o.APIVersion != "apps/v1" {
			return collection.LocalTarget{}, ErrRuntime
		}
		switch o.Kind {
		case "ReplicaSet":
			owner, err := r.kube.AppsV1().ReplicaSets(t.Namespace).Get(ctx, o.Name, meta.GetOptions{})
			if err != nil || owner.UID != o.UID || owner.DeletionTimestamp != nil || (owner.Spec.Replicas != nil && *owner.Spec.Replicas < 1) {
				return collection.LocalTarget{}, ErrRuntime
			}
		case "StatefulSet":
			owner, err := r.kube.AppsV1().StatefulSets(t.Namespace).Get(ctx, o.Name, meta.GetOptions{})
			if err != nil || owner.UID != o.UID || owner.DeletionTimestamp != nil || (owner.Spec.Replicas != nil && *owner.Spec.Replicas < 1) {
				return collection.LocalTarget{}, ErrRuntime
			}
		case "DaemonSet":
			owner, err := r.kube.AppsV1().DaemonSets(t.Namespace).Get(ctx, o.Name, meta.GetOptions{})
			if err != nil || owner.UID != o.UID || owner.DeletionTimestamp != nil || owner.Status.DesiredNumberScheduled < 1 {
				return collection.LocalTarget{}, ErrRuntime
			}
		default:
			return collection.LocalTarget{}, ErrRuntime
		}
		owners++
	}
	if owners != 1 {
		return collection.LocalTarget{}, ErrRuntime
	}
	return t, nil
}
func (r *Runtime) receipt(ctx context.Context, id string, a attempt) error {
	var out incident.Action
	if err := r.client.post(ctx, "/agent/actions/"+id+"/receipt", r.credential.Token, map[string]string{"receipt_token": a.ReceiptToken, "outcome": a.Outcome}, &out); err != nil {
		return err
	}
	reconciled := out.State == "AMBIGUOUS" && out.OutcomeCode == "AMBIGUOUS" && out.ReconciledBy != ""
	if out.Plan.ID != id || (out.OutcomeCode != a.Outcome && !reconciled) {
		return ErrRuntime
	}
	a.Acknowledged = true
	r.journal[id] = a
	return r.persistJournal()
}
