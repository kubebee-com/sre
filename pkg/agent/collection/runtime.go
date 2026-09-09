package collection

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/privacy"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RuntimeConfig requires explicit source and control-plane authority. CredentialFile
// belongs on a private volume separate from the executor-shared RegistryDir.
type RuntimeConfig struct {
	ControlPlane                               string
	Scope                                      identity.Scope
	ExpectedClusterUID                         string
	Namespaces                                 []string
	IdentityKey                                []byte
	RegistryDir, CredentialFile, BootstrapFile string
	Kubeconfig                                 string
	InCluster                                  bool
}
type Runtime struct {
	diagnosticSession atomic.Pointer[fleet.Credential]
	diagnosticActive  atomic.Bool
	mu                sync.Mutex
	config            RuntimeConfig
	kube              kubernetes.Interface
	client            *controlClient
	registry          *Registry
	credential        fleet.Credential
	stopped           bool
}

func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	if (cfg.Kubeconfig == "") == !cfg.InCluster {
		return nil, ErrRuntime
	}
	var kc *rest.Config
	var err error
	if cfg.InCluster {
		kc, err = rest.InClusterConfig()
	} else {
		kc, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	}
	if err != nil {
		return nil, ErrRuntime
	}
	kc.Timeout = 10 * time.Second
	kc.QPS = 5
	kc.Burst = 10
	k, err := kubernetes.NewForConfig(kc)
	if err != nil {
		return nil, ErrRuntime
	}
	return newRuntime(cfg, k, nil)
}
func newRuntime(cfg RuntimeConfig, k kubernetes.Interface, h *http.Client) (*Runtime, error) {
	c, err := newControlClient(cfg.ControlPlane, cfg.Scope, h)
	if err != nil || k == nil || !identity.ValidID(cfg.ExpectedClusterUID) || len(cfg.IdentityKey) != 32 || len(cfg.Namespaces) == 0 || len(cfg.Namespaces) > 64 || cfg.CredentialFile == "" || cfg.RegistryDir == "" {
		return nil, ErrRuntime
	}
	seen := map[string]bool{}
	for _, ns := range cfg.Namespaces {
		if len(validation.IsDNS1123Label(ns)) != 0 || seen[ns] {
			return nil, ErrRuntime
		}
		seen[ns] = true
	}
	reg, err := filepath.Abs(cfg.RegistryDir)
	if err != nil {
		return nil, ErrRuntime
	}
	cred, err := filepath.Abs(cfg.CredentialFile)
	if err != nil {
		return nil, ErrRuntime
	}
	rel, err := filepath.Rel(reg, cred)
	if err != nil || rel == "." || (!strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != "..") {
		return nil, ErrRuntime
	}
	// Resolve existing parent paths too, so aliases cannot put credentials on the registry path.
	if parent, e := filepath.EvalSymlinks(filepath.Dir(cred)); e != nil {
		return nil, ErrRuntime
	} else {
		cred = filepath.Join(parent, filepath.Base(cred))
	}
	st, err := os.Stat(filepath.Dir(cred))
	if err != nil || st.Mode().Perm()&0077 != 0 {
		return nil, ErrRuntime
	}
	registry, err := OpenRegistry(reg, cfg.IdentityKey, false)
	if err != nil {
		return nil, ErrRuntime
	}
	actual, e := filepath.EvalSymlinks(reg)
	rel, err = filepath.Rel(actual, cred)
	if e != nil || err != nil || rel == "." || (!strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != "..") {
		registry.Close()
		return nil, ErrRuntime
	}
	if cfg.BootstrapFile != "" {
		parent, e := filepath.EvalSymlinks(filepath.Dir(cfg.BootstrapFile))
		if e != nil {
			registry.Close()
			return nil, ErrRuntime
		}
		bootstrap := filepath.Join(parent, filepath.Base(cfg.BootstrapFile))
		relative, e := filepath.Rel(actual, bootstrap)
		if e != nil || relative == "." || (!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && relative != "..") {
			registry.Close()
			return nil, ErrRuntime
		}
		cfg.BootstrapFile = bootstrap
	}
	cfg.Namespaces = append([]string(nil), cfg.Namespaces...)
	cfg.IdentityKey = nil
	cfg.CredentialFile = cred
	return &Runtime{config: cfg, kube: k, client: c, registry: registry}, nil
}
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	r.diagnosticSession.Store(nil)
	return r.registry.Close()
}
func (r *Runtime) verifyCluster(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ns, err := r.kube.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(ns.UID) != r.config.ExpectedClusterUID {
		return ErrRuntime
	}
	return nil
}
func (r *Runtime) validCredential(c fleet.Credential) bool {
	a := c.Agent
	return len(c.Token) == 43 && a.Scope == r.config.Scope && a.ClusterUID == r.config.ExpectedClusterUID && a.Role == fleet.Collector && a.Audience == "sre-evidence" && identity.ValidID(a.ID) && identity.ValidID(a.Epoch) && a.Generation >= 1 && !a.Revoked && a.ExpiresAt.After(time.Now())
}
func (r *Runtime) authorize(ctx context.Context) error {
	if r.credential.Token == "" {
		if _, err := os.Lstat(r.config.CredentialFile); err == nil {
			c, e := loadCredential(r.config.CredentialFile)
			if e != nil || !r.validCredential(c) {
				return ErrReenrollment
			}
			r.credential = c
		} else if !os.IsNotExist(err) {
			return ErrRuntime
		} else {
			b, e := readPrivate(r.config.BootstrapFile, 1024)
			if e != nil {
				return ErrRuntime
			}
			token := strings.TrimSpace(string(b))
			if len(token) != 43 {
				return ErrRuntime
			}
			if r.verifyCluster(ctx) != nil {
				return ErrRuntime
			}
			c, e := r.client.enroll(ctx, token, r.config.ExpectedClusterUID)
			if e != nil {
				return e
			}
			if !r.validCredential(c) {
				return ErrReenrollment
			}
			if saveCredential(r.config.CredentialFile, c) != nil {
				return ErrReenrollment
			}
			r.credential = c
		}
	}
	if !r.validCredential(r.credential) {
		return ErrReenrollment
	}
	if time.Until(r.credential.Agent.ExpiresAt) < 2*time.Minute {
		c, err := r.client.renew(ctx, r.credential)
		if err != nil {
			return err
		}
		old := r.credential.Agent
		if !r.validCredential(c) || c.Agent.ID != old.ID || c.Agent.Epoch != old.Epoch || c.Agent.Generation != old.Generation+1 {
			return ErrReenrollment
		}
		if saveCredential(r.config.CredentialFile, c) != nil {
			return ErrReenrollment
		}
		r.credential = c
	}
	return nil
}

// Run stops on any failed operation; an operator can restart transient failures.
// Authentication failures never automatically consume another bootstrap token.
func (r *Runtime) Run(ctx context.Context) error {
	if err := r.Scan(ctx); err != nil {
		return err
	}
	last := time.Now()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			var checks struct {
				Requested bool `json:"requested"`
			}
			r.mu.Lock()
			token := r.credential.Token
			stopped := r.stopped
			r.mu.Unlock()
			if stopped {
				return ErrRuntime
			}
			err := r.client.post(ctx, "/agent/checks", token, struct{}{}, &checks)
			if err != nil {
				return err
			}
			if checks.Requested || (!r.diagnosticActive.Load() && time.Since(last) >= 30*time.Second) {
				if err := r.Scan(ctx); err != nil {
					if ctx.Err() != nil {
						return nil
					}
					return err
				}
				last = time.Now()
			}
		}
	}
}
func (r *Runtime) Scan(ctx context.Context) (err error) {
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
	if err = r.authorize(ctx); err != nil {
		return err
	}
	session := r.credential
	r.diagnosticSession.Store(&session)
	at := time.Now().UTC()
	obs := []privacy.Observation{}
	success, total := 0, 0
	for _, ns := range r.config.Namespaces {
		pods, pe := pages(ctx, func(o meta.ListOptions) ([]core.Pod, string, error) {
			v, e := r.kube.CoreV1().Pods(ns).List(ctx, o)
			if e != nil {
				return nil, "", e
			}
			return v.Items, v.Continue, nil
		})
		deps, de := pages(ctx, func(o meta.ListOptions) ([]apps.Deployment, string, error) {
			v, e := r.kube.AppsV1().Deployments(ns).List(ctx, o)
			if e != nil {
				return nil, "", e
			}
			return v.Items, v.Continue, nil
		})
		replicasets, re := pages(ctx, func(o meta.ListOptions) ([]apps.ReplicaSet, string, error) {
			v, e := r.kube.AppsV1().ReplicaSets(ns).List(ctx, o)
			if e != nil {
				return nil, "", e
			}
			return v.Items, v.Continue, nil
		})
		services, se := pages(ctx, func(o meta.ListOptions) ([]core.Service, string, error) {
			v, e := r.kube.CoreV1().Services(ns).List(ctx, o)
			if e != nil {
				return nil, "", e
			}
			return v.Items, v.Continue, nil
		})
		slices, ee := pages(ctx, func(o meta.ListOptions) ([]discovery.EndpointSlice, string, error) {
			v, e := r.kube.DiscoveryV1().EndpointSlices(ns).List(ctx, o)
			if e != nil {
				return nil, "", e
			}
			return v.Items, v.Continue, nil
		})
		total += 5
		for _, e := range []error{pe, de, re, se, ee} {
			if e == nil {
				success++
			}
		}
		handles := map[string]string{}
		for i := range pods {
			p := &pods[i]
			o, e := r.observation("Pod", p.ObjectMeta, at)
			if e != nil {
				return e
			}
			o.Code = privacy.Healthy
			ready := false
			for _, c := range p.Status.Conditions {
				if c.Type == core.PodReady && c.Status == core.ConditionTrue {
					ready = true
				}
			}
			restarts := float64(0)
			crash := PodRestarting(p, at)
			oom := false
			statuses := append(append([]core.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
			for _, c := range statuses {
				restarts += float64(c.RestartCount)
				if c.LastTerminationState.Terminated != nil && c.LastTerminationState.Terminated.Reason == "OOMKilled" && c.LastTerminationState.Terminated.FinishedAt.Time.After(at.Add(-90*time.Second)) {
					oom = true
				}
				if c.State.Waiting != nil && c.State.Waiting.Reason == "CrashLoopBackOff" {
					crash = true
				}
			}
			if !ready {
				o.Code = privacy.DependencyUnavailable
			}
			if p.Status.Phase == core.PodSucceeded {
				o.Code = privacy.Healthy
			}
			if p.Status.Phase == core.PodFailed {
				o.Code = privacy.PodFailed
			}
			if crash {
				o.Code = privacy.CrashLoop
			}
			o.Metrics = map[string]float64{"restart_count": restarts}
			if oom && !ready {
				pressure := o
				pressure.Code = privacy.ResourcePressure
				pressure.DependencyHandles = nil
				obs = append(obs, pressure)
			}
			handles[p.Name] = o.ResourceHandle
			obs = append(obs, o)
		}
		for i := range deps {
			d := &deps[i]
			o, e := r.observation("Deployment", d.ObjectMeta, at)
			if e != nil {
				return e
			}
			desired := int32(1)
			if d.Spec.Replicas != nil {
				desired = *d.Spec.Replicas
			}
			o.Code = privacy.Healthy
			if d.Status.ReadyReplicas < desired || d.Status.UpdatedReplicas < desired || d.Status.AvailableReplicas < desired || d.Status.UnavailableReplicas != 0 {
				o.Code = privacy.DependencyUnavailable
			}
			if d.Status.ObservedGeneration < d.Generation {
				o.Code = privacy.ReadUnavailable
			}
			o.Metrics = map[string]float64{"desired_replicas": float64(desired), "ready_replicas": float64(d.Status.ReadyReplicas)}
			// Follow verified ReplicaSet controller UIDs; never infer ownership from names.
			owners := map[string]bool{}
			for _, rs := range replicasets {
				for _, owner := range rs.OwnerReferences {
					if owner.Controller != nil && *owner.Controller && owner.Kind == "Deployment" && owner.UID == d.UID {
						owners[string(rs.UID)] = true
					}
				}
			}
			for _, p := range pods {
				for _, owner := range p.OwnerReferences {
					if owner.Controller != nil && *owner.Controller && ((owner.Kind == "Deployment" && owner.UID == d.UID) || (owner.Kind == "ReplicaSet" && owners[string(owner.UID)])) && len(o.DependencyHandles) < 32 {
						o.DependencyHandles = append(o.DependencyHandles, handles[p.Name])
					}
				}
			}
			obs = append(obs, o)
		}
		for i := range services {
			s := &services[i]
			o, e := r.observation("Service", s.ObjectMeta, at)
			if e != nil {
				return e
			}
			o.Code = privacy.ReadUnavailable
			if ee == nil && s.Spec.Type != core.ServiceTypeExternalName {
				ready := false
				for _, slice := range slices {
					if slice.Labels[discovery.LabelServiceName] != s.Name {
						continue
					}
					for _, endpoint := range slice.Endpoints {
						if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
							ready = true
						}
					}
				}
				o.Code = privacy.DependencyUnavailable
				if ready {
					o.Code = privacy.Healthy
				}
			}
			if len(s.Spec.Selector) > 0 {
				selector := labels.SelectorFromSet(s.Spec.Selector)
				for _, p := range pods {
					if selector.Matches(labels.Set(p.Labels)) && len(o.DependencyHandles) < 32 {
						o.DependencyHandles = append(o.DependencyHandles, handles[p.Name])
					}
				}
			}
			obs = append(obs, o)
		}
		if len(obs) > 10000 {
			return ErrRuntime
		}
	}
	coverage := "PARTIAL"
	if success == total {
		coverage = "COMPLETE"
	} else if success == 0 {
		coverage = "UNAVAILABLE"
	}
	if coverage == "COMPLETE" {
		handles := []string{}
		seen := map[string]bool{}
		for _, o := range obs {
			if !seen[o.ResourceHandle] {
				handles = append(handles, o.ResourceHandle)
				seen[o.ResourceHandle] = true
			}
		}
		if err := r.registry.ReconcileLive(r.config.Scope, handles); err != nil {
			return err
		}
	}
	// Empty coverage reports carry no recovery observations.
	for start := 0; start < len(obs) || start == 0; {
		end := start + 50
		if end > len(obs) {
			end = len(obs)
		}
		report := Report{ID: identity.NewID(), ClusterUID: r.config.ExpectedClusterUID, ObservedAt: at, Coverage: coverage, Observations: obs[start:end]}
		for {
			encoded, encodeErr := json.Marshal(report)
			if encodeErr != nil {
				return ErrRuntime
			}
			if len(encoded) <= maxWireBytes {
				break
			}
			if end-start <= 1 {
				return ErrRuntime
			}
			end--
			report.Observations = obs[start:end]
		}
		if err = r.client.report(ctx, r.credential.Token, report); err != nil {
			return err
		}
		if end == len(obs) {
			break
		}
		start = end
	}
	return nil
}
func pages[T any](ctx context.Context, list func(meta.ListOptions) ([]T, string, error)) ([]T, error) {
	var out []T
	next := ""
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		if ctx.Err() != nil {
			return out, ErrRuntime
		}
		seconds := int64(10)
		items, continuation, err := list(meta.ListOptions{Limit: 100, Continue: next, TimeoutSeconds: &seconds})
		if err != nil {
			return out, ErrRuntime
		}
		if len(out)+len(items) > 10000 {
			return out, ErrRuntime
		}
		out = append(out, items...)
		if continuation == "" {
			return out, nil
		}
		if seen[continuation] {
			return out, ErrRuntime
		}
		seen[continuation] = true
		next = continuation
	}
	return out, ErrRuntime
}
func (r *Runtime) observation(kind string, m meta.ObjectMeta, at time.Time) (privacy.Observation, error) {
	uid := string(m.UID)
	if !privacy.ValidUID(uid) || m.ResourceVersion == "" || len(m.ResourceVersion) > 64 {
		return privacy.Observation{}, ErrRuntime
	}
	for _, c := range m.ResourceVersion {
		if c < '0' || c > '9' {
			return privacy.Observation{}, ErrRuntime
		}
	}
	h, c, err := r.registry.Put(LocalTarget{Scope: r.config.Scope, Kind: kind, Namespace: m.Namespace, Name: m.Name, UID: uid, ResourceVersion: m.ResourceVersion, Epoch: r.credential.Agent.Epoch, Generation: r.credential.Agent.Generation})
	if err != nil {
		return privacy.Observation{}, ErrRuntime
	}
	return privacy.Observation{ResourceHandle: h, Target: &privacy.Target{Kind: kind, UID: uid, ResourceVersion: m.ResourceVersion, Commitment: c}, ObservedAt: at, ValidUntil: at.Add(90 * time.Second)}, nil
}
