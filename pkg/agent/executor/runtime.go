// Package executor runs one approved typed action against an explicitly bound cluster.
package executor

import (
	"context"
	"github.com/kubebee-com/sre/pkg/agent/collection"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type RuntimeConfig struct {
	ControlPlane                               string
	Scope                                      identity.Scope
	ExpectedClusterUID                         string
	Namespaces, ProtectedNamespaces            []string
	IdentityKey                                []byte
	RegistryDir, CredentialFile, BootstrapFile string
	Kubeconfig                                 string
	InCluster                                  bool
}
type Runtime struct {
	mu              sync.Mutex
	config          RuntimeConfig
	kube            kubernetes.Interface
	client          *controlClient
	registry        *collection.Registry
	credential      fleet.Credential
	stopped, closed bool
	lock            *os.File
	journal         map[string]attempt
	deletePod       func(context.Context, collection.LocalTarget, meta.DeleteOptions) error
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
	r, err := newRuntime(cfg, k, nil)
	if err != nil {
		return nil, err
	}
	// MaxRetries(0) disables client-go Retry-After replay even for DELETE.
	r.deletePod = func(ctx context.Context, t collection.LocalTarget, o meta.DeleteOptions) error {
		return k.CoreV1().RESTClient().Delete().Namespace(t.Namespace).Resource("pods").Name(t.Name).Body(&o).MaxRetries(0).Do(ctx).Error()
	}
	return r, nil
}
func newRuntime(cfg RuntimeConfig, k kubernetes.Interface, h *http.Client) (*Runtime, error) {
	c, err := newControlClient(cfg.ControlPlane, cfg.Scope, h)
	if err != nil || k == nil || !identity.ValidID(cfg.ExpectedClusterUID) || len(cfg.IdentityKey) != 32 || len(cfg.Namespaces) == 0 || len(cfg.Namespaces) > 64 || cfg.CredentialFile == "" || cfg.RegistryDir == "" {
		return nil, ErrRuntime
	}
	seen := map[string]bool{}
	protected := map[string]bool{"kube-system": true, "kube-public": true, "kube-node-lease": true}
	if len(cfg.ProtectedNamespaces) > 64 {
		return nil, ErrRuntime
	}
	for _, ns := range cfg.ProtectedNamespaces {
		if len(validation.IsDNS1123Label(ns)) != 0 {
			return nil, ErrRuntime
		}
		protected[ns] = true
	}

	for _, ns := range cfg.Namespaces {
		if len(validation.IsDNS1123Label(ns)) != 0 || seen[ns] || protected[ns] {
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
	registry, err := collection.OpenRegistry(reg, cfg.IdentityKey, true)
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
	cfg.ProtectedNamespaces = append([]string(nil), cfg.ProtectedNamespaces...)
	cfg.IdentityKey = nil
	cfg.CredentialFile = cred
	r := &Runtime{config: cfg, kube: k, client: c, registry: registry}
	if err := r.openJournal(); err != nil {
		registry.Close()
		return nil, err
	}
	return r, nil
}
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	r.stopped = true
	if r.lock != nil {
		syscall.Flock(int(r.lock.Fd()), syscall.LOCK_UN)
		r.lock.Close()
	}
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
	return len(c.Token) == 43 && a.Scope == r.config.Scope && a.ClusterUID == r.config.ExpectedClusterUID && a.Role == fleet.Executor && a.Audience == "sre-execution" && identity.ValidID(a.ID) && identity.ValidID(a.Epoch) && a.Generation >= 1 && !a.Revoked && a.ExpiresAt.After(time.Now())
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
