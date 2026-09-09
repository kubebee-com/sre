package executor

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/kubebee-com/sre/pkg/agent/collection"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	r                             *Runtime
	cfg                           RuntimeConfig
	kube                          *fake.Clientset
	server                        *httptest.Server
	action                        incident.Action
	credential                    fleet.Credential
	claims, writes, dry, receipts int
	enrolls, renews               int
	rejectActions                 bool
	outcome                       string
	loseReceipt                   bool
	reconciled                    bool
	mutateError                   error
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	d := t.TempDir()
	os.Chmod(d, 0700)
	s := identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}
	f.cfg = RuntimeConfig{Scope: s, ExpectedClusterUID: "cluster-uid", Namespaces: []string{"work"}, IdentityKey: []byte(strings.Repeat("k", 32)), RegistryDir: filepath.Join(d, "registry"), CredentialFile: filepath.Join(d, "credential"), BootstrapFile: filepath.Join(d, "bootstrap")}
	os.WriteFile(f.cfg.BootstrapFile, []byte(strings.Repeat("b", 43)), 0600)
	reg, e := collection.OpenRegistry(f.cfg.RegistryDir, f.cfg.IdentityKey, false)
	if e != nil {
		t.Fatal(e)
	}
	h, c, e := reg.Put(collection.LocalTarget{Scope: s, Kind: "Pod", Namespace: "work", Name: "pod", UID: "pod-uid", ResourceVersion: "12", Epoch: "epoch", Generation: 2})
	if e != nil {
		t.Fatal(e)
	}
	reg.Close()
	f.credential = fleet.Credential{Token: strings.Repeat("t", 43), Agent: incident.Agent{Scope: s, ID: "executor", Role: fleet.Executor, Audience: "sre-execution", ClusterUID: "cluster-uid", Epoch: "epoch", Generation: 1, ExpiresAt: time.Now().Add(time.Hour)}}
	p := incident.ActionPlan{Scope: s, ID: "action", Kind: "REPLACE_POD", ExecutorID: "executor", ExecutorGeneration: 1, SourceGeneration: 2, Epoch: "epoch", ResourceHandle: h, TargetCommitment: c, ExpiresAt: time.Now().Add(time.Minute)}
	f.action = incident.Action{Plan: p, Hash: p.Hash(), State: "APPROVED", ApprovedBy: "user", ApprovalExpiresAt: time.Now().Add(time.Hour), Version: 2}
	yes := true
	f.kube = fake.NewSimpleClientset(&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "pod", Namespace: "work", UID: "pod-uid", ResourceVersion: "12", OwnerReferences: []meta.OwnerReference{{Kind: "ReplicaSet", APIVersion: "apps/v1", Name: "rs", UID: "rs-uid", Controller: &yes}}}, Status: core.PodStatus{Phase: core.PodFailed}}, &apps.ReplicaSet{ObjectMeta: meta.ObjectMeta{Name: "rs", Namespace: "work", UID: "rs-uid"}})
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("organization_id") != "org" || r.URL.Query().Get("cluster_id") != "cluster" || r.URL.Query().Get("application_id") != "app" {
			t.Error("missing scope")
		}
		switch r.URL.Path {
		case "/agent/enroll":
			f.enrolls++
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["role"] != fleet.Executor {
				t.Error("wrong enrollment role")
			}
			json.NewEncoder(w).Encode(f.credential)
		case "/agent/renew":
			f.renews++
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["role"] != fleet.Executor {
				t.Error("wrong renewal role")
			}
			c := f.credential
			c.Agent.Generation++
			c.Agent.ExpiresAt = time.Now().Add(time.Hour)
			json.NewEncoder(w).Encode(c)
		case "/agent/actions":
			if f.rejectActions {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode([]incident.Action{f.action})
		case "/agent/actions/action/claim":
			f.claims++
			a := f.action
			a.State = "SUBMITTED"
			a.Version++
			json.NewEncoder(w).Encode(execution.Claim{Action: a, ReceiptToken: strings.Repeat("r", 64)})
		case "/agent/actions/action/receipt":
			f.receipts++
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			f.outcome = b["outcome"]
			if f.loseReceipt {
				w.WriteHeader(503)
				return
			}
			a := f.action
			a.OutcomeCode = f.outcome
			if f.reconciled {
				a.State = "AMBIGUOUS"
				a.OutcomeCode = "AMBIGUOUS"
				a.ReconciledBy = "owner"
			}
			json.NewEncoder(w).Encode(a)
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	f.cfg.ControlPlane = f.server.URL
	f.r, e = newRuntime(f.cfg, f.kube, f.server.Client())
	if e != nil {
		t.Fatal(e)
	}
	f.r.deletePod = func(ctx context.Context, target collection.LocalTarget, o meta.DeleteOptions) error {
		if o.Preconditions == nil || o.Preconditions.UID == nil || string(*o.Preconditions.UID) != "pod-uid" || o.Preconditions.ResourceVersion == nil || *o.Preconditions.ResourceVersion != "12" || o.GracePeriodSeconds != nil {
			t.Error("unsafe preconditions/grace")
		}
		if len(o.DryRun) > 0 {
			if o.DryRun[0] != meta.DryRunAll {
				t.Error("bad dry run")
			}
			f.dry++
			return nil
		}
		f.writes++
		return f.mutateError
	}
	t.Cleanup(func() { f.r.Close(); f.server.Close() })
	return f
}
func TestExecuteDryRunAndOneMutation(t *testing.T) {
	f := setup(t)
	if e := f.r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.claims != 1 || f.dry != 1 || f.writes != 1 || f.outcome != "APPLIED" {
		t.Fatalf("claim=%d dry=%d writes=%d outcome=%s", f.claims, f.dry, f.writes, f.outcome)
	}
	if e := f.r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.writes != 1 {
		t.Fatal("replayed action")
	}
}
func TestRejectBeforeClaim(t *testing.T) {
	for _, name := range []string{"namespace", "uid", "generation", "kind", "scope", "standalone", "static", "deleting", "hash", "executor-generation"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			switch name {
			case "namespace":
				f.r.config.Namespaces = []string{"elsewhere"}
			case "uid":
				f.kube.PrependReactor("get", "pods", func(kt.Action) (bool, runtime.Object, error) {
					return true, &core.Pod{ObjectMeta: meta.ObjectMeta{UID: "wrong"}}, nil
				})
			case "generation":
				f.action.Plan.SourceGeneration++
			case "kind":
				f.action.Plan.Kind = "EXEC"
			case "scope":
				f.action.Plan.Scope.ApplicationID = "other"
			case "standalone", "static", "deleting":
				p, _ := f.kube.CoreV1().Pods("work").Get(context.Background(), "pod", meta.GetOptions{})
				if name == "standalone" {
					p.OwnerReferences = nil
				}
				if name == "static" {
					p.Annotations = map[string]string{"kubernetes.io/config.mirror": ""}
				}
				if name == "deleting" {
					now := meta.Now()
					p.DeletionTimestamp = &now
				}
				f.kube.CoreV1().Pods("work").Update(context.Background(), p, meta.UpdateOptions{})
			case "executor-generation":
				f.action.Plan.ExecutorGeneration++
			}
			f.action.Hash = f.action.Plan.Hash()
			if name == "hash" {
				f.action.Hash = "bad"
			}
			_ = f.r.Poll(context.Background())
			if f.claims != 0 || f.writes != 0 {
				t.Fatal("unsafe target claimed or mutated")
			}
		})
	}
}
func TestCollectorCredentialRejected(t *testing.T) {
	f := setup(t)
	f.credential.Agent.Role = fleet.Collector
	if e := f.r.Poll(context.Background()); !errors.Is(e, ErrReenrollment) {
		t.Fatalf("got %v", e)
	}
	if f.claims != 0 {
		t.Fatal("claimed")
	}
}
func TestAmbiguousAndLostReceiptNeverReplays(t *testing.T) {
	f := setup(t)
	f.mutateError = errors.New("transport disconnected sensitive-pod")
	f.loseReceipt = true
	if e := f.r.Poll(context.Background()); e == nil {
		t.Fatal("expected failed receipt")
	}
	if f.outcome != "AMBIGUOUS" {
		t.Fatal(f.outcome)
	}
	f.r.Close()
	var e error
	f.r, e = newRuntime(f.cfg, f.kube, f.server.Client())
	if e != nil {
		t.Fatal(e)
	}
	f.r.deletePod = func(context.Context, collection.LocalTarget, meta.DeleteOptions) error { t.Fatal("replay"); return nil }
	f.loseReceipt = false
	if e = f.r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.writes != 1 || f.claims != 1 || f.receipts != 2 {
		t.Fatalf("writes=%d claims=%d receipts=%d", f.writes, f.claims, f.receipts)
	}
}

func TestClaimRevalidationDeniesChangedPod(t *testing.T) {
	f := setup(t)
	gets := 0
	f.kube.PrependReactor("get", "pods", func(a kt.Action) (bool, runtime.Object, error) {
		gets++
		if gets > 1 {
			return true, &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "pod", Namespace: "work", UID: "replacement", ResourceVersion: "13"}}, nil
		}
		return false, nil, nil
	})
	if e := f.r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.claims != 1 || f.writes != 0 || f.dry != 0 || f.outcome != "PRECONDITION_FAILED" {
		t.Fatalf("unsafe revalidation %s", f.outcome)
	}
}
func TestProtectedAndCredentialIsolation(t *testing.T) {
	for _, name := range []string{"kube-system", "kube-public", "kube-node-lease", "extra", "credential-in-registry", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			f.r.Close()
			cfg := f.cfg
			switch name {
			case "extra":
				cfg.ProtectedNamespaces = []string{"work"}
			case "credential-in-registry":
				cfg.CredentialFile = filepath.Join(cfg.RegistryDir, "credential")
			case "duplicate":
				cfg.Namespaces = []string{"work", "work"}
			default:
				cfg.Namespaces = []string{name}
			}
			r, e := newRuntime(cfg, f.kube, f.server.Client())
			if e == nil {
				r.Close()
				t.Fatal("accepted unsafe config")
			}
		})
	}
}
func TestJournalExclusiveRuntime(t *testing.T) {
	f := setup(t)
	r, e := newRuntime(f.cfg, f.kube, f.server.Client())
	if e == nil {
		r.Close()
		t.Fatal("accepted second executor with same journal")
	}
}
func TestControlRejectsRedirectAndOversize(t *testing.T) {
	for _, mode := range []string{"redirect", "oversize", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, "https://example.invalid", 302)
				case "oversize":
					w.Write([]byte(strings.Repeat("x", maxWireBytes+1)))
				case "unauthorized":
					w.WriteHeader(401)
				}
			}))
			defer srv.Close()
			c, e := newControlClient(srv.URL, identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}, srv.Client())
			if e != nil {
				t.Fatal(e)
			}
			e = c.post(context.Background(), "/agent/enroll", "", struct{}{}, nil)
			if e == nil {
				t.Fatal("accepted response")
			}
			if mode == "unauthorized" && e != ErrReenrollment {
				t.Fatal(e)
			}
		})
	}
}

func TestRESTDeleteDoesNotRetry429(t *testing.T) {
	f := setup(t)
	f.r.Close()
	dry, actual := 0, 0
	ks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete {
			var o meta.DeleteOptions
			if json.NewDecoder(r.Body).Decode(&o) != nil {
				t.Error("decode delete")
			}
			if o.Preconditions == nil || o.Preconditions.UID == nil || string(*o.Preconditions.UID) != "pod-uid" || o.Preconditions.ResourceVersion == nil || *o.Preconditions.ResourceVersion != "12" || o.GracePeriodSeconds != nil {
				t.Error("missing exact preconditions")
			}
			if len(o.DryRun) > 0 {
				dry++
				json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Success"})
				return
			}
			actual++
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: meta.StatusReasonTooManyRequests, Code: 429})
			return
		}
		if r.URL.Path == "/api/v1/namespaces/kube-system" {
			ns, _ := f.kube.CoreV1().Namespaces().Get(r.Context(), "kube-system", meta.GetOptions{})
			ns.TypeMeta = meta.TypeMeta{Kind: "Namespace", APIVersion: "v1"}
			json.NewEncoder(w).Encode(ns)
			return
		}
		if strings.Contains(r.URL.Path, "/replicasets/") {
			rs, _ := f.kube.AppsV1().ReplicaSets("work").Get(r.Context(), "rs", meta.GetOptions{})
			rs.TypeMeta = meta.TypeMeta{Kind: "ReplicaSet", APIVersion: "apps/v1"}
			json.NewEncoder(w).Encode(rs)
			return
		}
		p, _ := f.kube.CoreV1().Pods("work").Get(r.Context(), "pod", meta.GetOptions{})
		p.TypeMeta = meta.TypeMeta{Kind: "Pod", APIVersion: "v1"}
		json.NewEncoder(w).Encode(p)
	}))
	defer ks.Close()
	cfg := clientapi.Config{Clusters: map[string]*clientapi.Cluster{"local": {Server: ks.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ks.Certificate().Raw})}}, AuthInfos: map[string]*clientapi.AuthInfo{"local": {}}, Contexts: map[string]*clientapi.Context{"local": {Cluster: "local", AuthInfo: "local"}}, CurrentContext: "local"}
	f.cfg.Kubeconfig = filepath.Join(filepath.Dir(f.cfg.CredentialFile), "kubeconfig")
	if e := clientcmd.WriteToFile(cfg, f.cfg.Kubeconfig); e != nil {
		t.Fatal(e)
	}
	r, e := NewRuntime(f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	f.r = r
	r.client, _ = newControlClient(f.server.URL, f.cfg.Scope, f.server.Client())
	if e = r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	if dry != 1 || actual != 1 || f.outcome != "AMBIGUOUS" {
		t.Fatalf("dry=%d actual=%d outcome=%s", dry, actual, f.outcome)
	}
}

func TestPrivatePersistenceBoundAndLockCleanup(t *testing.T) {
	f := setup(t)
	f.r.Close()
	if e := savePrivate(f.cfg.CredentialFile, strings.Repeat("x", maxWireBytes+1)); e == nil {
		t.Fatal("accepted oversized private state")
	}
}

func TestRenewalIsExecutorBoundAndPersistsGeneration(t *testing.T) {
	f := setup(t)
	f.credential.Agent.ExpiresAt = time.Now().Add(time.Minute)
	if e := f.r.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	c, e := loadCredential(f.cfg.CredentialFile)
	if e != nil || c.Agent.Generation != 2 || f.renews != 1 || f.claims != 0 {
		t.Fatal("renewal failed or stale action claimed")
	}
	st, e := os.Stat(f.cfg.CredentialFile)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("credential permissions")
	}
}
func TestAuthorizationRejectionNeverReenrolls(t *testing.T) {
	f := setup(t)
	f.rejectActions = true
	for i := 0; i < 2; i++ {
		if e := f.r.Poll(context.Background()); e != ErrReenrollment {
			t.Fatal(e)
		}
	}
	if f.enrolls != 1 || f.writes != 0 {
		t.Fatal("automatic reenrollment")
	}
}
func TestWrongClusterOrScopeCredentialRejected(t *testing.T) {
	for _, mode := range []string{"live-cluster", "scope", "cluster", "epoch", "expired", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			switch mode {
			case "live-cluster":
				f.r.config.ExpectedClusterUID = "other"
			case "scope":
				f.credential.Agent.Scope.ApplicationID = "other"
			case "cluster":
				f.credential.Agent.ClusterUID = "other"
			case "epoch":
				f.action.Plan.Epoch = "other"
				f.action.Hash = f.action.Plan.Hash()
			case "expired":
				f.credential.Agent.ExpiresAt = time.Now().Add(-time.Second)
			case "revoked":
				f.credential.Agent.Revoked = true
			}
			_ = f.r.Poll(context.Background())
			if f.claims != 0 || f.writes != 0 {
				t.Fatal("claimed invalid authority")
			}
		})
	}
}

func TestLiveProtectionAndControllerExistenceBeforeSubmission(t *testing.T) {
	for _, mode := range []string{"healthy", "orphaned", "protected"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			p, _ := f.kube.CoreV1().Pods("work").Get(context.Background(), "pod", meta.GetOptions{})
			switch mode {
			case "healthy":
				p.Status = core.PodStatus{Phase: core.PodRunning, Conditions: []core.PodCondition{{Type: core.PodReady, Status: core.ConditionTrue}}}
			case "orphaned":
				f.kube.AppsV1().ReplicaSets("work").Delete(context.Background(), "rs", meta.DeleteOptions{})
			case "protected":
				p.Labels = map[string]string{"sre.component": "collector"}
			}
			f.kube.CoreV1().Pods("work").Update(context.Background(), p, meta.UpdateOptions{})
			_ = f.r.Poll(context.Background())
			if f.claims != 0 || f.writes != 0 {
				t.Fatal("unsafe target submitted")
			}
		})
	}
}

func TestLostAppliedReceiptAcknowledgesOwnerReconciliation(t *testing.T) {
	f := setup(t)
	f.loseReceipt = true
	if err := f.r.Poll(context.Background()); err == nil {
		t.Fatal("expected lost receipt")
	}
	if f.outcome != "APPLIED" || f.writes != 1 {
		t.Fatal("fixture did not apply once")
	}
	f.loseReceipt = false
	f.reconciled = true
	if err := f.r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	entry := f.r.journal["action"]
	if !entry.Acknowledged || entry.Outcome != "APPLIED" || f.writes != 1 || f.claims != 1 {
		t.Fatal("lost local outcome or replayed mutation", entry)
	}
	// A later credential renewal must no longer be blocked by this receipt.
	f.r.credential.Agent.ExpiresAt = time.Now().Add(time.Second)
	if err := f.r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.renews != 1 {
		t.Fatal("reconciled receipt blocked future authority")
	}
}
