package systemintegration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/kubebee-com/sre/pkg/agent/collection"
	"github.com/kubebee-com/sre/pkg/agent/executor"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/delivery"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/messaging"
	"github.com/kubebee-com/sre/pkg/orchestrator"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/recovery"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	apps "k8s.io/api/apps/v1"
	authentication "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/retry"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const applicationNamespace = "customer-alice"
const agentNamespace = "sre-orchestrator-test"

func principal(id, group string) identity.Principal {
	return identity.Principal{ID: id, Issuer: "https://fixture.invalid", Groups: []string{group}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute)}
}

type fixtureVerifier struct{}

func (fixtureVerifier) Verify(_ context.Context, token string) (identity.Principal, error) {
	if token == "fixture-admin" {
		return principal("admin", "admins"), nil
	}
	if token == "fixture-owner-a" {
		return principal("owner-a", "owner-a"), nil
	}
	return identity.Principal{}, errors.New("fixture identity rejected")
}
func cluster(t *testing.T, path string) (*rest.Config, *kubernetes.Clientset) {
	t.Helper()
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Timeout = 10 * time.Second
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, client
}
func prepareCluster(t *testing.T, ctx context.Context, c *kubernetes.Clientset) {
	t.Helper()
	for _, ns := range []string{applicationNamespace, agentNamespace, "other-app"} {
		if _, err := c.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: ns}}, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	one := int32(1)
	labels := map[string]string{"app": "private-workload"}
	_, err := c.AppsV1().Deployments(applicationNamespace).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "alice-private", Namespace: applicationNamespace}, Spec: apps.DeploymentSpec{Replicas: &one, Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{Containers: []core.Container{{Name: "app", Image: os.Getenv("SRE_ENTERPRISE_FIXTURE_IMAGE"), ImagePullPolicy: core.PullIfNotPresent, Args: []string{"--crash"}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
}
func serviceAccountConfig(t *testing.T, ctx context.Context, c *kubernetes.Clientset, base *rest.Config, role string, dir string) string {
	t.Helper()
	if _, err := c.CoreV1().ServiceAccounts(agentNamespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: role}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rules := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "list"}}, {APIGroups: []string{"apps"}, Resources: []string{"deployments", "replicasets"}, Verbs: []string{"get", "list"}}, {APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"get", "list"}}}
	if role == "executor" {
		rules = []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "delete"}}, {APIGroups: []string{"apps"}, Resources: []string{"replicasets", "statefulsets", "daemonsets"}, Verbs: []string{"get"}}}
	}
	if _, err := c.RbacV1().Roles(applicationNamespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: role}, Rules: rules}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	subject := []rbac.Subject{{Kind: "ServiceAccount", Name: role, Namespace: agentNamespace}}
	if _, err := c.RbacV1().RoleBindings(applicationNamespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role}, Subjects: subject, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: role}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "sre-test-" + role}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{"kube-system"}, Verbs: []string{"get"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "sre-test-" + role}, Subjects: subject, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "sre-test-" + role}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	seconds := int64(3600)
	token, err := c.CoreV1().ServiceAccounts(agentNamespace).CreateToken(ctx, role, &authentication.TokenRequest{Spec: authentication.TokenRequestSpec{ExpirationSeconds: &seconds}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ca := base.CAData
	if len(ca) == 0 && base.CAFile != "" {
		var err error
		ca, err = os.ReadFile(base.CAFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := clientapi.Config{Clusters: map[string]*clientapi.Cluster{"fixture": {Server: base.Host, CertificateAuthorityData: ca}}, AuthInfos: map[string]*clientapi.AuthInfo{"agent": {Token: token.Status.Token}}, Contexts: map[string]*clientapi.Context{"fixture": {Cluster: "fixture", AuthInfo: "agent"}}, CurrentContext: "fixture"}
	path := filepath.Join(dir, role+".kubeconfig")
	if err := clientcmd.WriteToFile(cfg, path); err != nil {
		t.Fatal(err)
	}
	return path
}
func waitFor(t *testing.T, ctx context.Context, description string, check func() bool) {
	t.Helper()
	deadline := time.NewTimer(150 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if check() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(description, ctx.Err())
		case <-deadline.C:
			t.Fatal("deadline waiting for", description)
		case <-ticker.C:
		}
	}
}
func TestTwoClustersOwnerApprovalAndIndependentRecovery(t *testing.T) {
	aPath, bPath, dsn := os.Getenv("SRE_ENTERPRISE_KIND_A"), os.Getenv("SRE_ENTERPRISE_KIND_B"), os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if aPath == "" || bPath == "" || dsn == "" {
		if os.Getenv("SRE_KIND_REQUIRED") == "1" {
			t.Fatal("required Kind cluster/database configuration missing")
		}
		t.Skip("two disposable Kind clusters and PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	aCfg, a := cluster(t, aPath)
	bCfg, b := cluster(t, bPath)
	prepareCluster(t, ctx, a)
	prepareCluster(t, ctx, b)
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	organization := identity.NewID()
	scopeA := identity.Scope{OrganizationID: organization, ClusterID: "cluster-a", ApplicationID: "application"}
	scopeB := scopeA
	scopeB.ClusterID = "cluster-b"
	policy, err := authorization.NewPolicy([]authorization.Binding{{Scope: scopeA, Group: "owner-a", Role: authorization.Owner}, {Scope: scopeA, Group: "investigators", Role: authorization.Investigator}, {Scope: scopeA, Group: "admins", Role: authorization.Administrator}, {Scope: scopeB, Group: "admins", Role: authorization.Administrator}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := fleet.NewService(db, policy, "disposable-cluster-authority")
	if err != nil {
		t.Fatal(err)
	}
	actions := &execution.Service{Fleet: f, Enabled: true}
	investigations, err := investigation.NewService(db, policy, []investigation.Profile{{ID: "rule", Version: "v1", Metadata: investigation.ProviderMetadata{Provider: "rule"}, Scopes: []identity.Scope{scopeA, scopeB}}})
	if err != nil {
		t.Fatal(err)
	}
	sink := &kindNotificationSink{}
	t.Setenv("SRE_KIND_NOTIFICATION_ENDPOINT", "https://notifications.example/kind")
	t.Setenv("SRE_KIND_SLACK_SECRET", "synthetic-kind-signing-secret")
	route := delivery.Route{ID: "kind-ops", Scope: scopeA, RecipientGroup: "owner-a", EndpointEnv: "SRE_KIND_NOTIFICATION_ENDPOINT"}
	notifications, err := delivery.NewService(db, policy, []delivery.Route{route}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err = notifications.RegisterRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	channel := messaging.Config{ID: "kind-ops", Provider: "slack", SecretEnv: "SRE_KIND_SLACK_SECRET", AccountID: "kind-team", ConversationID: "kind-room", Scope: scopeA, Users: []messaging.User{{ExternalID: "owner", PrincipalID: "slack-owner-a", Groups: []string{"owner-a"}}, {ExternalID: "investigator", PrincipalID: "slack-investigator", Groups: []string{"investigators"}}}}
	investigations.AuthorityEpoch = f.Epoch
	queue := &investigation.Queue{Service: investigations, Scopes: []identity.Scope{scopeA, scopeB}}
	var handler http.Handler
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	handler, err = orchestrator.New(orchestrator.Config{Queue: queue, DB: db, Policy: policy, Verifier: fixtureVerifier{}, PublicURL: server.URL, Fleet: f, Execution: actions, Investigations: investigations, Notifications: notifications, Messaging: []messaging.Config{channel}})
	if err != nil {
		t.Fatal(err)
	}
	operator := &kindMessaging{t: t, ctx: ctx, server: server, scope: scopeA, service: notifications, route: route, sink: sink}
	ca := filepath.Join(t.TempDir(), "control-plane-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	type agentFixture struct {
		runtime        *collection.Runtime
		cfg            collection.RuntimeConfig
		clusterUID     string
		executorConfig string
	}
	fixtures := []agentFixture{}
	for index, c := range []*kubernetes.Clientset{a, b} {
		scope := scopeA
		base := aCfg
		if index == 1 {
			scope = scopeB
			base = bCfg
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		ns, err := c.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		credentialPath := serviceAccountConfig(t, ctx, c, base, "collector", dir)
		boot, err := f.Bootstrap(ctx, principal("admin", "admins"), scope, "collector", string(ns.UID), fleet.Collector)
		if err != nil {
			t.Fatal(err)
		}
		bootstrap := filepath.Join(dir, "bootstrap")
		if err := os.WriteFile(bootstrap, []byte(boot.Token), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := collection.RuntimeConfig{ControlPlane: server.URL, Scope: scope, ExpectedClusterUID: string(ns.UID), Namespaces: []string{applicationNamespace}, IdentityKey: []byte(strings.Repeat("k", 32)), RegistryDir: filepath.Join(dir, "registry"), CredentialFile: filepath.Join(dir, "credential"), BootstrapFile: bootstrap, Kubeconfig: credentialPath}
		runtime, err := collection.NewRuntime(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close()
		fixture := agentFixture{runtime: runtime, cfg: cfg, clusterUID: string(ns.UID)}
		if index == 0 {
			fixture.executorConfig = serviceAccountConfig(t, ctx, c, base, "executor", dir)
		}
		fixtures = append(fixtures, fixture)
		_, restricted := cluster(t, credentialPath)
		if _, err := restricted.CoreV1().Pods("other-app").List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(err) {
			t.Fatal("collector crossed namespace boundary", err)
		}
		if err := restricted.CoreV1().Pods(applicationNamespace).Delete(ctx, "nonexistent", meta.DeleteOptions{DryRun: []string{meta.DryRunAll}}); !apierrors.IsForbidden(err) {
			t.Fatal("collector could mutate", err)
		}
	}
	waitFor(t, ctx, "both crash loops", func() bool {
		for _, c := range []*kubernetes.Clientset{a, b} {
			pods, err := c.CoreV1().Pods(applicationNamespace).List(ctx, meta.ListOptions{})
			if err != nil {
				return false
			}
			found := false
			for _, p := range pods.Items {
				if collection.PodRestarting(&p, time.Now()) {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		return true
	})
	for _, fixture := range fixtures {
		if err := fixture.runtime.Scan(ctx); err != nil {
			t.Fatal("real collector scan", err)
		}
	}
	var evidence incident.Item
	var incidentID, healthyHandle string
	load := func() {
		t.Helper()
		err := db.Transact(ctx, scopeA, func(tx *postgres.Tx) error {
			active, err := tx.ActiveIncident()
			if err != nil {
				return err
			}
			incidentID = active.ID
			items, err := tx.Items(active.ID, "", 100)
			if err != nil {
				return err
			}
			for _, item := range items {
				var o privacy.Observation
				if json.Unmarshal(item.Body, &o) != nil {
					continue
				}
				encoded, _ := json.Marshal(item)
				if strings.Contains(string(encoded), "alice") || strings.Contains(string(encoded), "private-workload") {
					t.Fatal("customer canary reached central evidence")
				}
				if o.Code == privacy.CrashLoop {
					evidence = item
				}
				if o.Target != nil && o.Target.Kind == "Deployment" {
					healthyHandle = o.ResourceHandle
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	load()
	if evidence.ID == "" || healthyHandle == "" {
		t.Fatal("real evidence missing")
	}
	beforeB, err := b.CoreV1().Pods(applicationNamespace).List(ctx, meta.ListOptions{})
	if err != nil || len(beforeB.Items) != 1 {
		t.Fatal("expected one cluster B fixture pod", err)
	}
	beforeA, err := a.CoreV1().Pods(applicationNamespace).List(ctx, meta.ListOptions{})
	if err != nil || len(beforeA.Items) != 1 {
		t.Fatal("expected one cluster A fixture pod", err)
	}
	oldUID := beforeA.Items[0].UID
	boot, err := f.Bootstrap(ctx, principal("admin", "admins"), scopeA, "executor", fixtures[0].clusterUID, fleet.Executor)
	if err != nil {
		t.Fatal(err)
	}
	execDir := t.TempDir()
	if err := os.Chmod(execDir, 0700); err != nil {
		t.Fatal(err)
	}
	bootstrap := filepath.Join(execDir, "bootstrap")
	if err := os.WriteFile(bootstrap, []byte(boot.Token), 0600); err != nil {
		t.Fatal(err)
	}
	exec, err := executor.NewRuntime(executor.RuntimeConfig{ControlPlane: server.URL, Scope: scopeA, ExpectedClusterUID: fixtures[0].clusterUID, Namespaces: []string{applicationNamespace}, ProtectedNamespaces: []string{agentNamespace}, IdentityKey: fixtures[0].cfg.IdentityKey, RegistryDir: fixtures[0].cfg.RegistryDir, CredentialFile: filepath.Join(execDir, "credential"), BootstrapFile: bootstrap, Kubeconfig: fixtures[0].executorConfig})
	if err != nil {
		t.Fatal(err)
	}
	defer exec.Close()
	if err := exec.Poll(ctx); err != nil {
		t.Fatal("executor enrollment", err)
	}
	request := execution.ProposeRequest{IncidentID: incidentID, Kind: "REPLACE_POD", Evidence: incident.ItemRef{ID: evidence.ID, Version: evidence.Version}, EvidenceHash: evidence.Hash, ExecutorID: "executor"}
	assertUnchanged := func() {
		t.Helper()
		if err := exec.Poll(ctx); err != nil {
			t.Fatal(err)
		}
		for index, c := range []*kubernetes.Clientset{a, b} {
			pods, err := c.CoreV1().Pods(applicationNamespace).List(ctx, meta.ListOptions{})
			expected := oldUID
			if index == 1 {
				expected = beforeB.Items[0].UID
			}
			if err != nil || len(pods.Items) != 1 || pods.Items[0].UID != expected {
				t.Fatalf("cluster %d mutated without approval: %v", index, err)
			}
		}
	}
	// Acknowledging the delivered proposal never authorizes executor mutation.
	rejected := operator.propose(request)
	assertUnchanged()
	operator.callback("owner", "reject "+rejected.Plan.ID, false, true)
	operator.callback("owner", "reject "+rejected.Plan.ID, false, false)
	operator.callback("owner", "approve "+rejected.Plan.ID+" "+rejected.Hash, false, false)
	operator.state(rejected.Plan.ID, "CANCELLED", 2)
	assertUnchanged()
	operator.dispatch()
	operator.audit(dsn, rejected.Plan.ID, []string{"PROPOSED", "CANCELLED"})
	action := operator.propose(request)
	assertUnchanged()
	for _, bad := range []struct {
		user, hash string
		forged     bool
	}{
		{"investigator", action.Hash, false},
		{"owner", strings.Repeat("0", 64), false},
		{"owner", action.Hash, true},
	} {
		operator.callback(bad.user, "approve "+action.Plan.ID+" "+bad.hash, bad.forged, false)
		operator.state(action.Plan.ID, "PROPOSED", 1)
		assertUnchanged()
	}

	applied := false
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			// An unclaimed stale plan is cancelled. Every new exact snapshot receives a
			// separate owner approval; SUBMITTED or ambiguous effects are never retried.
			operator.callback("owner", "reject "+action.Plan.ID, false, true)
			operator.state(action.Plan.ID, "CANCELLED", 3)
			if err := fixtures[0].runtime.Scan(ctx); err != nil {
				t.Fatal(err)
			}
			load()
			request.Evidence = incident.ItemRef{ID: evidence.ID, Version: evidence.Version}
			request.EvidenceHash = evidence.Hash
			action = operator.propose(request)
			assertUnchanged()
		}
		operator.callback("owner", "approve "+action.Plan.ID+" "+action.Hash, false, true)
		operator.callback("owner", "approve "+action.Plan.ID+" "+action.Hash, false, false)
		approved := operator.state(action.Plan.ID, "APPROVED", 2)
		if approved.ApprovedBy != "slack-owner-a" {
			t.Fatal("wrong approval actor")
		}
		if err := exec.Poll(ctx); err != nil {
			t.Fatal("approved executor", err)
		}
		var state string
		if err := db.Transact(ctx, scopeA, func(tx *postgres.Tx) error { got, _, err := tx.Action(action.Plan.ID); state = got.State; return err }); err != nil {
			t.Fatal(err)
		}
		if state == "APPLIED" {
			applied = true
			break
		}
		if state != "APPROVED" {
			t.Fatal("terminal action not retried", state)
		}
	}
	if !applied {
		t.Fatal("no stable exact target obtained for owner-approved fixture action")
	}

	done := operator.state(action.Plan.ID, "APPLIED", 4)
	if done.OutcomeCode != "APPLIED" || done.ApprovedBy != "slack-owner-a" || done.SubmittedAt.IsZero() || done.CompletedAt.IsZero() {
		t.Fatal("executor receipt missing from action")
	}
	waitFor(t, ctx, "owner-approved pod replacement", func() bool {
		pods, err := a.CoreV1().Pods(applicationNamespace).List(ctx, meta.ListOptions{})
		return err == nil && len(pods.Items) == 1 && pods.Items[0].UID != oldUID
	})
	operator.callback("owner", "approve "+action.Plan.ID+" "+action.Hash, false, false)
	operator.state(action.Plan.ID, "APPLIED", 4)
	operator.dispatch()
	operator.audit(dsn, action.Plan.ID, []string{"PROPOSED", "APPROVED", "SUBMITTED", "APPLIED"})

	afterB, _ := b.CoreV1().Pods(applicationNamespace).List(ctx, meta.ListOptions{})
	if len(afterB.Items) != len(beforeB.Items) || afterB.Items[0].UID != beforeB.Items[0].UID {
		t.Fatal("other cluster changed")
	}
	recoveryService := recovery.Service{DB: db, Policy: policy}
	if _, err := recoveryService.SetProfile(ctx, principal("admin", "admins"), incident.RecoveryProfile{Scope: scopeA, ID: "application-health", Version: 1, Handles: []string{healthyHandle}, WindowSeconds: 60, MaximumGapSeconds: 45, MinimumSamples: 3, MinimumReadyReplicas: 1}); err != nil {
		t.Fatal(err)
	}
	assessment, err := recoveryService.Assess(ctx, principal("owner-a", "owner-a"), scopeA, incidentID, "application-health")
	if err != nil || assessment.Status == "RECOVERED" {
		t.Fatal("APPLIED became recovery", err)
	}
	// This is an independent administrator's synthetic fixture repair, not an
	// executor retry. Refresh the fixture update if the deployment controller races.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		deployment, err := a.AppsV1().Deployments(applicationNamespace).Get(ctx, "alice-private", meta.GetOptions{})
		if err != nil {
			return err
		}
		deployment.Spec.Template.Spec.Containers[0].Args = nil
		_, err = a.AppsV1().Deployments(applicationNamespace).Update(ctx, deployment, meta.UpdateOptions{})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, ctx, "external fixture repair", func() bool {
		d, err := a.AppsV1().Deployments(applicationNamespace).Get(ctx, "alice-private", meta.GetOptions{})
		return err == nil && d.Status.ObservedGeneration >= d.Generation && d.Status.ReadyReplicas == 1 && d.Status.UpdatedReplicas == 1 && d.Status.UnavailableReplicas == 0
	})
	for sample := 0; sample < 3; sample++ {
		if sample > 0 {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(31 * time.Second):
			}
		}
		if err := fixtures[0].runtime.Scan(ctx); err != nil {
			t.Fatal(err)
		}
	}
	assessment, err = recoveryService.Assess(ctx, principal("owner-a", "owner-a"), scopeA, incidentID, "application-health")
	if err != nil || assessment.Status != "RECOVERED" {
		t.Fatal("sustained recovery missing", assessment, err)
	}
	req, _ := http.NewRequest("GET", server.URL+"/api/incidents?organization_id="+organization+"&cluster_id=cluster-b&application_id=application", nil)
	req.Header.Set("Authorization", "Bearer fixture-owner-a")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("owner crossed cluster scope")
	}
	// Browser investigations must be claimed by the enrolled collection runtime;
	// an orchestrator-side worker would conceal a broken managed-agent protocol.
	diagnosticCtx, stopDiagnostics := context.WithCancel(ctx)
	diagnosticDone := make(chan error, 1)
	go func() { diagnosticDone <- fixtures[0].runtime.RunDiagnostics(diagnosticCtx, []string{"rule"}, nil) }()
	defer func() { stopDiagnostics(); <-diagnosticDone }()
	runBrowser(t, server.URL, scopeA)
	checkPrivateVolumeRemount(t, ctx, a)
}
