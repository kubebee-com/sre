package systemintegration

// These acceptance tests launch the shipped process, never agent.Run or the
// collection runtime. The Kind runner supplies prebuilt binaries and images.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/agent/collection"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/orchestrator"
	"github.com/kubebee-com/sre/pkg/privacy"
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
)

func unifiedAgentRequired(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if os.Getenv(name) == "" {
			if os.Getenv("SRE_KIND_REQUIRED") == "1" {
				t.Fatalf("required Kind acceptance dependency %s is missing", name)
			}
			t.Skipf("Kind acceptance requires %s", name)
		}
	}
}

func unifiedAgentWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// Each mode has its own application/agent namespace and cluster role. Collector
// credentials cannot mutate workloads or read a namespace outside the allowlist.
func unifiedAgentCluster(t *testing.T, ctx context.Context, c *kubernetes.Clientset, base *rest.Config, dir string) (string, string, string) {
	t.Helper()
	ns := "unified-" + identity.NewID()[:12]
	_, err := c.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: ns}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = c.CoreV1().Namespaces().Delete(cleanup, ns, meta.DeleteOptions{})
		_ = c.RbacV1().ClusterRoleBindings().Delete(cleanup, ns, meta.DeleteOptions{})
		_ = c.RbacV1().ClusterRoles().Delete(cleanup, ns, meta.DeleteOptions{})
	})
	_, err = c.CoreV1().ServiceAccounts(ns).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "agent"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rules := []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "replicasets"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"get", "list"}},
	}
	_, err = c.RbacV1().Roles(ns).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "collector"}, Rules: rules}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: "agent", Namespace: ns}}
	_, err = c.RbacV1().RoleBindings(ns).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "collector"}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "collector"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: ns}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{"kube-system"}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: ns}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: ns}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	seconds := int64(3600)
	token, err := c.CoreV1().ServiceAccounts(ns).CreateToken(ctx, "agent", &authentication.TokenRequest{Spec: authentication.TokenRequestSpec{ExpirationSeconds: &seconds}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ca := base.CAData
	if len(ca) == 0 && base.CAFile != "" {
		ca, err = os.ReadFile(base.CAFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := clientapi.Config{Clusters: map[string]*clientapi.Cluster{"kind": {Server: base.Host, CertificateAuthorityData: ca}}, AuthInfos: map[string]*clientapi.AuthInfo{"agent": {Token: token.Status.Token}}, Contexts: map[string]*clientapi.Context{"kind": {Cluster: "kind", AuthInfo: "agent"}}, CurrentContext: "kind"}
	path := filepath.Join(dir, "agent.kubeconfig")
	if err = clientcmd.WriteToFile(cfg, path); err != nil {
		t.Fatal(err)
	}
	_, restricted := cluster(t, path)
	if _, err = restricted.CoreV1().Pods("kube-system").List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Fatalf("collector crossed namespace boundary: %v", err)
	}
	if err = restricted.CoreV1().Pods(ns).Delete(ctx, "absent", meta.DeleteOptions{DryRun: []string{meta.DryRunAll}}); !apierrors.IsForbidden(err) {
		t.Fatalf("collector obtained mutation authority: %v", err)
	}
	system, err := restricted.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	one := int32(1)
	labels := map[string]string{"app": "unified-private-canary"}
	_, err = c.AppsV1().Deployments(ns).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "private-canary"}, Spec: apps.DeploymentSpec{Replicas: &one, Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{Containers: []core.Container{{Name: "fixture", Image: os.Getenv("SRE_ENTERPRISE_FIXTURE_IMAGE"), ImagePullPolicy: core.PullIfNotPresent, Args: []string{"--crash"}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, "unified workload crash loop", func() bool {
		pods, err := c.CoreV1().Pods(ns).List(ctx, meta.ListOptions{LabelSelector: "app=unified-private-canary"})
		if err != nil {
			return false
		}
		for i := range pods.Items {
			if collection.PodRestarting(&pods.Items[i], time.Now()) {
				return true
			}
		}
		return false
	})
	return ns, string(system.UID), path
}

// A private self-signed certificate includes the Docker gateway so Pods validate
// the same HTTPS control plane used by external agents; TLS is never disabled.
func unifiedAgentTLS(t *testing.T, gateway string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Kind acceptance"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(gateway)}}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func unifiedAgentHTTP(t *testing.T, ctx context.Context, client *http.Client, origin string, scope identity.Scope, token, method, path string, body any, status int, out any) {
	t.Helper()
	var input io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		input = bytes.NewReader(raw)
	}
	q := url.Values{"organization_id": {scope.OrganizationID}, "cluster_id": {scope.ClusterID}, "application_id": {scope.ApplicationID}}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+path+separator+q.Encode(), input)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != status {
		t.Fatalf("%s %s: HTTP %d, want %d", method, path, res.StatusCode, status)
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

func unifiedAgentItems(t *testing.T, ctx context.Context, client *http.Client, origin string, scope identity.Scope, incidentID string) []incident.Item {
	t.Helper()
	var result []incident.Item
	after := ""
	for page := 0; page < 20; page++ {
		var views []struct {
			Item incident.Item `json:"item"`
		}
		unifiedAgentHTTP(t, ctx, client, origin, scope, "fixture-admin", "GET", "/api/incidents/"+incidentID+"/items?after="+url.QueryEscape(after), nil, 200, &views)
		for _, view := range views {
			result = append(result, view.Item)
		}
		if len(views) < 50 {
			return result
		}
		next := views[len(views)-1].Item.ID
		if next <= after {
			t.Fatal("incident item pagination did not advance")
		}
		after = next
	}
	t.Fatal("acceptance incident exceeded 1000 items")
	return nil
}

type unifiedAgentProcess struct {
	cmd     *exec.Cmd
	done    chan error
	log     *os.File
	stopped bool
}

func unifiedAgentStart(t *testing.T, args []string, ca, dir string, input io.Reader) *unifiedAgentProcess {
	t.Helper()
	log, err := os.CreateTemp(dir, "agent-*.log")
	if err != nil {
		t.Fatal(err)
	}
	p := &unifiedAgentProcess{cmd: exec.Command(os.Getenv("SRE_KIND_AGENT_BINARY"), args...), done: make(chan error, 1), log: log}
	// Explicit credential selection remains deterministic on developer machines.
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "KUBECONFIG=") && !strings.HasPrefix(env, "KUBE_CONFIG=") && !strings.HasPrefix(env, "SSL_CERT_FILE=") {
			p.cmd.Env = append(p.cmd.Env, env)
		}
	}
	p.cmd.Env = append(p.cmd.Env, "SSL_CERT_FILE="+ca)
	p.cmd.Stdout, p.cmd.Stderr, p.cmd.Stdin = log, log, input
	if err = p.cmd.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(func() {
		if !p.stopped {
			_ = p.cmd.Process.Kill()
			<-p.done
		}
		_ = log.Close()
		if t.Failed() {
			raw, _ := os.ReadFile(log.Name())
			t.Logf("sre-agent process output:\n%s", raw)
		}
	})
	return p
}
func (p *unifiedAgentProcess) alive(t *testing.T) {
	t.Helper()
	if p == nil {
		return
	}
	select {
	case err := <-p.done:
		p.stopped = true
		t.Fatalf("sre-agent exited before acceptance completed: %v", err)
	default:
	}
}

func (p *unifiedAgentProcess) stop(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		p.stopped = true
		if err != nil {
			t.Fatalf("agent graceful shutdown: %v (log %s)", err, p.log.Name())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not drain on SIGTERM")
	}
}

func TestUnifiedAgentKindAcceptance(t *testing.T) {
	unifiedAgentRequired(t, "SRE_ENTERPRISE_KIND_A", "SRE_ENTERPRISE_KIND_B", "SRE_ENTERPRISE_TEST_DATABASE_URL", "SRE_ENTERPRISE_FIXTURE_IMAGE", "SRE_KIND_AGENT_BINARY", "SRE_KIND_AGENT_IMAGE", "SRE_KIND_HOST_IP")
	binary, err := os.Stat(os.Getenv("SRE_KIND_AGENT_BINARY"))
	if err != nil || !binary.Mode().IsRegular() || binary.Mode().Perm()&0111 == 0 {
		t.Fatal("SRE_KIND_AGENT_BINARY must name a prebuilt executable")
	}
	if net.ParseIP(os.Getenv("SRE_KIND_HOST_IP")) == nil {
		t.Fatal("SRE_KIND_HOST_IP must be the Kind network gateway IP")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	db, err := postgres.Open(ctx, os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for index, configPath := range []string{os.Getenv("SRE_ENTERPRISE_KIND_A"), os.Getenv("SRE_ENTERPRISE_KIND_B")} {
		t.Run(fmt.Sprintf("cluster-%d", index+1), func(t *testing.T) {
			for _, mode := range []string{"kubeconfig", "in-cluster"} {
				t.Run(mode, func(t *testing.T) {
					base, kube := cluster(t, configPath)
					dir := t.TempDir()
					if err := os.Chmod(dir, 0700); err != nil {
						t.Fatal(err)
					}
					ns, uid, kubeconfig := unifiedAgentCluster(t, ctx, kube, base, dir)
					scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: fmt.Sprintf("kind-%d", index+1), ApplicationID: mode}
					policy, err := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "admins", Role: authorization.Administrator}, {Scope: scope, Group: "admins", Role: authorization.Investigator}})
					if err != nil {
						t.Fatal(err)
					}
					grantKey := bytes.Repeat([]byte{7}, 32) // Synthetic shared HA authority key.
					if err := policy.SetGrantKey(grantKey, "kind-generation"); err != nil {
						t.Fatal(err)
					}
					fleetService, err := fleet.NewService(db, policy, "unified-kind-authority")
					if err != nil {
						t.Fatal(err)
					}
					service, err := investigation.NewService(db, policy, []investigation.Profile{{ID: "rule", Version: "v1", Scopes: []identity.Scope{scope}, Metadata: investigation.ProviderMetadata{Provider: "rule"}}})
					if err != nil {
						t.Fatal(err)
					}
					service.AuthorityEpoch = fleetService.Epoch
					queue := &investigation.Queue{Service: service, Scopes: []identity.Scope{scope}}
					// Install the real handler before accepting any requests.
					var handler atomic.Pointer[orchestrator.Server]
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.Load().ServeHTTP(w, r) }))
					_ = server.Listener.Close()
					server.Listener, err = net.Listen("tcp4", "0.0.0.0:0")
					if err != nil {
						t.Fatal(err)
					}
					certificate, caRaw := unifiedAgentTLS(t, os.Getenv("SRE_KIND_HOST_IP"))
					server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
					port := server.Listener.Addr().(*net.TCPAddr).Port
					origin := fmt.Sprintf("https://127.0.0.1:%d", port)
					initial, err := orchestrator.New(orchestrator.Config{DB: db, Policy: policy, Fleet: fleetService, Investigations: service, Queue: queue, Verifier: fixtureVerifier{}, PublicURL: origin})
					if err != nil {
						t.Fatal(err)
					}
					handler.Store(initial)
					server.StartTLS()
					defer server.Close()
					ca := filepath.Join(dir, "ca.pem")
					unifiedAgentWrite(t, ca, caRaw)
					roots := x509.NewCertPool()
					roots.AppendCertsFromPEM(caRaw)
					transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
					boot, err := fleetService.Bootstrap(ctx, principal("admin", "admins"), scope, "unified-agent", uid, fleet.Collector)
					if err != nil {
						t.Fatal(err)
					}
					key := make([]byte, 32)
					if _, err := rand.Read(key); err != nil {
						t.Fatal(err)
					}
					keyFile := filepath.Join(dir, "identity.key")
					bootstrap := filepath.Join(dir, "bootstrap")
					unifiedAgentWrite(t, keyFile, key)
					unifiedAgentWrite(t, bootstrap, []byte(boot.Token))
					state := filepath.Join(dir, "state")
					args := []string{"run", "--orchestrator", origin, "--organization-id", scope.OrganizationID, "--cluster-id", scope.ClusterID, "--application-id", scope.ApplicationID, "--cluster-uid", uid, "--namespaces", ns, "--profiles", "rule", "--state-dir", state, "--identity-key-file", keyFile, "--collector-bootstrap-file", bootstrap}
					var process *unifiedAgentProcess
					if mode == "kubeconfig" {
						args = append(args, "--kubeconfig", kubeconfig)
						process = unifiedAgentStart(t, args, ca, dir, nil)
					} else {
						unifiedAgentPod(t, ctx, kube, ns, args, port, key, []byte(boot.Token), caRaw)
					}
					var current incident.Incident
					var crash privacy.Observation
					waitFor(t, ctx, "binary enrolled and published crash-loop evidence", func() bool {
						process.alive(t)
						var incidents []incident.Incident
						unifiedAgentHTTP(t, ctx, client, origin, scope, "fixture-admin", "GET", "/api/incidents", nil, 200, &incidents)
						if len(incidents) != 1 {
							return false
						}
						current = incidents[0]
						items := unifiedAgentItems(t, ctx, client, origin, scope, current.ID)
						for _, item := range items {
							raw, _ := json.Marshal(item)
							if bytes.Contains(raw, []byte(ns)) || bytes.Contains(raw, []byte("private-canary")) {
								t.Fatal("raw Kubernetes name leaked into central evidence")
							}
							var observation privacy.Observation
							if json.Unmarshal(item.Body, &observation) == nil && observation.Code == privacy.CrashLoop {
								crash = observation
								return true
							}
						}
						return false
					})
					diagnose := func() {
						var job incident.DiagnosticJob
						unifiedAgentHTTP(t, ctx, client, origin, scope, "fixture-admin", "POST", "/api/incidents/"+current.ID+"/investigate", map[string]string{"profile_id": "rule"}, 202, &job)
						waitFor(t, ctx, "unified agent completed queued rule diagnostic", func() bool {
							process.alive(t)
							var jobs []incident.DiagnosticJob
							unifiedAgentHTTP(t, ctx, client, origin, scope, "fixture-admin", "GET", "/api/incidents/"+current.ID+"/jobs", nil, 200, &jobs)
							for _, got := range jobs {
								if got.ID == job.ID {
									if got.State == "FAILED" || got.State == "CANCELLED" {
										t.Fatalf("diagnostic ended in %s", got.State)
									}
									if got.State == "COMPLETED" && got.Result != nil {
										job = got
										return true
									}
									return false
								}
							}
							return false
						})
						found := false
						for _, item := range unifiedAgentItems(t, ctx, client, origin, scope, current.ID) {
							if item.ID != job.Result.ID || item.Version != job.Result.Version {
								continue
							}
							var result investigation.RunResult
							if err := json.Unmarshal(item.Body, &result); err != nil {
								t.Fatal(err)
							}
							if item.Kind != incident.Claim || result.RunID != job.ID || result.ProfileID != "rule" || result.ProfileVersion != "v1" || result.PrivacyVersion != privacy.Version {
								t.Fatal("queued diagnostic result has invalid provenance")
							}
							found = true
						}
						if !found {
							t.Fatal("completed agent diagnostic has no durable claim")
						}
					}
					diagnose()
					if process == nil {
						return
					}
					process.stop(t)
					credentialPath := filepath.Join(state, "collector", "credential")
					before, err := os.ReadFile(credentialPath)
					if err != nil {
						t.Fatal(err)
					}
					var credential fleet.Credential
					if err := json.Unmarshal(before, &credential); err != nil {
						t.Fatal(err)
					}
					if credential.Agent.ID != "unified-agent" || credential.Token == "" {
						t.Fatal("binary did not persist enrolled collector")
					}
					registry, err := collection.OpenRegistry(filepath.Join(state, "identities"), key, true)
					if err != nil {
						t.Fatal(err)
					}
					// The opaque central evidence must still resolve from encrypted disk state.
					resolved := false
					for _, item := range unifiedAgentItems(t, ctx, client, origin, scope, current.ID) {
						var observation privacy.Observation
						if json.Unmarshal(item.Body, &observation) != nil || observation.ResourceHandle != crash.ResourceHandle || observation.Target == nil {
							continue
						}
						if target, err := registry.Resolve(observation.ResourceHandle, observation.Target.Commitment); err == nil && target.Namespace == ns {
							resolved = true
						}
					}
					_ = registry.Close()
					if !resolved {
						t.Fatal("persisted target registry lost evidence mapping")
					}
					if err := os.Remove(bootstrap); err != nil {
						t.Fatal(err)
					}
					// Queue while the agent is stopped, then reconstruct the orchestrator
					// with fresh services and the same shared authority key. The resumed
					// agent must finish this durable job without reenrollment.
					var pending incident.DiagnosticJob
					unifiedAgentHTTP(t, ctx, client, origin, scope, "fixture-admin", "POST", "/api/incidents/"+current.ID+"/investigate", map[string]string{"profile_id": "rule"}, 202, &pending)
					if pending.State != "QUEUED" {
						t.Fatalf("offline agent job state %s", pending.State)
					}
					nextPolicy, err := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "admins", Role: authorization.Administrator}, {Scope: scope, Group: "admins", Role: authorization.Investigator}})
					if err != nil {
						t.Fatal(err)
					}
					if err := nextPolicy.SetGrantKey(grantKey, "kind-generation"); err != nil {
						t.Fatal(err)
					}
					nextFleet, err := fleet.NewService(db, nextPolicy, "unified-kind-authority")
					if err != nil {
						t.Fatal(err)
					}
					if nextFleet.Epoch != fleetService.Epoch {
						t.Fatal("orchestrator restart changed configured authority epoch")
					}
					nextService, err := investigation.NewService(db, nextPolicy, []investigation.Profile{{ID: "rule", Version: "v1", Scopes: []identity.Scope{scope}, Metadata: investigation.ProviderMetadata{Provider: "rule"}}})
					if err != nil {
						t.Fatal(err)
					}
					nextService.AuthorityEpoch = nextFleet.Epoch
					next, err := orchestrator.New(orchestrator.Config{DB: db, Policy: nextPolicy, Fleet: nextFleet, Investigations: nextService, Queue: &investigation.Queue{Service: nextService, Scopes: []identity.Scope{scope}}, Verifier: fixtureVerifier{}, PublicURL: origin})
					if err != nil {
						t.Fatal(err)
					}
					handler.Store(next)
					process = unifiedAgentStart(t, args, ca, dir, nil)
					diagnose()
					var resumed []incident.DiagnosticJob
					unifiedAgentHTTP(t, ctx, client, origin, scope, "fixture-admin", "GET", "/api/incidents/"+current.ID+"/jobs", nil, 200, &resumed)
					survived := false
					for _, job := range resumed {
						if job.ID == pending.ID && job.State == "COMPLETED" && job.Result != nil {
							survived = true
						}
					}
					if !survived {
						t.Fatal("orchestrator restart lost queued authority/job")
					}
					process.stop(t)
					after, err := os.ReadFile(credentialPath)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(before, after) {
						t.Fatal("short restart replaced collector credential")
					}
					// An agent token cannot impersonate a human on the orchestration API.
					unifiedAgentHTTP(t, ctx, client, origin, scope, credential.Token, "GET", "/api/incidents", nil, 401, nil)
					invalidArgs := append(append([]string{}, args...), "--interactive", "--human-token-file", credentialPath)
					invalidCtx, invalidCancel := context.WithTimeout(ctx, 10*time.Second)
					invalid := exec.CommandContext(invalidCtx, os.Getenv("SRE_KIND_AGENT_BINARY"), invalidArgs...)
					output, invalidErr := invalid.CombinedOutput()
					invalidCancel()
					if invalidErr == nil || !bytes.Contains(output, []byte("human identity must be separate")) {
						t.Fatalf("interactive CLI did not reject agent credential alias: %v %s", invalidErr, output)
					}
					humanFile := filepath.Join(dir, "human-token")
					unifiedAgentWrite(t, humanFile, []byte("fixture-admin"))
					interactiveArgs := append(append([]string{}, args...), "--interactive", "--human-token-file", humanFile)
					input, writer, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					defer input.Close()
					defer writer.Close()
					process = unifiedAgentStart(t, interactiveArgs, ca, dir, input)
					waitFor(t, ctx, "interactive human channel", func() bool {
						process.alive(t)
						raw, _ := os.ReadFile(process.log.Name())
						return bytes.Contains(raw, []byte("Commands: investigate"))
					})
					// Exercise an actual terminal command against the human-authenticated API.
					var oldJobs []incident.DiagnosticJob
					unifiedAgentHTTP(t, ctx, client, origin, scope, "fixture-admin", "GET", "/api/incidents/"+current.ID+"/jobs", nil, 200, &oldJobs)
					if _, err := fmt.Fprintf(writer, "investigate %s rule\n", current.ID); err != nil {
						t.Fatal(err)
					}
					waitFor(t, ctx, "human terminal queued and agent completed diagnostic", func() bool {
						process.alive(t)
						var jobs []incident.DiagnosticJob
						unifiedAgentHTTP(t, ctx, client, origin, scope, "fixture-admin", "GET", "/api/incidents/"+current.ID+"/jobs", nil, 200, &jobs)
						if len(jobs) <= len(oldJobs) {
							return false
						}
						known := map[string]bool{}
						for _, job := range oldJobs {
							known[job.ID] = true
						}
						for _, job := range jobs {
							if !known[job.ID] && job.State == "COMPLETED" && job.Result != nil {
								return true
							}
						}
						return false
					})
					// EOF cleanly detaches the terminal and drains the process workers.
					_ = writer.Close()
					select {
					case err := <-process.done:
						process.stopped = true
						if err != nil {
							t.Fatalf("interactive EOF shutdown: %v", err)
						}
					case <-time.After(20 * time.Second):
						t.Fatal("interactive EOF did not stop agent")
					}
				})
			}
		})
	}
}

func unifiedAgentPod(t *testing.T, ctx context.Context, kube *kubernetes.Clientset, ns string, args []string, port int, key, bootstrap, ca []byte) {
	t.Helper()
	// The product init command copies projected Secrets to private regular files.
	// The agent creates 0700 state beneath emptyDir and uses its ServiceAccount.
	// The projected Secret is readable only by the agent's fsGroup; the init
	// container copies it into 0600 files owned by the non-root UID.
	mode := int32(0640)
	_, err := kube.CoreV1().Secrets(ns).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "agent-bootstrap"}, Data: map[string][]byte{"key": key, "bootstrap": bootstrap, "ca.pem": ca}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	podArgs := append([]string{}, args...)
	for i := range podArgs {
		if i == 0 {
			continue
		}
		switch podArgs[i-1] {
		case "--orchestrator":
			podArgs[i] = fmt.Sprintf("https://%s:%d", os.Getenv("SRE_KIND_HOST_IP"), port)
		case "--state-dir":
			podArgs[i] = "/data/state"
		case "--identity-key-file":
			podArgs[i] = "/data/material/identity.key"
		case "--collector-bootstrap-file":
			podArgs[i] = "/data/material/bootstrap"
		}
	}
	podArgs = append(podArgs, "--in-cluster")
	uid := int64(65532)
	gid := int64(65532)
	nonRoot := true
	fsGroupChangePolicy := core.FSGroupChangeOnRootMismatch
	mounts := []core.VolumeMount{{Name: "bootstrap", MountPath: "/bootstrap", ReadOnly: true}, {Name: "state", MountPath: "/data"}}
	pod := &core.Pod{
		ObjectMeta: meta.ObjectMeta{Name: "unified-agent"},
		Spec: core.PodSpec{
			ServiceAccountName: "agent", RestartPolicy: core.RestartPolicyNever,
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: &nonRoot, RunAsUser: &uid, RunAsGroup: &gid, FSGroup: &gid, FSGroupChangePolicy: &fsGroupChangePolicy},
			InitContainers: []core.Container{{
				Name: "initialize", Image: os.Getenv("SRE_KIND_AGENT_IMAGE"), ImagePullPolicy: core.PullNever,
				Command:      []string{"/usr/local/bin/sre-agent"},
				Args:         []string{"init", "--source-key", "/bootstrap/key", "--source-bootstrap", "/bootstrap/bootstrap", "--destination", "/data/material"},
				VolumeMounts: mounts,
			}},
			Containers: []core.Container{{
				Name: "agent", Image: os.Getenv("SRE_KIND_AGENT_IMAGE"), ImagePullPolicy: core.PullNever,
				Command: []string{"/usr/local/bin/sre-agent"}, Args: podArgs,
				Env:          []core.EnvVar{{Name: "SSL_CERT_FILE", Value: "/bootstrap/ca.pem"}},
				VolumeMounts: mounts,
			}},
			Volumes: []core.Volume{
				{Name: "bootstrap", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "agent-bootstrap", DefaultMode: &mode}}},
				{Name: "state", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{}}},
			},
		},
	}
	_, err = kube.CoreV1().Pods(ns).Create(ctx, pod, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		pod, err := kube.CoreV1().Pods(ns).Get(cleanup, "unified-agent", meta.GetOptions{})
		if err == nil {
			t.Logf("in-cluster agent phase=%s containers=%+v", pod.Status.Phase, append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...))
		}
		raw, err := kube.CoreV1().Pods(ns).GetLogs("unified-agent", &core.PodLogOptions{Container: "agent"}).DoRaw(cleanup)
		if err == nil {
			t.Logf("in-cluster agent output:\n%s", raw)
		}
	})
}
