package collection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kubebee-com/sre/pkg/privacy"
	"io"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runtimeFixture(t *testing.T) (RuntimeConfig, *fake.Clientset) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	bootstrap := filepath.Join(dir, "bootstrap")
	os.WriteFile(bootstrap, []byte(strings.Repeat("b", 43)), 0600)
	cfg := RuntimeConfig{ControlPlane: "https://example.com", Scope: runtimeScope, ExpectedClusterUID: "cluster-uid", Namespaces: []string{"customer-canary"}, IdentityKey: make([]byte, 32), RegistryDir: filepath.Join(dir, "registry"), CredentialFile: filepath.Join(dir, "credential"), BootstrapFile: bootstrap}
	return cfg, fake.NewSimpleClientset(&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}})
}
func TestRuntimeRejectsWrongClusterBeforeEnrollment(t *testing.T) {
	cfg, k := runtimeFixture(t)
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer s.Close()
	cfg.ControlPlane = s.URL
	cfg.ExpectedClusterUID = "wrong"
	r, err := newRuntime(cfg, k, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Scan(context.Background()) == nil || calls != 0 {
		t.Fatal("enrollment attempted on wrong cluster")
	}
}
func TestRuntimeRequiresExplicitNamespacesAndPrivateCredentialLocation(t *testing.T) {
	cfg, k := runtimeFixture(t)
	cfg.Namespaces = nil
	if _, err := newRuntime(cfg, k, nil); err == nil {
		t.Fatal("all namespaces allowed")
	}
	cfg.Namespaces = []string{"default"}
	cfg.CredentialFile = filepath.Join(cfg.RegistryDir, "credential")
	if _, err := newRuntime(cfg, k, nil); err == nil {
		t.Fatal("credential allowed in shared registry")
	}
}
func TestRuntimeProjectionPaginationAndPartialCoverage(t *testing.T) {
	cfg, k := runtimeFixture(t)
	pages := 0
	k.PrependReactor("list", "pods", func(action ktesting.Action) (bool, kruntime.Object, error) {
		pages++
		if action.GetNamespace() != "customer-canary" {
			t.Error("unscoped read")
		}
		p := core.Pod{ObjectMeta: meta.ObjectMeta{Name: "private-canary", Namespace: "customer-canary", UID: types.UID("11111111-1111-1111-1111-111111111111"), ResourceVersion: "123"}, Status: core.PodStatus{ContainerStatuses: []core.ContainerStatus{{Name: "secret-canary", RestartCount: 3, State: core.ContainerState{Waiting: &core.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "password-canary"}}}}}}
		if pages == 1 {
			return true, &core.PodList{ListMeta: meta.ListMeta{Continue: "next"}, Items: []core.Pod{p}}, nil
		}
		return true, &core.PodList{}, nil
	})
	k.PrependReactor("list", "deployments", func(ktesting.Action) (bool, kruntime.Object, error) { return true, nil, errors.New("private-canary") })
	reports := []Report{}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/enroll" {
			json.NewEncoder(w).Encode(testCredential())
			return
		}
		b, _ := io.ReadAll(r.Body)
		for _, canary := range []string{"private-canary", "customer-canary", "secret-canary", "password-canary"} {
			if strings.Contains(string(b), canary) {
				t.Error("PII leak")
			}
		}
		var report Report
		if json.Unmarshal(b, &report) != nil || report.Validate() != nil {
			t.Error("invalid report")
		}
		reports = append(reports, report)
		w.WriteHeader(202)
	}))
	defer s.Close()
	cfg.ControlPlane = s.URL
	r, err := newRuntime(cfg, k, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = r.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pages != 2 || len(reports) != 1 || reports[0].Coverage != "PARTIAL" || len(reports[0].Observations) != 1 || reports[0].Observations[0].Code != privacy.CrashLoop {
		t.Fatalf("bad coverage/pages: %d %#v", pages, reports)
	}
	o := reports[0].Observations[0]
	target, err := r.registry.Resolve(o.ResourceHandle, o.Target.Commitment)
	if err != nil || target.Generation != 1 || target.Name != "private-canary" {
		t.Fatal("mapping not committed")
	}
}

func TestRuntimeHealthyBatchingRenewalAndAuthorizationStop(t *testing.T) {
	cfg, k := runtimeFixture(t)
	for i := 0; i < 51; i++ {
		name := fmt.Sprintf("pod-%d", i)
		_, err := k.CoreV1().Pods("customer-canary").Create(context.Background(), &core.Pod{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "customer-canary", UID: types.UID(fmt.Sprintf("11111111-1111-1111-1111-%012d", i)), ResourceVersion: "1"}, Status: core.PodStatus{Conditions: []core.PodCondition{{Type: core.PodReady, Status: core.ConditionTrue}}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	old := testCredential()
	old.Agent.ExpiresAt = time.Now().Add(time.Minute)
	if saveCredential(cfg.CredentialFile, old) != nil {
		t.Fatal("save")
	}
	renewed := false
	reports := 0
	reject := false
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if reject {
			w.WriteHeader(401)
			return
		}
		if req.URL.Path == "/agent/renew" {
			renewed = true
			c := testCredential()
			c.Agent.Generation = 2
			json.NewEncoder(w).Encode(c)
			return
		}
		if req.URL.Path == "/agent/enroll" {
			t.Error("unexpected enrollment")
		}
		reports++
		var report Report
		json.NewDecoder(req.Body).Decode(&report)
		if report.Coverage != "COMPLETE" || len(report.Observations) > 50 {
			t.Error("bad batch")
		}
		for _, o := range report.Observations {
			if o.Code != privacy.Healthy {
				t.Error("healthy missing")
			}
		}
		w.WriteHeader(202)
	}))
	defer s.Close()
	cfg.ControlPlane = s.URL
	r, err := newRuntime(cfg, k, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = r.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !renewed || reports != 2 {
		t.Fatal("renewal/batching missing")
	}
	reject = true
	if r.Scan(context.Background()) != ErrReenrollment {
		t.Fatal("auth rejection ignored")
	}
	reject = false
	if r.Scan(context.Background()) != ErrReenrollment {
		t.Fatal("auth failure not latched")
	}
}
func TestRuntimeRejectsImplicitKubeconfig(t *testing.T) {
	if _, err := NewRuntime(RuntimeConfig{}); err == nil {
		t.Fatal("implicit kubeconfig accepted")
	}
}

func TestRuntimeBoundsReportBytesWithDependencies(t *testing.T) {
	cfg, k := runtimeFixture(t)
	for i := 0; i < 32; i++ {
		k.CoreV1().Pods("customer-canary").Create(context.Background(), &core.Pod{ObjectMeta: meta.ObjectMeta{Name: fmt.Sprintf("pod-%d", i), Namespace: "customer-canary", Labels: map[string]string{"app": "canary"}, UID: types.UID(fmt.Sprintf("11111111-1111-1111-1111-%012d", i)), ResourceVersion: "1"}}, meta.CreateOptions{})
	}
	for i := 0; i < 70; i++ {
		k.CoreV1().Services("customer-canary").Create(context.Background(), &core.Service{ObjectMeta: meta.ObjectMeta{Name: fmt.Sprintf("svc-%d", i), Namespace: "customer-canary", UID: types.UID(fmt.Sprintf("22222222-2222-2222-2222-%012d", i)), ResourceVersion: "1"}, Spec: core.ServiceSpec{Selector: map[string]string{"app": "canary"}}}, meta.CreateOptions{})
	}
	count := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/agent/enroll" {
			json.NewEncoder(w).Encode(testCredential())
			return
		}
		b, _ := io.ReadAll(req.Body)
		if len(b) > maxWireBytes {
			t.Error("oversized report")
		}
		var report Report
		json.Unmarshal(b, &report)
		count += len(report.Observations)
		w.WriteHeader(202)
	}))
	defer s.Close()
	cfg.ControlPlane = s.URL
	r, err := newRuntime(cfg, k, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = r.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count != 102 {
		t.Fatal("incomplete reporting")
	}
}

func TestRuntimeRejectsSharedBootstrapAuthority(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(fmt.Sprint(alias), func(t *testing.T) {
			cfg, k := runtimeFixture(t)
			if err := os.Mkdir(cfg.RegistryDir, 0700); err != nil {
				t.Fatal(err)
			}
			base := cfg.RegistryDir
			if alias {
				base = cfg.RegistryDir + "-alias"
				if err := os.Symlink(cfg.RegistryDir, base); err != nil {
					t.Fatal(err)
				}
			}
			cfg.BootstrapFile = filepath.Join(base, "bootstrap")
			if err := os.WriteFile(cfg.BootstrapFile, []byte(strings.Repeat("b", 43)), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := newRuntime(cfg, k, nil)
			if err == nil {
				r.Close()
				t.Fatal("collector bootstrap exposed on executor registry")
			}
		})
	}
}
