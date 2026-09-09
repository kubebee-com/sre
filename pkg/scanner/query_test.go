package scanner

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/kubebee-com/sre/pkg/sanitizer"
)

func TestQueryResourceValidatesIdentifiersBeforeKubernetesAccess(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "ops"}})
	scanner := NewClusterScanner(client)

	if _, err := scanner.QueryResource(context.Background(), "v1/Pods", "ops", "worker"); err != nil {
		t.Fatalf("QueryResource() alias error = %v", err)
	}
	actionsBefore := len(client.Actions())
	for _, test := range []struct {
		kind      string
		namespace string
		name      string
	}{
		{kind: "Pod", namespace: "ops/other", name: "worker"},
		{kind: "Pod", namespace: "ops", name: "worker bad"},
		{kind: "Pod", namespace: "ops", name: "worker\nname"},
		{kind: "Secret", namespace: "ops", name: "credentials"},
	} {
		if _, err := scanner.QueryResource(context.Background(), test.kind, test.namespace, test.name); err == nil {
			t.Fatalf("QueryResource(%#v) accepted invalid or secret request", test)
		}
	}
	if got := len(client.Actions()); got != actionsBefore {
		t.Fatalf("invalid query issued Kubernetes actions: before=%d after=%d", actionsBefore, got)
	}
}

func TestSanitizeResourceRejectsSecretsAndOmitsConfigMapData(t *testing.T) {
	redactor := sanitizer.NewRedactor("literal-secret")
	if _, err := SanitizeResourceForKind("Secret", &corev1.Secret{}, redactor); !errors.Is(err, ErrSecretResource) {
		t.Fatalf("secret projection error = %v, want ErrSecretResource", err)
	}
	if _, err := SanitizeResource(&corev1.Secret{}, redactor); !errors.Is(err, ErrSecretResource) {
		t.Fatalf("typed secret projection error = %v, want ErrSecretResource", err)
	}

	resource, err := SanitizeResourceForKind("ConfigMap", &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ops"},
		Data:       map[string]string{"password": "literal-secret"},
	}, redactor)
	if err != nil {
		t.Fatalf("configmap projection error = %v", err)
	}
	object, ok := resource.(map[string]interface{})
	if !ok {
		t.Fatalf("configmap projection type = %T, want map", resource)
	}
	if _, exists := object["data"]; exists {
		t.Fatal("configmap projection retained data")
	}
}
