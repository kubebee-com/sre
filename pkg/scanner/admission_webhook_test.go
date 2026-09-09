package scanner

import (
	"context"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestScanWebhooksReportsServiceTargetPortMismatch(t *testing.T) {
	port := int32(8443)
	client := fake.NewSimpleClientset(
		&admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "receiver-config"},
			Webhooks: []admissionregistrationv1.MutatingWebhook{{
				Name: "mutate.example.com",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{Namespace: "webhooks", Name: "receiver", Port: &port},
				},
			}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "receiver", Namespace: "webhooks"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "receiver"},
				Ports:    []corev1.ServicePort{{Name: "https", Port: 443}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "receiver-0", Namespace: "webhooks", Labels: map[string]string{"app": "receiver"}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)

	issues, err := NewClusterScanner(client).scanWebhooks(context.Background(), "")
	if err != nil {
		t.Fatalf("scanWebhooks() error = %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("scanWebhooks() returned %d issues, want one: %#v", len(issues), issues)
	}
	if issues[0].Category != CategoryWebhookTargetMissing {
		t.Fatalf("issue category = %q, want %q: %#v", issues[0].Category, CategoryWebhookTargetMissing, issues[0])
	}
	if !strings.Contains(strings.ToLower(issues[0].Details), "8443") || !strings.Contains(strings.ToLower(issues[0].Details), "443") {
		t.Fatalf("issue details = %q, want referenced and exposed ports", issues[0].Details)
	}
}

func TestScanWebhooksRejectsEmptyServiceNamespaceBeforeLookup(t *testing.T) {
	client := fake.NewSimpleClientset(&admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "receiver-config"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "validate.example.com",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				Service: &admissionregistrationv1.ServiceReference{Name: "receiver"},
			},
		}},
	})
	serviceGets := 0
	client.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		serviceGets++
		return true, nil, apierrors.NewNotFound(action.GetResource().GroupResource(), "receiver")
	})

	issues, err := NewClusterScanner(client).scanWebhooks(context.Background(), "")
	if err != nil {
		t.Fatalf("scanWebhooks() error = %v", err)
	}
	if serviceGets != 0 {
		t.Fatalf("service GET count = %d, want zero for an invalid namespace", serviceGets)
	}
	if len(issues) != 1 || issues[0].Category != CategoryWebhookTargetMissing {
		t.Fatalf("scanWebhooks() issues = %#v, want one target issue", issues)
	}
	if !strings.Contains(strings.ToLower(issues[0].Details), "namespace") {
		t.Fatalf("issue details = %q, want namespace context", issues[0].Details)
	}
}

func TestScanWebhooksReportsInvalidConfigurationFields(t *testing.T) {
	failurePolicy := admissionregistrationv1.FailurePolicyType("Retry")
	matchPolicy := admissionregistrationv1.MatchPolicyType("Loose")
	sideEffects := admissionregistrationv1.SideEffectClassSome
	timeoutSeconds := int32(31)
	webhookURL := "https://webhook.example.com/validate"
	client := fake.NewSimpleClientset(&admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-config"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "validate.example.com",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				URL:      &webhookURL,
				CABundle: []byte("not a PEM certificate"),
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Rule: admissionregistrationv1.Rule{},
			}},
			FailurePolicy:           &failurePolicy,
			MatchPolicy:             &matchPolicy,
			NamespaceSelector:       &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Invalid"}}},
			SideEffects:             &sideEffects,
			TimeoutSeconds:          &timeoutSeconds,
			AdmissionReviewVersions: []string{"", "v1"},
		}},
	})

	issues, err := NewClusterScanner(client).scanWebhooks(context.Background(), "")
	if err != nil {
		t.Fatalf("scanWebhooks() error = %v", err)
	}
	if len(issues) < 8 {
		t.Fatalf("scanWebhooks() returned %d issues, want at least eight configuration findings: %#v", len(issues), issues)
	}
	allText := make([]string, 0, len(issues))
	for _, issue := range issues {
		allText = append(allText, strings.ToLower(issue.Summary+" "+issue.Details))
	}
	joined := strings.Join(allText, "\n")
	for _, want := range []string{"failure", "match policy", "side effect", "timeout", "admission review", "ca bundle", "namespace selector", "rule"} {
		if !strings.Contains(joined, want) {
			t.Errorf("configuration findings omitted %q: %s", want, joined)
		}
	}
}

func TestScanWebhooksAcceptsValidServiceTargetAndConfiguration(t *testing.T) {
	failurePolicy := admissionregistrationv1.Fail
	matchPolicy := admissionregistrationv1.Equivalent
	sideEffects := admissionregistrationv1.SideEffectClassNone
	timeoutSeconds := int32(10)
	client := fake.NewSimpleClientset(
		&admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "valid-config"},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{{
				Name: "validate.example.com",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{Namespace: "webhooks", Name: "receiver"},
				},
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"apps"},
						APIVersions: []string{"v1"},
						Resources:   []string{"deployments"},
					},
				}},
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				NamespaceSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "prod"}},
				ObjectSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{"managed": "true"}},
				SideEffects:             &sideEffects,
				TimeoutSeconds:          &timeoutSeconds,
				AdmissionReviewVersions: []string{"v1"},
			}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "receiver", Namespace: "webhooks"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "receiver"},
				Ports:    []corev1.ServicePort{{Port: 443}},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "receiver-0", Namespace: "webhooks", Labels: map[string]string{"app": "receiver"}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)

	issues, err := NewClusterScanner(client).scanWebhooks(context.Background(), "")
	if err != nil {
		t.Fatalf("scanWebhooks() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("scanWebhooks() returned unexpected issues: %#v", issues)
	}
}

func TestScanWebhooksReportsReturnedServiceNamespaceMismatch(t *testing.T) {
	client := fake.NewSimpleClientset(&admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "receiver-config"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name: "mutate.example.com",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				Service: &admissionregistrationv1.ServiceReference{Namespace: "webhooks", Name: "receiver"},
			},
		}},
	})
	client.PrependReactor("get", "services", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "receiver", Namespace: "other"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 443}}},
		}, nil
	})

	issues, err := NewClusterScanner(client).scanWebhooks(context.Background(), "")
	if err != nil {
		t.Fatalf("scanWebhooks() error = %v", err)
	}
	if len(issues) != 1 || issues[0].Category != CategoryWebhookTargetMissing {
		t.Fatalf("scanWebhooks() issues = %#v, want one target issue", issues)
	}
	if !strings.Contains(strings.ToLower(issues[0].Details), "namespace") {
		t.Fatalf("issue details = %q, want namespace context", issues[0].Details)
	}
}
