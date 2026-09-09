package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestScanWorkloadDriftIncludesDaemonSetJobAndCronJob(t *testing.T) {
	ctx := context.Background()
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "expected"}}
	template := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "actual"}}}
	manual := true
	client := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "daemon", Namespace: "default"},
			Spec:       appsv1.DaemonSetSpec{Selector: selector, Template: template},
		},
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "default"},
			Spec:       batchv1.JobSpec{ManualSelector: &manual, Selector: selector, Template: template},
		},
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "cron", Namespace: "default"},
			Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{ManualSelector: &manual, Selector: selector, Template: template},
			}},
		},
	)

	issues, err := NewClusterScanner(client).scanWorkloadDrift(ctx, "default")
	if err != nil {
		t.Fatalf("scanWorkloadDrift() error = %v", err)
	}
	got := make(map[string]bool, len(issues))
	for _, issue := range issues {
		got[issue.Kind] = true
	}
	for _, kind := range []string{"DaemonSet", "Job", "CronJob"} {
		if !got[kind] {
			t.Errorf("scanWorkloadDrift() omitted %s: %#v", kind, issues)
		}
	}
}

func TestScanWorkloadDriftIgnoresControllerGeneratedJobSelectors(t *testing.T) {
	client := fake.NewSimpleClientset(
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "generated-job", Namespace: "default"},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{"job-name": "generated-job"},
			}}},
		},
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "generated-cron", Namespace: "default"},
			Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"job-name": "generated-cron"}}},
			}}},
		},
	)

	issues, err := NewClusterScanner(client).scanWorkloadDrift(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanWorkloadDrift() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("scanWorkloadDrift() reported generated selectors as drift: %#v", issues)
	}
}

func TestConfigMapUsageIncludesAllWorkloadKindsAndEphemeralContainers(t *testing.T) {
	configMapKey := func(name string) *corev1.EnvVarSource {
		return &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: name}, Key: "value"}}
	}
	configMapRef := func(name string) *corev1.EnvFromSource {
		return &corev1.EnvFromSource{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: name}}}
	}
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}}
	workloadTemplate := func(container corev1.Container) corev1.PodTemplateSpec {
		return corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{container}}}
	}
	manual := true
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
				EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:    "debug",
					Env:     []corev1.EnvVar{{Name: "KEY", ValueFrom: configMapKey("ephemeral-key")}},
					EnvFrom: []corev1.EnvFromSource{*configMapRef("ephemeral-env")},
				}}},
			},
		},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "deployment", Namespace: "default"}, Spec: appsv1.DeploymentSpec{Selector: selector, Template: workloadTemplate(corev1.Container{Name: "app", Env: []corev1.EnvVar{{ValueFrom: configMapKey("deployment")}}})}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "stateful", Namespace: "default"}, Spec: appsv1.StatefulSetSpec{Selector: selector, Template: workloadTemplate(corev1.Container{Name: "app", EnvFrom: []corev1.EnvFromSource{*configMapRef("stateful")}})}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "daemon", Namespace: "default"}, Spec: appsv1.DaemonSetSpec{Selector: selector, Template: workloadTemplate(corev1.Container{Name: "app", Env: []corev1.EnvVar{{ValueFrom: configMapKey("daemon")}}})}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "replica", Namespace: "default"}, Spec: appsv1.ReplicaSetSpec{Selector: selector, Template: workloadTemplate(corev1.Container{Name: "app", VolumeMounts: []corev1.VolumeMount{{Name: "projected"}}})}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "default"}, Spec: batchv1.JobSpec{ManualSelector: &manual, Selector: selector, Template: workloadTemplate(corev1.Container{Name: "app", EnvFrom: []corev1.EnvFromSource{*configMapRef("job")}})}},
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "cron", Namespace: "default"}, Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{ManualSelector: &manual, Selector: selector, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}, Volumes: []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cron-volume"}}}}}}}}}}},
	)
	// Add a projected ConfigMap after construction to keep the ReplicaSet fixture readable.
	replicaSet, err := client.AppsV1().ReplicaSets("default").Get(context.Background(), "replica", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get ReplicaSet fixture: %v", err)
	}
	replicaSet.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "projected", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "replica-projected"}}}}}}}}
	if _, err := client.AppsV1().ReplicaSets("default").Update(context.Background(), replicaSet, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update ReplicaSet fixture: %v", err)
	}

	used, err := NewClusterScanner(client).configMapUsage(context.Background(), "default")
	if err != nil {
		t.Fatalf("configMapUsage() error = %v", err)
	}
	for _, name := range []string{"deployment", "stateful", "daemon", "replica-projected", "job", "cron-volume", "ephemeral-key", "ephemeral-env"} {
		if _, ok := used[namespaceKey("default", name)]; !ok {
			t.Errorf("configMapUsage() omitted %q: %#v", name, used)
		}
	}
}

func TestReadBoundedLogSnippetNeverReadsBeyondLimit(t *testing.T) {
	const limit = 32
	input := strings.Repeat("error ", 100)
	reader := &countingReader{reader: strings.NewReader(input)}
	got := readBoundedLogSnippet(reader, limit)
	if len(got) != limit {
		t.Fatalf("readBoundedLogSnippet() length = %d, want %d", len(got), limit)
	}
	if got != input[:limit] {
		t.Fatalf("readBoundedLogSnippet() = %q, want prefix %q", got, input[:limit])
	}
	if reader.bytesRead > limit {
		t.Fatalf("readBoundedLogSnippet() consumed %d bytes, want at most %d", reader.bytesRead, limit)
	}
}

type countingReader struct {
	reader    *strings.Reader
	bytesRead int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)
	return n, err
}

func TestPodSecurityFindingsIncludeEphemeralContainerChecks(t *testing.T) {
	privileged := true
	allowPrivilegeEscalation := true
	root := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "debuggable", Namespace: "default"},
		Spec: corev1.PodSpec{EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:            "debug",
			SecurityContext: &corev1.SecurityContext{Privileged: &privileged, AllowPrivilegeEscalation: &allowPrivilegeEscalation, RunAsUser: &root},
		}}}},
	}

	issues := podSecurityFindings(pod)
	got := make(map[string]bool, len(issues))
	for _, issue := range issues {
		got[issue.ID] = true
	}
	for _, suffix := range []string{"Privileged-ephemeral-debug", "PrivilegeEscalation-ephemeral-debug", "Root-ephemeral-debug"} {
		if !got[makeID("default", "Pod", "debuggable", suffix)] {
			t.Errorf("podSecurityFindings() omitted ephemeral %s: %#v", suffix, issues)
		}
	}
}

func TestScanWebhooksReturnsPermissionErrors(t *testing.T) {
	client := fake.NewSimpleClientset(&admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "webhook"},
		Webhooks:   []admissionregistrationv1.MutatingWebhook{{Name: "check.example.com", ClientConfig: admissionregistrationv1.WebhookClientConfig{Service: &admissionregistrationv1.ServiceReference{Namespace: "default", Name: "webhook"}}}},
	})
	client.PrependReactor("get", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "webhook", errors.New("service access denied"))
	})

	_, err := NewClusterScanner(client).scanWebhooks(context.Background(), "")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanWebhooks() error = %v, want Forbidden", err)
	}
}

func TestScanWebhooksReturnsBackingPodPermissionErrors(t *testing.T) {
	client := fake.NewSimpleClientset(
		&admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "webhook"},
			Webhooks:   []admissionregistrationv1.MutatingWebhook{{Name: "check.example.com", ClientConfig: admissionregistrationv1.WebhookClientConfig{Service: &admissionregistrationv1.ServiceReference{Namespace: "default", Name: "webhook"}}}},
		},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "webhook", Namespace: "default", Labels: map[string]string{"app": "webhook"}}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "webhook"}}},
	)
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("backing pod access denied"))
	})

	_, err := NewClusterScanner(client).scanWebhooks(context.Background(), "")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanWebhooks() error = %v, want Forbidden", err)
	}
}

func TestScanHPASemanticsReturnsPermissionErrors(t *testing.T) {
	client := fake.NewSimpleClientset(&autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "autoscaler", Namespace: "default"},
		Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "workload"}},
	})
	client.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "workload", errors.New("deployment access denied"))
	})

	_, err := NewClusterScanner(client).scanHPASemantics(context.Background(), "default")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanHPASemantics() error = %v, want Forbidden", err)
	}
}

func TestScanPDBSemanticsReturnsPermissionErrors(t *testing.T) {
	client := fake.NewSimpleClientset(&policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "budget", Namespace: "default"},
		Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}}},
	})
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("pod access denied"))
	})

	_, err := NewClusterScanner(client).scanPDBSemantics(context.Background(), "default")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanPDBSemantics() error = %v, want Forbidden", err)
	}
}

func TestScanIngressSemanticsReturnsSecretListPermissionErrors(t *testing.T) {
	client := fake.NewSimpleClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "tls"}}},
	})
	client.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("secret access denied"))
	})

	_, err := NewClusterScanner(client).scanIngressSemantics(context.Background(), "default")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanIngressSemantics() error = %v, want Forbidden", err)
	}
}

func TestPermissionErrorsDoNotChangeNotFoundFindings(t *testing.T) {
	client := fake.NewSimpleClientset(
		&admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "webhook"},
			Webhooks:   []admissionregistrationv1.MutatingWebhook{{Name: "check.example.com", ClientConfig: admissionregistrationv1.WebhookClientConfig{Service: &admissionregistrationv1.ServiceReference{Namespace: "default", Name: "missing"}}}},
		},
		&autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "autoscaler", Namespace: "default"}, Spec: autoscalingv2.HorizontalPodAutoscalerSpec{ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "missing"}}},
	)

	webhookIssues, err := NewClusterScanner(client).scanWebhooks(context.Background(), "")
	if err != nil || len(webhookIssues) != 1 || webhookIssues[0].Category != CategoryWebhookServiceMissing {
		t.Fatalf("missing webhook service = issues %#v, err %v", webhookIssues, err)
	}
	hpaIssues, err := NewClusterScanner(client).scanHPASemantics(context.Background(), "default")
	if err != nil || len(hpaIssues) != 1 || hpaIssues[0].Category != CategoryHPATargetMissing {
		t.Fatalf("missing HPA target = issues %#v, err %v", hpaIssues, err)
	}
}
