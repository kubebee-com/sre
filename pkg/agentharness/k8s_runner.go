package agentharness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	promptMountDir  = "/etc/sre-solver"
	promptFileName  = "prompt.txt"
	promptMountPath = promptMountDir + "/" + promptFileName
	jobPollInterval = 2 * time.Second
)

// K8sJobRunner executes AI agent harnesses (`codex` default, or `agy`) inside
// ephemeral hardened Kubernetes Jobs isolated by a configurable RuntimeClass
// (gVisor by default, or Kata/Firecracker microVM where KVM is available).
type K8sJobRunner struct {
	client       kubernetes.Interface
	cfg          Config
	pollInterval time.Duration
	logFetcher   func(ctx context.Context, namespace, podName, container string) (string, error)
}

func NewK8sJobRunner(client kubernetes.Interface, cfg Config) *K8sJobRunner {
	r := &K8sJobRunner{
		client:       client,
		cfg:          cfg.Normalized(),
		pollInterval: jobPollInterval,
	}
	r.logFetcher = r.fetchPodLogs
	return r
}

func (r *K8sJobRunner) Config() Config {
	return r.cfg
}

func (r *K8sJobRunner) sandboxRuntimeLabel() string {
	if rt := strings.TrimSpace(r.cfg.RuntimeClassName); rt != "" {
		return rt
	}
	return "pod"
}

func (r *K8sJobRunner) CreateSolution(ctx context.Context, issue *scanner.Issue, requested HarnessKind) (*Solution, error) {
	if r == nil || r.client == nil {
		return nil, errors.New("kubernetes client is unavailable for agent sandbox runner")
	}
	if issue == nil {
		return nil, errors.New("issue is required")
	}
	harness, err := r.cfg.ResolveHarness(string(requested))
	if err != nil {
		return nil, err
	}
	prompt := BuildPlanPrompt(issue, r.cfg.GitOpsRepoURL, r.cfg.SecretValues...)
	jobName, rawOutput, err := r.runJob(ctx, harness, PhasePlan, prompt, map[string]string{
		"sre.kubebee.com/issue-id": sanitizeLabelValue(issue.ID),
	})
	if err != nil {
		return nil, err
	}
	solution, err := ParseSolutionOutput(rawOutput, harness, r.sandboxRuntimeLabel(), r.cfg.SecretValues...)
	if err != nil {
		return nil, err
	}
	solution.JobName = jobName
	return solution, nil
}

func (r *K8sJobRunner) ApplySolution(ctx context.Context, req ApplyRequest) (string, error) {
	if r == nil || r.client == nil {
		return "", errors.New("kubernetes client is unavailable for agent sandbox runner")
	}
	if strings.TrimSpace(req.ProposalID) == "" {
		return "", errors.New("proposal ID is required")
	}
	if strings.TrimSpace(req.ApprovedBy) == "" {
		return "", errors.New("approved actor is required before running apply agent")
	}
	harness, err := r.cfg.ResolveHarness(string(req.Harness))
	if err != nil {
		return "", err
	}
	prompt := BuildApplyPrompt(req, r.cfg.GitOpsRepoURL, r.cfg.SecretValues...)
	jobName, rawOutput, err := r.runJob(ctx, harness, PhaseApply, prompt, map[string]string{
		"sre.kubebee.com/proposal-id": sanitizeLabelValue(req.ProposalID),
	})
	if err != nil {
		return "", err
	}
	redactor := sanitizer.RedactorForSecrets(r.cfg.SecretValues...)
	summary := strings.TrimSpace(redactor.SanitizeText(rawOutput))
	if summary == "" {
		return fmt.Sprintf("Agent harness %s (%s) completed job %s", harness, r.sandboxRuntimeLabel(), jobName), nil
	}
	if len(summary) > 4000 {
		summary = summary[len(summary)-4000:]
	}
	return fmt.Sprintf("Agent harness %s (%s, job %s): %s", harness, r.sandboxRuntimeLabel(), jobName, summary), nil
}

// BuildJobSpec constructs the hardened ephemeral Kubernetes Job manifest for
// an agent invocation. Exported so tests and operators can inspect or audit
// the exact pod security and RuntimeClass specification.
func (r *K8sJobRunner) BuildJobSpec(jobName, configMapName string, harness HarnessKind, phase Phase, extraLabels map[string]string) (*batchv1.Job, error) {
	containerCmd, err := BuildContainerCommand(r.cfg, harness, phase, promptMountPath)
	if err != nil {
		return nil, err
	}

	serviceAccount := r.cfg.PlanServiceAccount
	if phase == PhaseApply {
		serviceAccount = r.cfg.ApplyServiceAccount
	}

	labels := map[string]string{
		"app.kubernetes.io/name":          "sre-agent-sandbox",
		"app.kubernetes.io/component":     "sre-agent-sandbox",
		"app.kubernetes.io/managed-by":    "kubebee-sre",
		"sre.kubebee.com/harness":         string(harness),
		"sre.kubebee.com/phase":           string(phase),
		"sre.kubebee.com/sandbox-runtime": sanitizeLabelValue(r.sandboxRuntimeLabel()),
	}
	for k, v := range extraLabels {
		if v != "" {
			labels[k] = sanitizeLabelValue(v)
		}
	}

	runAsNonRoot := true
	runAsUser := int64(10001)
	runAsGroup := int64(10001)
	fsGroup := int64(10001)
	allowPrivilegeEscalation := false
	readOnlyRootFS := true
	backoffLimit := int32(0)
	ttlSeconds := r.cfg.TTLSecondsAfterFinished
	activeDeadline := int64(r.cfg.Timeout.Seconds())
	if activeDeadline < 30 {
		activeDeadline = 30
	}
	automountToken := true
	tmpLimit := resource.MustParse("256Mi")
	workspaceLimit := resource.MustParse("512Mi")

	env := []corev1.EnvVar{
		{Name: "HOME", Value: "/workspace"},
		{Name: "TMPDIR", Value: "/tmp"},
		{Name: "SRE_AGENT_HARNESS", Value: string(harness)},
		{Name: "SRE_AGENT_PHASE", Value: string(phase)},
	}
	if endpoint := strings.TrimSpace(r.cfg.APIEndpoint); endpoint != "" {
		env = append(env,
			corev1.EnvVar{Name: "OPENAI_BASE_URL", Value: endpoint},
			corev1.EnvVar{Name: "OPENAI_API_ENDPOINT", Value: endpoint},
		)
	}
	if model := strings.TrimSpace(r.cfg.Model); model != "" {
		env = append(env, corev1.EnvVar{Name: "OPENAI_MODEL", Value: model})
	}
	if repo := strings.TrimSpace(r.cfg.GitOpsRepoURL); repo != "" {
		env = append(env, corev1.EnvVar{Name: "SRE_GITOPS_REPO_URL", Value: repo})
	}
	if secretName := strings.TrimSpace(r.cfg.OpenAISecretName); secretName != "" {
		optional := true
		env = append(env, corev1.EnvVar{
			Name: "OPENAI_API_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  "OPENAI_API_KEY",
					Optional:             &optional,
				},
			},
		})
	}
	if phase == PhaseApply && strings.TrimSpace(r.cfg.GitOpsSecretName) != "" {
		optional := true
		env = append(env, corev1.EnvVar{
			Name: "GITOPS_TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: r.cfg.GitOpsSecretName},
					Key:                  "GITOPS_TOKEN",
					Optional:             &optional,
				},
			},
		})
	}

	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    parseQuantityOrDefault(r.cfg.CPURequest, DefaultCPURequest),
			corev1.ResourceMemory: parseQuantityOrDefault(r.cfg.MemoryRequest, DefaultMemoryRequest),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    parseQuantityOrDefault(r.cfg.CPULimit, DefaultCPULimit),
			corev1.ResourceMemory: parseQuantityOrDefault(r.cfg.MemoryLimit, DefaultMemoryLimit),
		},
	}

	podSpec := corev1.PodSpec{
		ServiceAccountName:           serviceAccount,
		AutomountServiceAccountToken: &automountToken,
		RestartPolicy:                corev1.RestartPolicyNever,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: &runAsNonRoot,
			RunAsUser:    &runAsUser,
			RunAsGroup:   &runAsGroup,
			FSGroup:      &fsGroup,
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "prompt",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
					},
				},
			},
			{
				Name: "tmp",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &tmpLimit},
				},
			},
			{
				Name: "workspace",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &workspaceLimit},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:            "agent",
				Image:           r.cfg.Image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         containerCmd,
				WorkingDir:      "/workspace",
				Env:             env,
				Resources:       resources,
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &allowPrivilegeEscalation,
					ReadOnlyRootFilesystem:   &readOnlyRootFS,
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "prompt", MountPath: promptMountDir, ReadOnly: true},
					{Name: "tmp", MountPath: "/tmp"},
					{Name: "workspace", MountPath: "/workspace"},
				},
			},
		},
	}
	if rt := strings.TrimSpace(r.cfg.RuntimeClassName); rt != "" {
		runtimeClass := rt
		podSpec.RuntimeClassName = &runtimeClass
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: r.cfg.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoffLimit,
			ActiveDeadlineSeconds:   &activeDeadline,
			TTLSecondsAfterFinished: &ttlSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: podSpec,
			},
		},
	}, nil
}

func (r *K8sJobRunner) runJob(ctx context.Context, harness HarnessKind, phase Phase, prompt string, extraLabels map[string]string) (string, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	suffix := randomHex(4)
	jobName := fmt.Sprintf("sre-solver-%s-%s-%s", phase, harness, suffix)
	cmName := jobName + "-prompt"

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: r.cfg.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/component": "sre-agent-sandbox",
				"app.kubernetes.io/managed-by": "kubebee-sre",
			},
		},
		Data: map[string]string{
			promptFileName: prompt,
		},
	}
	if _, err := r.client.CoreV1().ConfigMaps(r.cfg.Namespace).Create(runCtx, cm, metav1.CreateOptions{}); err != nil {
		return "", "", fmt.Errorf("create solver prompt configmap: %w", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = r.client.CoreV1().ConfigMaps(r.cfg.Namespace).Delete(cleanupCtx, cmName, metav1.DeleteOptions{})
	}()

	job, err := r.BuildJobSpec(jobName, cmName, harness, phase, extraLabels)
	if err != nil {
		return "", "", err
	}
	if _, err := r.client.BatchV1().Jobs(r.cfg.Namespace).Create(runCtx, job, metav1.CreateOptions{}); err != nil {
		return "", "", fmt.Errorf("create solver job: %w", err)
	}

	pollInterval := r.pollInterval
	if pollInterval <= 0 {
		pollInterval = jobPollInterval
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		current, err := r.client.BatchV1().Jobs(r.cfg.Namespace).Get(runCtx, jobName, metav1.GetOptions{})
		if err != nil {
			return jobName, "", fmt.Errorf("get solver job %s: %w", jobName, err)
		}
		if current.Status.Succeeded > 0 {
			output, logErr := r.readJobPodLogs(runCtx, jobName)
			if logErr != nil {
				return jobName, "", logErr
			}
			return jobName, output, nil
		}
		if current.Status.Failed > 0 {
			output, _ := r.readJobPodLogs(runCtx, jobName)
			redactor := sanitizer.RedactorForSecrets(r.cfg.SecretValues...)
			snippet := strings.TrimSpace(redactor.SanitizeText(output))
			if len(snippet) > 512 {
				snippet = snippet[len(snippet)-512:]
			}
			if snippet != "" {
				return jobName, output, fmt.Errorf("solver job %s failed: %s", jobName, snippet)
			}
			return jobName, output, fmt.Errorf("solver job %s failed", jobName)
		}
		select {
		case <-runCtx.Done():
			return jobName, "", fmt.Errorf("solver job %s timed out or cancelled: %w", jobName, runCtx.Err())
		case <-ticker.C:
		}
	}
}

func (r *K8sJobRunner) readJobPodLogs(ctx context.Context, jobName string) (string, error) {
	pods, err := r.client.CoreV1().Pods(r.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "job-name=" + jobName,
	})
	if err != nil {
		return "", fmt.Errorf("list pods for solver job %s: %w", jobName, err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods found for solver job %s", jobName)
	}
	podName := pods.Items[0].Name
	if r.logFetcher != nil {
		return r.logFetcher(ctx, r.cfg.Namespace, podName, "agent")
	}
	return r.fetchPodLogs(ctx, r.cfg.Namespace, podName, "agent")
}

func (r *K8sJobRunner) fetchPodLogs(ctx context.Context, namespace, podName, container string) (string, error) {
	limitBytes := int64(MaxCapturedLogBytes)
	req := r.client.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Container:  container,
		LimitBytes: &limitBytes,
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("stream logs for solver pod %s: %w", podName, err)
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, MaxCapturedLogBytes))
	if err != nil {
		return "", fmt.Errorf("read logs for solver pod %s: %w", podName, err)
	}
	return string(data), nil
}

func parseQuantityOrDefault(raw, fallback string) resource.Quantity {
	if q, err := resource.ParseQuantity(strings.TrimSpace(raw)); err == nil {
		return q
	}
	return resource.MustParse(fallback)
}

func sanitizeLabelValue(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range trimmed {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 63 {
			break
		}
	}
	out := strings.Trim(b.String(), "-_.")
	if out == "" {
		return "unknown"
	}
	return out
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	}
	return hex.EncodeToString(buf)
}
