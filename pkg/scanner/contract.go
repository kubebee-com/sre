package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanplan"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type skipHistoryRecordingKey struct{}

type analyzerAdapter struct {
	info AnalyzerInfo
	run  func(context.Context, string) ([]*Issue, error)
}

func (a analyzerAdapter) Info() AnalyzerInfo {
	return a.info
}

func (a analyzerAdapter) Analyze(ctx context.Context, namespace string) ([]*Issue, error) {
	return a.run(ctx, namespace)
}

func (s *ClusterScanner) RegisteredAnalyzers() []Analyzer {
	analyzers := []Analyzer{
		analyzerAdapter{info: AnalyzerInfo{Name: "PodAnalyzer", Resource: "Pod", Description: "Checks pod state, container failures, events, and bounded logs", DocsURL: "https://kubernetes.io/docs/concepts/workloads/pods/"}, run: s.scanPods},
		analyzerAdapter{info: AnalyzerInfo{Name: "EventAnalyzer", Resource: "Event", Description: "Checks standalone Warning events associated with workload resources", DocsURL: "https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/"}, run: s.scanWarningEvents},
		analyzerAdapter{info: AnalyzerInfo{Name: "DeploymentAnalyzer", Resource: "Deployment", Description: "Checks replica availability and rollout progress", DocsURL: "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/"}, run: s.scanDeployments},
		analyzerAdapter{info: AnalyzerInfo{Name: "StatefulSetAnalyzer", Resource: "StatefulSet", Description: "Checks StatefulSet readiness and update progress", DocsURL: "https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/"}, run: s.scanStatefulSets},
		analyzerAdapter{info: AnalyzerInfo{Name: "DaemonSetAnalyzer", Resource: "DaemonSet", Description: "Checks DaemonSet scheduling and ready pods", DocsURL: "https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/"}, run: s.scanDaemonSets},
		analyzerAdapter{info: AnalyzerInfo{Name: "ReplicaSetAnalyzer", Resource: "ReplicaSet", Description: "Checks ReplicaSet provisioning and ready replicas", DocsURL: "https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/"}, run: s.scanReplicaSets},
		analyzerAdapter{info: AnalyzerInfo{Name: "JobAnalyzer", Resource: "Job", Description: "Checks failed Jobs, retry limits, and deadlines", DocsURL: "https://kubernetes.io/docs/concepts/workloads/controllers/job/"}, run: s.scanJobs},
		analyzerAdapter{info: AnalyzerInfo{Name: "CronJobAnalyzer", Resource: "CronJob", Description: "Checks CronJob schedules and failed executions", DocsURL: "https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/"}, run: s.scanCronJobs},
		analyzerAdapter{info: AnalyzerInfo{Name: "ServiceAnalyzer", Resource: "Service", Description: "Checks Service selectors and ready endpoints", DocsURL: "https://kubernetes.io/docs/concepts/services-networking/service/"}, run: s.scanServices},
		analyzerAdapter{info: AnalyzerInfo{Name: "IngressAnalyzer", Resource: "Ingress", Description: "Checks Ingress classes, backends, and TLS references", DocsURL: "https://kubernetes.io/docs/concepts/services-networking/ingress/"}, run: s.scanIngresses},
		analyzerAdapter{info: AnalyzerInfo{Name: "IngressSemanticsAnalyzer", Resource: "Ingress", Description: "Checks ingress class and Service backend ports", DocsURL: "https://kubernetes.io/docs/concepts/services-networking/ingress/"}, run: s.scanIngressSemantics},
		analyzerAdapter{info: AnalyzerInfo{Name: "NetworkPolicyAnalyzer", Resource: "NetworkPolicy", Description: "Checks NetworkPolicy selectors and matching workloads", DocsURL: "https://kubernetes.io/docs/concepts/services-networking/network-policies/"}, run: s.scanNetworkPolicies},
		analyzerAdapter{info: AnalyzerInfo{Name: "PersistentVolumeClaimAnalyzer", Resource: "PersistentVolumeClaim", Description: "Checks PVC and persistent-volume binding state", DocsURL: "https://kubernetes.io/docs/concepts/storage/persistent-volumes/"}, run: s.scanPVCs},
		analyzerAdapter{info: AnalyzerInfo{Name: "NodeAnalyzer", Resource: "Node", Description: "Checks node readiness and pressure conditions", DocsURL: "https://kubernetes.io/docs/concepts/architecture/nodes/"}, run: func(ctx context.Context, _ string) ([]*Issue, error) { return s.scanNodes(ctx) }},
		analyzerAdapter{info: AnalyzerInfo{Name: "HPAAnalyzer", Resource: "HorizontalPodAutoscaler", Description: "Checks HPA metric availability and scaling limits", DocsURL: "https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/"}, run: s.scanHPAs},
		analyzerAdapter{info: AnalyzerInfo{Name: "HPATargetAnalyzer", Resource: "HorizontalPodAutoscaler", Description: "Checks HPA target workloads and metric definitions", DocsURL: "https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/"}, run: s.scanHPASemantics},
		analyzerAdapter{info: AnalyzerInfo{Name: "PDBAnalyzer", Resource: "PodDisruptionBudget", Description: "Checks disruption budgets that block maintenance", DocsURL: "https://kubernetes.io/docs/concepts/workloads/pods/disruptions/"}, run: s.scanPDBs},
		analyzerAdapter{info: AnalyzerInfo{Name: "PDBSelectorAnalyzer", Resource: "PodDisruptionBudget", Description: "Checks PDB selector validity and workload coverage", DocsURL: "https://kubernetes.io/docs/concepts/workloads/pods/disruptions/"}, run: s.scanPDBSemantics},
		analyzerAdapter{info: AnalyzerInfo{Name: "LogAnalyzer", Resource: "Pod", Description: "Finds bounded error patterns in logs for restarted pods", DocsURL: "https://kubernetes.io/docs/concepts/cluster-administration/logging/"}, run: s.scanPodLogs},
		analyzerAdapter{info: AnalyzerInfo{Name: "WorkloadGraphAnalyzer", Resource: "Workload", Description: "Checks workload selectors against pod templates", DocsURL: "https://kubernetes.io/docs/concepts/workloads/controllers/"}, run: s.scanWorkloadDrift},
		analyzerAdapter{info: AnalyzerInfo{Name: "CronJobScheduleAnalyzer", Resource: "CronJob", Description: "Validates CronJob schedules and reports suspended schedules", DocsURL: "https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/"}, run: s.scanCronSemantics},
		analyzerAdapter{info: AnalyzerInfo{Name: "AdmissionWebhookAnalyzer", Resource: "Webhook", Description: "Checks admission webhook service targets and active pods", DocsURL: "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/"}, run: s.scanWebhooks},
		analyzerAdapter{info: AnalyzerInfo{Name: "ConfigMapAnalyzer", Resource: "ConfigMap", Description: "Checks ConfigMap usage, size, and empty data", DocsURL: "https://kubernetes.io/docs/concepts/configuration/configmap/"}, run: s.scanConfigMaps},
		analyzerAdapter{info: AnalyzerInfo{Name: "StorageAnalyzer", Resource: "Storage", Description: "Checks StorageClasses, PV phases, and PVC capacity", DocsURL: "https://kubernetes.io/docs/concepts/storage/"}, run: s.scanStorage},
		analyzerAdapter{info: AnalyzerInfo{Name: "SecurityAnalyzer", Resource: "Security", Description: "Checks privileged workload and cluster-admin paths", DocsURL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"}, run: s.scanSecurity},
	}
	if s != nil && s.custom != nil {
		analyzers = append(analyzers, s.custom.List()...)
	}
	return analyzers
}

func (s *ClusterScanner) GetAnalyzers() []AnalyzerInfo {
	analyzers := s.RegisteredAnalyzers()
	result := make([]AnalyzerInfo, 0, len(analyzers))
	for _, analyzer := range analyzers {
		info := analyzer.Info()
		info.Enabled = true
		result = append(result, info)
	}
	return result
}

func (s *ClusterScanner) ScanWithPlan(ctx context.Context, plan scanplan.Plan) (*ScanReport, error) {
	if s == nil {
		return nil, ErrKubernetesClientUnavailable
	}
	known := s.GetAnalyzers()
	knownNames := make([]string, 0, len(known))
	for _, info := range known {
		knownNames = append(knownNames, info.Name)
	}
	if err := plan.Validate(knownNames); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	effective := plan.EffectiveScope()
	scanCtx, cancel := context.WithTimeout(ctx, planTimeout(effective.Timeout))
	defer cancel()
	scanCtx = scanplan.WithContext(scanCtx, plan)

	started := time.Now().UTC()
	finish := func(report *ScanReport, err error) (*ScanReport, error) {
		if s.metrics != nil {
			s.metrics.ObserveScan(err, time.Since(started))
		}
		return report, err
	}
	selected := make([]Analyzer, 0, len(known))
	for _, analyzer := range s.RegisteredAnalyzers() {
		info := analyzer.Info()
		info.Enabled = true
		if !plan.IncludesAnalyzer(info.Name) || !resourceSelected(plan, info.Resource) {
			continue
		}
		selected = append(selected, analyzer)
	}
	sort.SliceStable(selected, func(i, j int) bool {
		return strings.ToLower(selected[i].Info().Name) < strings.ToLower(selected[j].Info().Name)
	})

	type result struct {
		run    AnalyzerRun
		issues []*Issue
	}
	results := make(chan result, len(selected))
	semaphore := make(chan struct{}, effective.MaxConcurrency)
	var wg sync.WaitGroup
	namespace := plan.NamespaceArgument()
	for _, analyzer := range selected {
		analyzer := analyzer
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := analyzer.Info()
			if s.client == nil {
				if _, builtIn := analyzer.(analyzerAdapter); builtIn {
					finished := time.Now().UTC()
					results <- result{run: AnalyzerRun{
						Info:       info,
						Error:      sanitizer.SanitizeText(ErrKubernetesClientUnavailable.Error()),
						StartedAt:  finished,
						FinishedAt: finished,
					}}
					return
				}
			}
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-scanCtx.Done():
				info := analyzer.Info()
				finished := time.Now().UTC()
				results <- result{run: AnalyzerRun{
					Info:       info,
					Error:      sanitizer.SanitizeText(scanCtx.Err().Error()),
					StartedAt:  finished,
					FinishedAt: finished,
				}}
				return
			}
			begin := time.Now().UTC()
			issues, err := analyzeSafely(analyzer, scanCtx, namespace)
			if err == nil && scanCtx.Err() != nil {
				err = scanCtx.Err()
			}
			analyzerDuration := time.Since(begin)
			if s.metrics != nil {
				s.metrics.ObserveAnalyzer(info.Name, err, analyzerDuration)
			}
			filtered := make([]*Issue, 0, len(issues))
			for _, rawIssue := range issues {
				issue := cloneIssue(rawIssue)
				if issue == nil || !issueMatchesPlan(plan, issue) {
					continue
				}
				issue.AnalyzerNames = appendUniqueField(issue.AnalyzerNames, info.Name)
				normalizeIssue(issue, info.DocsURL)
				filtered = append(filtered, issue)
			}
			run := AnalyzerRun{
				Info:       info,
				IssueCount: len(filtered),
				Duration:   time.Since(begin).String(),
				StartedAt:  begin,
				FinishedAt: time.Now().UTC(),
			}
			if err != nil {
				run.Error = classifyAnalyzerError(err)
			}
			results <- result{run: run, issues: filtered}
		}()
	}
	wg.Wait()
	close(results)

	report := &ScanReport{
		SchemaVersion: scanplan.SchemaVersion,
		Scope:         effective,
		Issues:        make([]*Issue, 0),
		Analyzers:     make([]AnalyzerRun, 0, len(selected)),
		StartedAt:     started,
		FinishedAt:    time.Now().UTC(),
	}
	for item := range results {
		report.Analyzers = append(report.Analyzers, item.run)
		report.Issues = append(report.Issues, item.issues...)
	}
	report.Issues = s.enrichIssueTargets(scanCtx, report.Issues)
	report.Issues = deduplicateIssues(report.Issues)
	sort.Slice(report.Analyzers, func(i, j int) bool { return report.Analyzers[i].Info.Name < report.Analyzers[j].Info.Name })
	sort.SliceStable(report.Issues, func(i, j int) bool {
		return issueLess(report.Issues[i], report.Issues[j])
	})
	report.Duration = report.FinishedAt.Sub(report.StartedAt).String()
	if scanCtx.Err() != nil {
		report.Error = classifyAnalyzerError(scanCtx.Err())
	}
	if s.history != nil && scanCtx.Value(skipHistoryRecordingKey{}) != true {
		if err := s.recordReport(report); err != nil {
			return finish(report, fmt.Errorf("persist scan history: %w", err))
		}
	}
	if err := scanCtx.Err(); err != nil && err != context.Canceled {
		return finish(report, err)
	}
	if err := scanCtx.Err(); err == context.Canceled && ctx.Err() != nil {
		return finish(report, ctx.Err())
	}
	return finish(report, nil)
}

func analyzeSafely(analyzer Analyzer, ctx context.Context, namespace string) (issues []*Issue, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			issues = nil
			err = fmt.Errorf("analyzer panic: %s", boundIssueText(sanitizer.SanitizeText(fmt.Sprint(recovered)), maxIssueDetailsBytes))
		}
	}()
	return analyzer.Analyze(ctx, namespace)
}

func cloneIssue(issue *Issue) *Issue {
	if issue == nil {
		return nil
	}
	copy := *issue
	copy.AnalyzerNames = append([]string(nil), issue.AnalyzerNames...)
	copy.Events = append([]string(nil), issue.Events...)
	if issue.Parent != nil {
		parent := *issue.Parent
		copy.Parent = &parent
	}
	return &copy
}

func classifyAnalyzerError(err error) string {
	if err == nil {
		return ""
	}
	message := boundIssueText(sanitizer.SanitizeText(err.Error()), maxIssueDetailsBytes)
	switch {
	case apierrors.IsForbidden(err), strings.Contains(strings.ToLower(message), "forbidden"):
		return boundIssueText("forbidden: "+message, maxIssueDetailsBytes)
	case apierrors.IsMethodNotSupported(err), apierrors.IsNotAcceptable(err), strings.Contains(strings.ToLower(message), "unsupported"):
		return boundIssueText("unsupported: "+message, maxIssueDetailsBytes)
	default:
		return message
	}
}

func normalizeIssue(issue *Issue, fallbackDocsURL string) {
	if issue == nil {
		return
	}
	issue.Namespace = boundIssueText(issue.Namespace, 256)
	issue.Kind = boundIssueText(issue.Kind, 128)
	issue.Name = boundIssueText(issue.Name, 253)
	issue.Summary = boundIssueText(issue.Summary, maxIssueSummaryBytes)
	issue.Details = boundIssueText(issue.Details, maxIssueDetailsBytes)
	issue.LogsSnippet = boundIssueText(issue.LogsSnippet, maxIssueLogsSnippetBytes)
	issue.SpecSnippet = boundIssueText(issue.SpecSnippet, maxIssueSpecSnippetBytes)
	issue.DocsURL = boundIssueText(issue.DocsURL, 2048)
	if issue.DocsURL == "" {
		issue.DocsURL = boundIssueText(fallbackDocsURL, 2048)
	}
	if issue.ID == "" {
		issue.ID = makeID(issue.Namespace, issue.Kind, issue.Name, string(issue.Category))
	}
	if len(issue.Events) > maxIssueEventCount {
		issue.Events = issue.Events[:maxIssueEventCount]
	}
	for index := range issue.Events {
		issue.Events[index] = boundIssueText(issue.Events[index], maxIssueEventBytes)
	}
	if issue.Parent != nil {
		issue.Parent.Namespace = boundIssueText(issue.Parent.Namespace, 256)
		issue.Parent.Kind = boundIssueText(issue.Parent.Kind, 128)
		issue.Parent.Name = boundIssueText(issue.Parent.Name, 253)
		issue.Parent.UID = boundIssueText(issue.Parent.UID, 128)
	}
}

func boundIssueText(value string, limit int) string {
	value = sanitizer.SanitizeText(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	value = value[:limit]
	for len(value) > 0 && value[len(value)-1]&0xc0 == 0x80 {
		value = value[:len(value)-1]
	}
	return value
}

func analyzerIssueFingerprint(issue *Issue) string {
	if issue == nil {
		return ""
	}
	return fmt.Sprintf("issue/v1|%s|%s|%s|%s|%s", issueFingerprint(issue), issue.Namespace, issue.Kind, issue.Name, issue.Category)
}

func deduplicateIssues(issues []*Issue) []*Issue {
	seen := make(map[string]*Issue, len(issues))
	for _, issue := range issues {
		if issue == nil {
			continue
		}
		normalizeIssue(issue, issue.DocsURL)
		key := analyzerIssueFingerprint(issue)
		if existing, ok := seen[key]; ok {
			names := appendUniqueField(append([]string(nil), existing.AnalyzerNames...), issue.AnalyzerNames...)
			sort.Strings(names)
			if issueLess(issue, existing) {
				issue.AnalyzerNames = names
				seen[key] = issue
			} else {
				existing.AnalyzerNames = names
			}
		} else {
			seen[key] = issue
		}
	}
	result := make([]*Issue, 0, len(seen))
	for _, issue := range seen {
		result = append(result, issue)
	}
	return result
}

func issueLess(left, right *Issue) bool {
	if left == nil {
		return false
	}
	if right == nil {
		return true
	}
	for _, pair := range [][2]string{
		{left.Namespace, right.Namespace},
		{left.Kind, right.Kind},
		{left.Name, right.Name},
		{left.ID, right.ID},
		{string(left.Category), string(right.Category)},
		{left.Summary, right.Summary},
		{left.Details, right.Details},
	} {
		if pair[0] != pair[1] {
			return pair[0] < pair[1]
		}
	}
	return false
}

func resourceSelected(plan scanplan.Plan, resource string) bool {
	if len(plan.Kinds) == 0 {
		return true
	}
	if strings.EqualFold(resource, "Workload") {
		for _, kind := range []string{"Deployment", "StatefulSet", "ReplicaSet", "DaemonSet", "Job", "CronJob"} {
			if resourceSelected(plan, kind) {
				return true
			}
		}
		return false
	}
	if strings.EqualFold(resource, "Webhook") {
		for _, kind := range []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"} {
			if resourceSelected(plan, kind) {
				return true
			}
		}
		return false
	}
	if strings.EqualFold(resource, "Storage") {
		for _, kind := range []string{"StorageClass", "PersistentVolume", "PersistentVolumeClaim"} {
			if resourceSelected(plan, kind) {
				return true
			}
		}
		return false
	}
	if strings.EqualFold(resource, "Security") {
		for _, kind := range []string{"Pod", "RoleBinding", "ClusterRoleBinding"} {
			if resourceSelected(plan, kind) {
				return true
			}
		}
		return false
	}
	for _, kind := range plan.Kinds {
		if strings.EqualFold(kind, resource) {
			return true
		}
	}
	return false
}

func issueMatchesPlan(plan scanplan.Plan, issue *Issue) bool {
	if strings.TrimSpace(issue.Namespace) == "" {
		if len(plan.Kinds) > 0 && !resourceSelected(plan, issue.Kind) {
			return false
		}
		return len(plan.Names) == 0 || containsName(plan.Names, issue.Name)
	}
	if issue.Kind == "Node" {
		if len(plan.Kinds) > 0 && !resourceSelected(plan, issue.Kind) {
			return false
		}
		if len(plan.Names) > 0 {
			return plan.Includes(issue.Kind, issue.Name, "") || containsName(plan.Names, issue.Name)
		}
		return true
	}
	return plan.Includes(issue.Kind, issue.Name, issue.Namespace)
}

func containsName(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func planTimeout(value string) time.Duration {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return scanplan.DefaultScanTimeout
	}
	return duration
}
