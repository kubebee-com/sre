package scanner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanplan"
)

// DynamicCapabilityState describes whether an optional CRD family can be
// queried with the caller's Kubernetes identity.
type DynamicCapabilityState string

const (
	DynamicCapabilityAvailable   DynamicCapabilityState = "available"
	DynamicCapabilityAbsent      DynamicCapabilityState = "absent"
	DynamicCapabilityForbidden   DynamicCapabilityState = "forbidden"
	DynamicCapabilityUnsupported DynamicCapabilityState = "unsupported"
	DynamicCapabilityUnavailable DynamicCapabilityState = "unavailable"
)

// DynamicAnalyzerInfo extends the core analyzer contract with capability
// discovery data. Dynamic analyzers are deliberately optional: a cluster that
// does not install a CRD, or does not grant access to it, remains scannable.
type DynamicAnalyzerInfo struct {
	AnalyzerInfo
	Family    string                        `json:"family"`
	Optional  bool                          `json:"optional"`
	Scope     string                        `json:"scope"`
	Resources []schema.GroupVersionResource `json:"resources"`
}

// DynamicResourceCapability records the result for one supported GVR. A
// family can list more than one version so a CRD upgrade does not break scans.
type DynamicResourceCapability struct {
	Resource   schema.GroupVersionResource `json:"resource"`
	Namespaced bool                        `json:"namespaced"`
	State      DynamicCapabilityState      `json:"state"`
	Error      string                      `json:"error,omitempty"`
}

// DynamicCapability is returned by Capability and is safe to expose in API
// metadata. It contains no object payloads or status messages from the CRD.
type DynamicCapability struct {
	Family    string                      `json:"family"`
	Analyzer  string                      `json:"analyzer"`
	Optional  bool                        `json:"optional"`
	State     DynamicCapabilityState      `json:"state"`
	Resources []DynamicResourceCapability `json:"resources"`
}

// DynamicAnalyzer is the optional analyzer contract. Analyze follows the
// existing scanner Analyzer interface; the additional methods make optional
// API availability explicit to callers and user interfaces.
type DynamicAnalyzer interface {
	Analyzer
	DynamicInfo() DynamicAnalyzerInfo
	Capability(context.Context) DynamicCapability
}

const (
	CategoryGatewayClassNotAccepted      IssueCategory = "GatewayClassNotAccepted"
	CategoryGatewayNotAccepted           IssueCategory = "GatewayNotAccepted"
	CategoryGatewayNotProgrammed         IssueCategory = "GatewayNotProgrammed"
	CategoryGatewayListenerInvalid       IssueCategory = "GatewayListenerInvalid"
	CategoryGatewaySpecInvalid           IssueCategory = "GatewaySpecInvalid"
	CategoryHTTPRouteNoParent            IssueCategory = "HTTPRouteNoParent"
	CategoryHTTPRouteParentNotAccepted   IssueCategory = "HTTPRouteParentNotAccepted"
	CategoryHTTPRouteRefsNotResolved     IssueCategory = "HTTPRouteRefsNotResolved"
	CategoryHTTPRouteBackendMissing      IssueCategory = "HTTPRouteBackendMissing"
	CategoryHTTPRouteBackendInvalid      IssueCategory = "HTTPRouteBackendInvalid"
	CategoryReferenceGrantInvalid        IssueCategory = "ReferenceGrantInvalid"
	CategoryReferenceGrantMissing        IssueCategory = "ReferenceGrantMissing"
	CategoryOLMResourceUnhealthy         IssueCategory = "OLMResourceUnhealthy"
	CategoryIntegrationResourceUnhealthy IssueCategory = "IntegrationResourceUnhealthy"
	CategoryDynamicMalformed             IssueCategory = "DynamicResourceMalformed"
)

var (
	gatewayClassGVR   = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}
	gatewayGVR        = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	httpRouteGVR      = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
	referenceGrantGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "referencegrants"}
	serviceGVR        = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}

	clusterCatalogGVR        = schema.GroupVersionResource{Group: "olm.operatorframework.io", Version: "v1", Resource: "clustercatalogs"}
	clusterExtensionGVR      = schema.GroupVersionResource{Group: "olm.operatorframework.io", Version: "v1", Resource: "clusterextensions"}
	clusterServiceVersionGVR = schema.GroupVersionResource{Group: "operators.coreos.com", Version: "v1alpha1", Resource: "clusterserviceversions"}
	subscriptionGVR          = schema.GroupVersionResource{Group: "operators.coreos.com", Version: "v1alpha1", Resource: "subscriptions"}
	installPlanGVR           = schema.GroupVersionResource{Group: "operators.coreos.com", Version: "v1alpha1", Resource: "installplans"}
	catalogSourceGVR         = schema.GroupVersionResource{Group: "operators.coreos.com", Version: "v1alpha1", Resource: "catalogsources"}
	operatorGroupGVR         = schema.GroupVersionResource{Group: "operators.coreos.com", Version: "v1", Resource: "operatorgroups"}

	kedaScaledObjectGVR           = schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}
	kedaScaledJobGVR              = schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledjobs"}
	kedaTriggerAuthenticationGVR  = schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "triggerauthentications"}
	kedaClusterTriggerAuthGVR     = schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "clustertriggerauthentications"}
	kyvernoPolicyGVR              = schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "policies"}
	kyvernoClusterPolicyGVR       = schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "clusterpolicies"}
	kyvernoPolicyReportGVR        = schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports"}
	kyvernoClusterPolicyReportGVR = schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports"}
	prometheusGVR                 = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheuses"}
	serviceMonitorGVR             = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors"}
	podMonitorGVR                 = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "podmonitors"}
	prometheusRuleGVR             = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheusrules"}
	alertmanagerGVR               = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "alertmanagers"}
)

type dynamicResourceSpec struct {
	GVR        schema.GroupVersionResource
	Kind       string
	Namespaced bool
}

type dynamicAnalyzer struct {
	mu              sync.RWMutex
	client          dynamic.Interface
	owner           *DynamicAnalyzerSet
	info            DynamicAnalyzerInfo
	resources       []dynamicResourceSpec
	analyzeResource func(context.Context, dynamicResourceSpec, *unstructured.Unstructured) []*Issue
}

func (a *dynamicAnalyzer) Info() AnalyzerInfo {
	info := a.info.AnalyzerInfo
	info.Enabled = true
	return info
}

func (a *dynamicAnalyzer) DynamicInfo() DynamicAnalyzerInfo {
	info := a.info
	info.AnalyzerInfo.Enabled = true
	info.Resources = append([]schema.GroupVersionResource(nil), info.Resources...)
	return info
}

func (a *dynamicAnalyzer) setClient(client dynamic.Interface) {
	a.mu.Lock()
	a.client = client
	a.mu.Unlock()
}

func (a *dynamicAnalyzer) getClient() dynamic.Interface {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.client
}

func (a *dynamicAnalyzer) Capability(ctx context.Context) DynamicCapability {
	if ctx == nil {
		ctx = context.Background()
	}
	capability := DynamicCapability{
		Family:    a.info.Family,
		Analyzer:  a.info.Name,
		Optional:  a.info.Optional,
		Resources: make([]DynamicResourceCapability, 0, len(a.resources)),
	}
	client := a.getClient()
	options := listOptionsForScan(ctx)
	for _, spec := range a.resources {
		outcome := listDynamicResource(ctx, client, spec, dynamicNamespace(ctx, spec.Namespaced, ""), options)
		item := DynamicResourceCapability{Resource: spec.GVR, Namespaced: spec.Namespaced, State: outcome.state}
		if outcome.err != nil && outcome.state == DynamicCapabilityUnavailable {
			item.Error = sanitizer.SanitizeText(outcome.err.Error())
		}
		capability.Resources = append(capability.Resources, item)
	}
	capability.State = aggregateDynamicCapability(capability.Resources)
	return capability
}

type dynamicObservationKey struct{}
type dynamicObservation struct{ unavailable string }

func markDynamicUnobserved(ctx context.Context, state DynamicCapabilityState) {
	if observation, ok := ctx.Value(dynamicObservationKey{}).(*dynamicObservation); ok {
		observation.unavailable = string(state)
	}
}

func (a *dynamicAnalyzer) Analyze(ctx context.Context, namespace string) ([]*Issue, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.owner != nil && !a.owner.IsFamilyEnabled(a.info.Family) {
		return nil, nil
	}
	if plan, ok := scanplan.FromContext(ctx); ok && !plan.IncludesAnalyzer(a.info.Name) {
		return nil, nil
	}
	client := a.getClient()
	if client == nil {
		markDynamicUnobserved(ctx, DynamicCapabilityUnavailable)
		return nil, nil
	}
	namespace = dynamicNamespace(ctx, false, namespace)
	options := listOptionsForScan(ctx)
	var issues []*Issue
	var operationalErrors []error
	available := false
	for _, spec := range a.resources {
		outcome := listDynamicResource(ctx, client, spec, dynamicNamespace(ctx, spec.Namespaced, namespace), options)
		if outcome.state != DynamicCapabilityAvailable {
			markDynamicUnobserved(ctx, outcome.state)
		}
		switch outcome.state {
		case DynamicCapabilityAvailable:
			available = true
			for index := range outcome.list.Items {
				object := &outcome.list.Items[index]
				if !dynamicObjectSelected(ctx, spec.Kind, object) {
					continue
				}
				if a.analyzeResource != nil {
					issues = append(issues, a.analyzeResource(dynamicClientContext(ctx, client), spec, object)...)
				}
			}
		case DynamicCapabilityUnavailable:
			if outcome.err != nil {
				operationalErrors = append(operationalErrors, outcome.err)
			}
		}
	}
	issues = deduplicateDynamicIssues(issues)
	if !available && len(operationalErrors) > 0 {
		return issues, errors.Join(operationalErrors...)
	}
	return issues, nil
}

type dynamicListOutcome struct {
	list  *unstructured.UnstructuredList
	state DynamicCapabilityState
	err   error
}

func listDynamicResource(ctx context.Context, client dynamic.Interface, spec dynamicResourceSpec, namespace string, options metav1.ListOptions) (outcome dynamicListOutcome) {
	defer func() {
		if outcome.state != DynamicCapabilityAvailable {
			markDynamicUnobserved(ctx, outcome.state)
		} else if outcome.list != nil && outcome.list.GetContinue() != "" {
			markDynamicUnobserved(ctx, DynamicCapabilityUnavailable)
		}
	}()
	if client == nil {
		return dynamicListOutcome{state: DynamicCapabilityAbsent}
	}
	if err := ctx.Err(); err != nil {
		return dynamicListOutcome{state: DynamicCapabilityUnavailable, err: err}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			message := fmt.Sprint(recovered)
			if strings.Contains(message, "must register resource to list kind") {
				outcome = dynamicListOutcome{state: DynamicCapabilityAbsent}
				return
			}
			outcome = dynamicListOutcome{state: DynamicCapabilityUnavailable, err: fmt.Errorf("list %s: %s", spec.GVR.Resource, sanitizer.SanitizeText(message))}
		}
	}()
	resource := client.Resource(spec.GVR)
	var list *unstructured.UnstructuredList
	var err error
	if spec.Namespaced && namespace != "" {
		list, err = resource.Namespace(namespace).List(ctx, options)
	} else {
		list, err = resource.List(ctx, options)
	}
	if err != nil {
		switch {
		case apierrors.IsNotFound(err):
			return dynamicListOutcome{state: DynamicCapabilityAbsent}
		case apierrors.IsForbidden(err):
			return dynamicListOutcome{state: DynamicCapabilityForbidden}
		case apierrors.IsMethodNotSupported(err), apierrors.IsNotAcceptable(err):
			return dynamicListOutcome{state: DynamicCapabilityUnsupported}
		default:
			return dynamicListOutcome{state: DynamicCapabilityUnavailable, err: err}
		}
	}
	if list == nil {
		list = &unstructured.UnstructuredList{}
	}
	return dynamicListOutcome{list: list, state: DynamicCapabilityAvailable}
}

type dynamicGetOutcome struct {
	object *unstructured.Unstructured
	state  DynamicCapabilityState
	err    error
}

func getDynamicResource(ctx context.Context, client dynamic.Interface, spec dynamicResourceSpec, namespace, name string) (outcome dynamicGetOutcome) {
	defer func() {
		// NotFound is a successful observation of a missing dependency. Other
		// inaccessible dependency states leave prior findings unresolved.
		if outcome.state != DynamicCapabilityAvailable && outcome.state != DynamicCapabilityAbsent {
			markDynamicUnobserved(ctx, outcome.state)
		}
		if client == nil {
			markDynamicUnobserved(ctx, DynamicCapabilityUnavailable)
		}
	}()
	if client == nil {
		return dynamicGetOutcome{state: DynamicCapabilityAbsent}
	}
	if err := ctx.Err(); err != nil {
		return dynamicGetOutcome{state: DynamicCapabilityUnavailable, err: err}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			outcome = dynamicGetOutcome{state: DynamicCapabilityUnavailable, err: fmt.Errorf("get %s: %s", spec.GVR.Resource, sanitizer.SanitizeText(fmt.Sprint(recovered)))}
		}
	}()
	resource := client.Resource(spec.GVR)
	var object *unstructured.Unstructured
	var err error
	if spec.Namespaced && namespace != "" {
		object, err = resource.Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	} else {
		object, err = resource.Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		switch {
		case apierrors.IsNotFound(err):
			return dynamicGetOutcome{state: DynamicCapabilityAbsent}
		case apierrors.IsForbidden(err):
			return dynamicGetOutcome{state: DynamicCapabilityForbidden}
		case apierrors.IsMethodNotSupported(err), apierrors.IsNotAcceptable(err):
			return dynamicGetOutcome{state: DynamicCapabilityUnsupported}
		default:
			return dynamicGetOutcome{state: DynamicCapabilityUnavailable, err: err}
		}
	}
	return dynamicGetOutcome{object: object, state: DynamicCapabilityAvailable}
}

func aggregateDynamicCapability(resources []DynamicResourceCapability) DynamicCapabilityState {
	if len(resources) == 0 {
		return DynamicCapabilityAbsent
	}
	for _, resource := range resources {
		if resource.State == DynamicCapabilityAvailable {
			return DynamicCapabilityAvailable
		}
	}
	for _, resource := range resources {
		if resource.State == DynamicCapabilityForbidden {
			return DynamicCapabilityForbidden
		}
	}
	for _, resource := range resources {
		if resource.State == DynamicCapabilityUnsupported {
			return DynamicCapabilityUnsupported
		}
	}
	for _, resource := range resources {
		if resource.State == DynamicCapabilityUnavailable {
			return DynamicCapabilityUnavailable
		}
	}
	return DynamicCapabilityAbsent
}

// DynamicAnalyzerSet owns the optional analyzers and their dynamic client. It
// is independent from ClusterScanner so existing fake typed-client scans do
// not need a dynamic scheme or any CRD registrations.
type DynamicAnalyzerSet struct {
	mu              sync.RWMutex
	client          dynamic.Interface
	analyzers       []*dynamicAnalyzer
	metrics         MetricsObserver
	enabledFamilies map[string]bool
}

// NewDynamicAnalyzerSet creates the Gateway API, OLM, and integration CRD
// analyzers. Passing nil is valid and represents an unavailable optional API.
func NewDynamicAnalyzerSet(client dynamic.Interface) *DynamicAnalyzerSet {
	set := &DynamicAnalyzerSet{client: client, enabledFamilies: map[string]bool{"gateway-api": true, "olm": true}}
	for _, definition := range dynamicAnalyzerDefinitions() {
		analyzer := &dynamicAnalyzer{
			client:          client,
			owner:           set,
			info:            definition.info,
			resources:       append([]dynamicResourceSpec(nil), definition.resources...),
			analyzeResource: definition.analyzeResource,
		}
		set.analyzers = append(set.analyzers, analyzer)
	}
	return set
}

// EnableFamily explicitly activates an optional integration family. The
// catalog remains discoverable while analyzers in the integration family are
// inert until this method is called.
func (s *DynamicAnalyzerSet) EnableFamily(family string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.enabledFamilies == nil {
		s.enabledFamilies = make(map[string]bool)
	}
	s.enabledFamilies[strings.ToLower(strings.TrimSpace(family))] = true
	s.mu.Unlock()
}

// DisableFamily prevents all analyzers in a family from querying or
// analyzing resources. Repeated calls are safe.
func (s *DynamicAnalyzerSet) DisableFamily(family string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.enabledFamilies, strings.ToLower(strings.TrimSpace(family)))
	s.mu.Unlock()
}

func (s *DynamicAnalyzerSet) IsFamilyEnabled(family string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	enabled := s.enabledFamilies[strings.ToLower(strings.TrimSpace(family))]
	s.mu.RUnlock()
	return enabled
}

func (s *DynamicAnalyzerSet) EnabledFamilies() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	result := make([]string, 0, len(s.enabledFamilies))
	for family, enabled := range s.enabledFamilies {
		if enabled {
			result = append(result, family)
		}
	}
	s.mu.RUnlock()
	sort.Strings(result)
	return result
}

// SetDynamicClient replaces the optional client without changing analyzer
// metadata. A nil client disables the optional family while preserving the
// set's stable catalog.
func (s *DynamicAnalyzerSet) SetDynamicClient(client dynamic.Interface) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.client = client
	analyzers := append([]*dynamicAnalyzer(nil), s.analyzers...)
	s.mu.Unlock()
	for _, analyzer := range analyzers {
		analyzer.setClient(client)
	}
}

// SetMetricsObserver attaches the same low-cardinality observer used by the
// typed scanner. Optional analyzers are reported individually; scan totals are
// owned by ClusterScanner so a dynamic scan does not double-count requests.
func (s *DynamicAnalyzerSet) SetMetricsObserver(observer MetricsObserver) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.metrics = observer
	s.mu.Unlock()
}

// DynamicAnalyzers returns the optional analyzers using the common Analyzer
// interface so callers can append them to an existing analyzer catalog.
func (s *DynamicAnalyzerSet) DynamicAnalyzers() []Analyzer {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Analyzer, 0, len(s.analyzers))
	for _, analyzer := range s.analyzers {
		result = append(result, analyzer)
	}
	return result
}

func (s *DynamicAnalyzerSet) Analyzers() []Analyzer {
	return s.DynamicAnalyzers()
}

func (s *DynamicAnalyzerSet) Capabilities(ctx context.Context) []DynamicCapability {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	analyzers := append([]*dynamicAnalyzer(nil), s.analyzers...)
	s.mu.RUnlock()
	result := make([]DynamicCapability, 0, len(analyzers))
	for _, analyzer := range analyzers {
		result = append(result, analyzer.Capability(ctx))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Analyzer < result[j].Analyzer })
	return result
}

func (s *DynamicAnalyzerSet) Analyze(ctx context.Context, namespace string) ([]*Issue, error) {
	issues, _, err := s.analyzeWithPlan(ctx, namespace, nil)
	return issues, err
}

func (s *DynamicAnalyzerSet) analyzeWithPlan(ctx context.Context, namespace string, plan *scanplan.Plan) ([]*Issue, []AnalyzerRun, error) {
	if s == nil {
		return nil, nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if plan != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, planTimeout(plan.EffectiveScope().Timeout))
		defer cancel()
		ctx = scanplan.WithContext(ctx, *plan)
	}
	s.mu.RLock()
	analyzers := append([]*dynamicAnalyzer(nil), s.analyzers...)
	enabledFamilies := make(map[string]bool, len(s.enabledFamilies))
	for family, enabled := range s.enabledFamilies {
		enabledFamilies[family] = enabled
	}
	s.mu.RUnlock()
	var issues []*Issue
	runs := make([]AnalyzerRun, 0, len(analyzers))
	var operationalErrors []error
	for _, analyzer := range analyzers {
		if !enabledFamilies[strings.ToLower(strings.TrimSpace(analyzer.info.Family))] {
			continue
		}
		if plan != nil && !plan.IncludesAnalyzer(analyzer.info.Name) {
			continue
		}
		begin := time.Now().UTC()
		observation := &dynamicObservation{}
		analyzerIssues, err := analyzer.Analyze(context.WithValue(ctx, dynamicObservationKey{}, observation), namespace)
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		analyzerDuration := time.Since(begin)
		s.mu.RLock()
		observer := s.metrics
		s.mu.RUnlock()
		if observer != nil {
			observer.ObserveAnalyzer(analyzer.info.Name, err, analyzerDuration)
		}
		info := analyzer.Info()
		filteredCount := 0
		for _, rawIssue := range analyzerIssues {
			issue := cloneIssue(rawIssue)
			if issue == nil || !dynamicObjectIssueSelected(ctx, issue) {
				continue
			}
			issue.AnalyzerNames = appendUniqueField(issue.AnalyzerNames, info.Name)
			normalizeIssue(issue, info.DocsURL)
			filteredCount++
			issues = append(issues, issue)
		}
		run := AnalyzerRun{
			Info:       info,
			IssueCount: filteredCount,
			Duration:   time.Since(begin).String(),
			StartedAt:  begin,
			FinishedAt: time.Now().UTC(),
		}
		if observation.unavailable != "" {
			run.Error = "coverage unavailable: " + observation.unavailable
		}
		if err != nil {
			run.Error = classifyAnalyzerError(err)
			operationalErrors = append(operationalErrors, err)
		}
		runs = append(runs, run)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].Info.Name < runs[j].Info.Name })
	issues = deduplicateDynamicIssues(issues)
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].ID != issues[j].ID {
			return issues[i].ID < issues[j].ID
		}
		return issues[i].Name < issues[j].Name
	})
	if err := ctx.Err(); err != nil {
		return issues, runs, err
	}
	if len(operationalErrors) > 0 {
		return issues, runs, errors.Join(operationalErrors...)
	}
	return issues, runs, nil
}

type dynamicAnalyzerDefinition struct {
	info            DynamicAnalyzerInfo
	resources       []dynamicResourceSpec
	analyzeResource func(context.Context, dynamicResourceSpec, *unstructured.Unstructured) []*Issue
}

func dynamicAnalyzerDefinitions() []dynamicAnalyzerDefinition {
	return []dynamicAnalyzerDefinition{
		{
			info:            dynamicInfo("GatewayClassAnalyzer", "GatewayClass", "Optional Gateway API GatewayClass acceptance and controller configuration checks", "https://gateway-api.sigs.k8s.io/", "gateway-api", "cluster", []dynamicResourceSpec{{GVR: gatewayClassGVR, Kind: "GatewayClass"}, {GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "gatewayclasses"}, Kind: "GatewayClass"}}),
			resources:       []dynamicResourceSpec{{GVR: gatewayClassGVR, Kind: "GatewayClass"}, {GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "gatewayclasses"}, Kind: "GatewayClass"}},
			analyzeResource: analyzeGatewayClass,
		},
		{
			info:            dynamicInfo("GatewayAnalyzer", "Gateway", "Optional Gateway API listener, acceptance, and programming checks", "https://gateway-api.sigs.k8s.io/guides/gateway/", "gateway-api", "namespaced", []dynamicResourceSpec{{GVR: gatewayGVR, Kind: "Gateway"}, {GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "gateways"}, Kind: "Gateway"}}),
			resources:       []dynamicResourceSpec{{GVR: gatewayGVR, Kind: "Gateway", Namespaced: true}, {GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "gateways"}, Kind: "Gateway", Namespaced: true}},
			analyzeResource: analyzeGateway,
		},
		{
			info:      dynamicInfo("HTTPRouteAnalyzer", "HTTPRoute", "Optional Gateway API parent, backend, and reference-resolution checks", "https://gateway-api.sigs.k8s.io/guides/http-routing/", "gateway-api", "namespaced", []dynamicResourceSpec{{GVR: httpRouteGVR, Kind: "HTTPRoute"}, {GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "httproutes"}, Kind: "HTTPRoute"}}),
			resources: []dynamicResourceSpec{{GVR: httpRouteGVR, Kind: "HTTPRoute", Namespaced: true}, {GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "httproutes"}, Kind: "HTTPRoute", Namespaced: true}},
			analyzeResource: func(ctx context.Context, spec dynamicResourceSpec, object *unstructured.Unstructured) []*Issue {
				return analyzeHTTPRoute(ctx, spec, object)
			},
		},
		{
			info:            dynamicInfo("ReferenceGrantAnalyzer", "ReferenceGrant", "Optional Gateway API cross-namespace ReferenceGrant shape checks", "https://gateway-api.sigs.k8s.io/api-types/referencegrant/", "gateway-api", "namespaced", []dynamicResourceSpec{{GVR: referenceGrantGVR, Kind: "ReferenceGrant"}}),
			resources:       []dynamicResourceSpec{{GVR: referenceGrantGVR, Kind: "ReferenceGrant", Namespaced: true}},
			analyzeResource: analyzeReferenceGrant,
		},
		{
			info:            dynamicInfo("ClusterCatalogAnalyzer", "ClusterCatalog", "Optional OLM ClusterCatalog condition and phase checks", "https://olm.operatorframework.io/docs/concepts/catalog/", "olm", "cluster", []dynamicResourceSpec{{GVR: clusterCatalogGVR, Kind: "ClusterCatalog"}, {GVR: schema.GroupVersionResource{Group: "olm.operatorframework.io", Version: "v1alpha1", Resource: "clustercatalogs"}, Kind: "ClusterCatalog"}}),
			resources:       []dynamicResourceSpec{{GVR: clusterCatalogGVR, Kind: "ClusterCatalog"}, {GVR: schema.GroupVersionResource{Group: "olm.operatorframework.io", Version: "v1alpha1", Resource: "clustercatalogs"}, Kind: "ClusterCatalog"}},
			analyzeResource: analyzeOLMResource,
		},
		{
			info:            dynamicInfo("ClusterExtensionAnalyzer", "ClusterExtension", "Optional OLM ClusterExtension condition and phase checks", "https://olm.operatorframework.io/docs/concepts/crds/clusterextension/", "olm", "cluster", []dynamicResourceSpec{{GVR: clusterExtensionGVR, Kind: "ClusterExtension"}, {GVR: schema.GroupVersionResource{Group: "olm.operatorframework.io", Version: "v1alpha1", Resource: "clusterextensions"}, Kind: "ClusterExtension"}}),
			resources:       []dynamicResourceSpec{{GVR: clusterExtensionGVR, Kind: "ClusterExtension"}, {GVR: schema.GroupVersionResource{Group: "olm.operatorframework.io", Version: "v1alpha1", Resource: "clusterextensions"}, Kind: "ClusterExtension"}},
			analyzeResource: analyzeOLMResource,
		},
		{
			info:            dynamicInfo("ClusterServiceVersionAnalyzer", "ClusterServiceVersion", "Optional OLM CSV phase and condition checks", "https://olm.operatorframework.io/docs/concepts/crds/clusterserviceversion/", "olm", "namespaced", []dynamicResourceSpec{{GVR: clusterServiceVersionGVR, Kind: "ClusterServiceVersion", Namespaced: true}}),
			resources:       []dynamicResourceSpec{{GVR: clusterServiceVersionGVR, Kind: "ClusterServiceVersion", Namespaced: true}},
			analyzeResource: analyzeOLMResource,
		},
		{
			info:            dynamicInfo("SubscriptionAnalyzer", "Subscription", "Optional OLM Subscription state and condition checks", "https://olm.operatorframework.io/docs/concepts/crds/subscription/", "olm", "namespaced", []dynamicResourceSpec{{GVR: subscriptionGVR, Kind: "Subscription", Namespaced: true}}),
			resources:       []dynamicResourceSpec{{GVR: subscriptionGVR, Kind: "Subscription", Namespaced: true}},
			analyzeResource: analyzeOLMResource,
		},
		{
			info:            dynamicInfo("InstallPlanAnalyzer", "InstallPlan", "Optional OLM InstallPlan phase and condition checks", "https://olm.operatorframework.io/docs/concepts/crds/installplan/", "olm", "namespaced", []dynamicResourceSpec{{GVR: installPlanGVR, Kind: "InstallPlan", Namespaced: true}}),
			resources:       []dynamicResourceSpec{{GVR: installPlanGVR, Kind: "InstallPlan", Namespaced: true}},
			analyzeResource: analyzeOLMResource,
		},
		{
			info:            dynamicInfo("CatalogSourceAnalyzer", "CatalogSource", "Optional OLM CatalogSource connection and condition checks", "https://olm.operatorframework.io/docs/concepts/crds/catalogsource/", "olm", "namespaced", []dynamicResourceSpec{{GVR: catalogSourceGVR, Kind: "CatalogSource", Namespaced: true}}),
			resources:       []dynamicResourceSpec{{GVR: catalogSourceGVR, Kind: "CatalogSource", Namespaced: true}},
			analyzeResource: analyzeOLMResource,
		},
		{
			info:            dynamicInfo("OperatorGroupAnalyzer", "OperatorGroup", "Optional OLM OperatorGroup condition and namespace checks", "https://olm.operatorframework.io/docs/concepts/crds/operatorgroup/", "olm", "namespaced", []dynamicResourceSpec{{GVR: operatorGroupGVR, Kind: "OperatorGroup", Namespaced: true}}),
			resources:       []dynamicResourceSpec{{GVR: operatorGroupGVR, Kind: "OperatorGroup", Namespaced: true}},
			analyzeResource: analyzeOLMResource,
		},
		{
			info:            dynamicInfo("KEDAAnalyzer", "KEDA", "Optional KEDA ScaledObject, ScaledJob, and authentication condition checks", "https://keda.sh/docs/", "integration", "mixed", []dynamicResourceSpec{{GVR: kedaScaledObjectGVR, Kind: "ScaledObject", Namespaced: true}, {GVR: kedaScaledJobGVR, Kind: "ScaledJob", Namespaced: true}, {GVR: kedaTriggerAuthenticationGVR, Kind: "TriggerAuthentication", Namespaced: true}, {GVR: kedaClusterTriggerAuthGVR, Kind: "ClusterTriggerAuthentication"}}),
			resources:       []dynamicResourceSpec{{GVR: kedaScaledObjectGVR, Kind: "ScaledObject", Namespaced: true}, {GVR: kedaScaledJobGVR, Kind: "ScaledJob", Namespaced: true}, {GVR: kedaTriggerAuthenticationGVR, Kind: "TriggerAuthentication", Namespaced: true}, {GVR: kedaClusterTriggerAuthGVR, Kind: "ClusterTriggerAuthentication"}},
			analyzeResource: analyzeIntegrationResource,
		},
		{
			info:            dynamicInfo("KyvernoAnalyzer", "Kyverno", "Optional Kyverno policy and policy-report failure checks", "https://kyverno.io/docs/", "integration", "mixed", []dynamicResourceSpec{{GVR: kyvernoPolicyGVR, Kind: "Policy", Namespaced: true}, {GVR: kyvernoClusterPolicyGVR, Kind: "ClusterPolicy"}, {GVR: kyvernoPolicyReportGVR, Kind: "PolicyReport", Namespaced: true}, {GVR: kyvernoClusterPolicyReportGVR, Kind: "ClusterPolicyReport"}}),
			resources:       []dynamicResourceSpec{{GVR: kyvernoPolicyGVR, Kind: "Policy", Namespaced: true}, {GVR: kyvernoClusterPolicyGVR, Kind: "ClusterPolicy"}, {GVR: kyvernoPolicyReportGVR, Kind: "PolicyReport", Namespaced: true}, {GVR: kyvernoClusterPolicyReportGVR, Kind: "ClusterPolicyReport"}},
			analyzeResource: analyzeIntegrationResource,
		},
		{
			info:            dynamicInfo("PrometheusOperatorAnalyzer", "PrometheusOperator", "Optional Prometheus Operator condition and paused-state checks", "https://prometheus-operator.dev/docs/", "integration", "namespaced", []dynamicResourceSpec{{GVR: prometheusGVR, Kind: "Prometheus", Namespaced: true}, {GVR: serviceMonitorGVR, Kind: "ServiceMonitor", Namespaced: true}, {GVR: podMonitorGVR, Kind: "PodMonitor", Namespaced: true}, {GVR: prometheusRuleGVR, Kind: "PrometheusRule", Namespaced: true}, {GVR: alertmanagerGVR, Kind: "Alertmanager", Namespaced: true}}),
			resources:       []dynamicResourceSpec{{GVR: prometheusGVR, Kind: "Prometheus", Namespaced: true}, {GVR: serviceMonitorGVR, Kind: "ServiceMonitor", Namespaced: true}, {GVR: podMonitorGVR, Kind: "PodMonitor", Namespaced: true}, {GVR: prometheusRuleGVR, Kind: "PrometheusRule", Namespaced: true}, {GVR: alertmanagerGVR, Kind: "Alertmanager", Namespaced: true}},
			analyzeResource: analyzeIntegrationResource,
		},
	}
}

func dynamicInfo(name, resource, description, docsURL, family, scope string, resources []dynamicResourceSpec) DynamicAnalyzerInfo {
	gvrList := make([]schema.GroupVersionResource, 0, len(resources))
	for _, resource := range resources {
		gvrList = append(gvrList, resource.GVR)
	}
	return DynamicAnalyzerInfo{
		AnalyzerInfo: AnalyzerInfo{Name: name, Resource: resource, Description: description, DocsURL: docsURL},
		Family:       family,
		Optional:     true,
		Scope:        scope,
		Resources:    gvrList,
	}
}

func analyzeGatewayClass(_ context.Context, spec dynamicResourceSpec, object *unstructured.Unstructured) []*Issue {
	var issues []*Issue
	if stringValue(object, "spec", "controllerName") == "" {
		issues = append(issues, dynamicIssue(object, spec.Kind, CategoryGatewaySpecInvalid, SeverityHigh, "ControllerMissing", "GatewayClass has no controllerName", "A GatewayClass without a controllerName cannot be claimed by a Gateway controller."))
	}
	issues = append(issues, conditionIssues(object, spec.Kind, "Accepted", CategoryGatewayClassNotAccepted, SeverityHigh)...)
	return issues
}

func analyzeGateway(_ context.Context, spec dynamicResourceSpec, object *unstructured.Unstructured) []*Issue {
	var issues []*Issue
	if stringValue(object, "spec", "gatewayClassName") == "" {
		issues = append(issues, dynamicIssue(object, spec.Kind, CategoryGatewaySpecInvalid, SeverityHigh, "GatewayClassMissing", "Gateway has no gatewayClassName", "Set spec.gatewayClassName so a GatewayClass controller can reconcile this Gateway."))
	}
	issues = append(issues, conditionIssues(object, spec.Kind, "Accepted", CategoryGatewayNotAccepted, SeverityHigh)...)
	issues = append(issues, conditionIssues(object, spec.Kind, "Programmed", CategoryGatewayNotProgrammed, SeverityHigh)...)

	listeners, found, err := unstructured.NestedSlice(object.Object, "spec", "listeners")
	if err != nil {
		return append(issues, dynamicIssue(object, spec.Kind, CategoryDynamicMalformed, SeverityMedium, "ListenersMalformed", "Gateway listeners could not be parsed", "The optional listeners field has an unexpected shape; inspect the Gateway against the installed Gateway API version."))
	}
	if !found {
		return issues
	}
	for index, rawListener := range listeners {
		listener, ok := rawListener.(map[string]interface{})
		if !ok {
			issues = append(issues, dynamicIssue(object, spec.Kind, CategoryGatewayListenerInvalid, SeverityHigh, fmt.Sprintf("Listener-%d", index), "Gateway listener is malformed", "Each Gateway listener must be an object with a protocol and a TCP port."))
			continue
		}
		port, hasPort := integerValue(listener["port"])
		protocol := strings.ToUpper(stringValueFromMap(listener, "protocol"))
		validProtocol := protocol == "HTTP" || protocol == "HTTPS" || protocol == "TLS" || protocol == "TCP" || protocol == "UDP"
		if !hasPort || port < 1 || port > 65535 || !validProtocol {
			listenerName := stringValueFromMap(listener, "name")
			if listenerName == "" {
				listenerName = strconv.Itoa(index)
			}
			issues = append(issues, dynamicIssue(object, spec.Kind, CategoryGatewayListenerInvalid, SeverityHigh, "Listener-"+listenerName, "Gateway listener has an invalid port or protocol", "Gateway listener ports must be between 1 and 65535 and protocols must be HTTP, HTTPS, TLS, TCP, or UDP."))
		}
	}
	return issues
}

func analyzeHTTPRoute(ctx context.Context, spec dynamicResourceSpec, object *unstructured.Unstructured) []*Issue {
	var issues []*Issue
	parents, found, err := unstructured.NestedSlice(object.Object, "spec", "parentRefs")
	if err != nil {
		issues = append(issues, dynamicIssue(object, spec.Kind, CategoryDynamicMalformed, SeverityMedium, "ParentRefsMalformed", "HTTPRoute parentRefs could not be parsed", "The optional parentRefs field has an unexpected shape."))
	} else if !found || len(parents) == 0 {
		issues = append(issues, dynamicIssue(object, spec.Kind, CategoryHTTPRouteNoParent, SeverityHigh, "NoParent", "HTTPRoute has no parentRefs", "An HTTPRoute without a parent Gateway cannot receive traffic."))
	} else {
		issues = append(issues, analyzeHTTPRouteParentRefs(ctx, spec, object, parents)...)
	}

	statusParents, statusFound, statusErr := unstructured.NestedSlice(object.Object, "status", "parents")
	if statusErr == nil && statusFound {
		for index, rawParent := range statusParents {
			parent, ok := rawParent.(map[string]interface{})
			if !ok {
				continue
			}
			for _, condition := range conditionMaps(parent, "conditions") {
				typeName := stringValueFromMap(condition, "type")
				switch {
				case typeName == "Accepted" && conditionIsFalse(condition):
					issues = append(issues, dynamicIssue(object, spec.Kind, CategoryHTTPRouteParentNotAccepted, SeverityHigh, fmt.Sprintf("Parent-%d-Accepted", index), "HTTPRoute parent did not accept the route", conditionDetails(condition, "The parent Gateway did not accept this HTTPRoute.")))
				case typeName == "ResolvedRefs" && conditionIsFalse(condition):
					issues = append(issues, dynamicIssue(object, spec.Kind, CategoryHTTPRouteRefsNotResolved, SeverityHigh, fmt.Sprintf("Parent-%d-ResolvedRefs", index), "HTTPRoute references could not be resolved", conditionDetails(condition, "One or more HTTPRoute references could not be resolved.")))
				}
			}
		}
	}

	rules, rulesFound, rulesErr := unstructured.NestedSlice(object.Object, "spec", "rules")
	if rulesErr != nil {
		return append(issues, dynamicIssue(object, spec.Kind, CategoryDynamicMalformed, SeverityMedium, "RulesMalformed", "HTTPRoute rules could not be parsed", "The optional rules field has an unexpected shape."))
	}
	if !rulesFound {
		return issues
	}
	for ruleIndex, rawRule := range rules {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}
		backends, found, err := nestedSliceFromMap(rule, "backendRefs")
		if err != nil || !found {
			continue
		}
		for backendIndex, rawBackend := range backends {
			backend, ok := rawBackend.(map[string]interface{})
			if !ok {
				issues = append(issues, dynamicIssue(object, spec.Kind, CategoryHTTPRouteBackendInvalid, SeverityHigh, fmt.Sprintf("Backend-%d-%d", ruleIndex, backendIndex), "HTTPRoute backendRef is malformed", "Each backendRef must identify a Service and an optional port."))
				continue
			}
			issues = append(issues, analyzeHTTPRouteBackend(ctx, spec, object, backend, ruleIndex, backendIndex)...)
		}
	}
	return issues
}

func analyzeHTTPRouteParentRefs(ctx context.Context, spec dynamicResourceSpec, route *unstructured.Unstructured, parents []interface{}) []*Issue {
	client := dynamicClientFromContext(ctx)
	if client == nil || route == nil {
		return nil
	}
	issues := make([]*Issue, 0)
	for index, rawParent := range parents {
		parent, ok := rawParent.(map[string]interface{})
		if !ok {
			issues = append(issues, dynamicIssue(route, spec.Kind, CategoryHTTPRouteRefsNotResolved, SeverityHigh, fmt.Sprintf("Parent-%d-Malformed", index), "HTTPRoute parentRef is malformed", "Each parentRef must identify a Gateway by name."))
			continue
		}
		name := strings.TrimSpace(stringValueFromMap(parent, "name"))
		if name == "" {
			issues = append(issues, dynamicIssue(route, spec.Kind, CategoryHTTPRouteRefsNotResolved, SeverityHigh, fmt.Sprintf("Parent-%d-Name", index), "HTTPRoute parentRef has no name", "A parentRef must identify a Gateway by name."))
			continue
		}
		group := strings.TrimSpace(stringValueFromMap(parent, "group"))
		if group == "" {
			group = "gateway.networking.k8s.io"
		}
		kind := strings.TrimSpace(stringValueFromMap(parent, "kind"))
		if kind == "" {
			kind = "Gateway"
		}
		if group != "gateway.networking.k8s.io" || !strings.EqualFold(kind, "Gateway") {
			issues = append(issues, dynamicIssue(route, spec.Kind, CategoryHTTPRouteRefsNotResolved, SeverityHigh, fmt.Sprintf("Parent-%d-Target", index), "HTTPRoute parentRef uses an unsupported target", "HTTPRoute parentRefs must target a Gateway in the Gateway API group."))
			continue
		}
		namespace := strings.TrimSpace(stringValueFromMap(parent, "namespace"))
		if namespace == "" {
			namespace = route.GetNamespace()
		}
		gatewaySpec := dynamicResourceSpec{GVR: gatewayGVR, Kind: "Gateway", Namespaced: true}
		gateway := getDynamicResource(ctx, client, gatewaySpec, namespace, name)
		if gateway.state == DynamicCapabilityAbsent {
			issues = append(issues, dynamicIssue(route, spec.Kind, CategoryHTTPRouteRefsNotResolved, SeverityHigh, fmt.Sprintf("Parent-%d-Missing", index), "HTTPRoute parent Gateway was not found", fmt.Sprintf("Gateway %q was not found in namespace %q.", name, namespace)))
			continue
		}
		if gateway.state != DynamicCapabilityAvailable || gateway.object == nil {
			continue
		}
		sectionName := strings.TrimSpace(stringValueFromMap(parent, "sectionName"))
		if !gatewayAcceptsHTTPRoute(gateway.object, route.GetNamespace(), sectionName) {
			suffix := fmt.Sprintf("Parent-%d-Listener", index)
			if sectionName != "" {
				suffix += "-" + sectionName
			}
			issues = append(issues, dynamicIssue(route, spec.Kind, CategoryHTTPRouteParentNotAccepted, SeverityHigh, suffix, "HTTPRoute parent has no compatible listener", "The referenced Gateway has no HTTP or HTTPS listener that accepts this route and sectionName."))
		}
	}
	return issues
}

func gatewayAcceptsHTTPRoute(gateway *unstructured.Unstructured, routeNamespace, sectionName string) bool {
	if gateway == nil {
		return false
	}
	listeners, found, err := unstructured.NestedSlice(gateway.Object, "spec", "listeners")
	if err != nil || !found {
		return false
	}
	for _, rawListener := range listeners {
		listener, ok := rawListener.(map[string]interface{})
		if !ok {
			continue
		}
		if sectionName != "" && stringValueFromMap(listener, "name") != sectionName {
			continue
		}
		protocol := strings.ToUpper(strings.TrimSpace(stringValueFromMap(listener, "protocol")))
		if protocol != "HTTP" && protocol != "HTTPS" {
			continue
		}
		if gatewayListenerAllowsHTTPRoute(listener, gateway.GetNamespace(), routeNamespace) {
			return true
		}
	}
	return false
}

func gatewayListenerAllowsHTTPRoute(listener map[string]interface{}, gatewayNamespace, routeNamespace string) bool {
	allowedRoutes, found, err := nestedMapFromMap(listener, "allowedRoutes")
	if err != nil || !found {
		return gatewayNamespace == routeNamespace
	}
	kinds, found, err := nestedSliceFromMap(allowedRoutes, "kinds")
	if err != nil {
		return false
	}
	if found && len(kinds) > 0 {
		allowedKind := false
		for _, rawKind := range kinds {
			kind, ok := rawKind.(map[string]interface{})
			if !ok || !strings.EqualFold(stringValueFromMap(kind, "kind"), "HTTPRoute") {
				continue
			}
			group := strings.TrimSpace(stringValueFromMap(kind, "group"))
			if group == "" || group == "gateway.networking.k8s.io" {
				allowedKind = true
				break
			}
		}
		if !allowedKind {
			return false
		}
	}
	namespaces, found, err := nestedMapFromMap(allowedRoutes, "namespaces")
	if err != nil || !found {
		return gatewayNamespace == routeNamespace
	}
	from := strings.TrimSpace(stringValueFromMap(namespaces, "from"))
	switch from {
	case "All":
		return true
	case "Selector":
		// Namespace label resolution is intentionally deferred until the
		// scanner has a namespace informer; do not claim acceptance here.
		return false
	default:
		return gatewayNamespace == routeNamespace
	}
}

func nestedMapFromMap(object map[string]interface{}, field string) (map[string]interface{}, bool, error) {
	value, found := object[field]
	if !found {
		return nil, false, nil
	}
	result, ok := value.(map[string]interface{})
	if !ok {
		return nil, true, fmt.Errorf("%s is not an object", field)
	}
	return result, true, nil
}

func analyzeHTTPRouteBackend(ctx context.Context, spec dynamicResourceSpec, route *unstructured.Unstructured, backend map[string]interface{}, ruleIndex, backendIndex int) []*Issue {
	name := stringValueFromMap(backend, "name")
	if name == "" {
		return []*Issue{dynamicIssue(route, spec.Kind, CategoryHTTPRouteBackendInvalid, SeverityHigh, fmt.Sprintf("Backend-%d-%d-Name", ruleIndex, backendIndex), "HTTPRoute backendRef has no name", "A backendRef must identify a Service by name.")}
	}
	group := stringValueFromMap(backend, "group")
	kind := stringValueFromMap(backend, "kind")
	if kind == "" {
		kind = "Service"
	}
	if (group != "" && group != "core") || !strings.EqualFold(kind, "Service") {
		return []*Issue{dynamicIssue(route, spec.Kind, CategoryHTTPRouteBackendInvalid, SeverityHigh, fmt.Sprintf("Backend-%d-%d-Kind", ruleIndex, backendIndex), "HTTPRoute backendRef uses an unsupported target", "This scanner validates core Service backends; verify custom backend references with their controller.")}
	}
	namespace := stringValueFromMap(backend, "namespace")
	if namespace == "" {
		namespace = route.GetNamespace()
	}
	if namespace != route.GetNamespace() && route.GetNamespace() != "" {
		allowed, known := referenceGrantAllows(ctx, namespace, route.GetNamespace(), name)
		if known && !allowed {
			return []*Issue{dynamicIssue(route, spec.Kind, CategoryReferenceGrantMissing, SeverityHigh, fmt.Sprintf("Backend-%d-%d-ReferenceGrant", ruleIndex, backendIndex), "HTTPRoute cross-namespace backend lacks a ReferenceGrant", "A ReferenceGrant in the backend namespace must allow this HTTPRoute namespace and Service reference.")}
		}
	}

	serviceSpec := dynamicResourceSpec{GVR: serviceGVR, Kind: "Service", Namespaced: true}
	client := dynamicClientFromContext(ctx)
	service := getDynamicResource(ctx, client, serviceSpec, namespace, name)
	if service.state == DynamicCapabilityAbsent {
		return []*Issue{dynamicIssue(route, spec.Kind, CategoryHTTPRouteBackendMissing, SeverityHigh, fmt.Sprintf("Backend-%d-%d-Missing", ruleIndex, backendIndex), "HTTPRoute backend Service was not found", fmt.Sprintf("Service %q was not found in namespace %q.", name, namespace))}
	}
	if service.state != DynamicCapabilityAvailable || service.object == nil {
		return nil
	}
	port, hasPort := backendPort(backend)
	if !hasPort {
		return nil
	}
	if !serviceHasPort(service.object, port) {
		return []*Issue{dynamicIssue(route, spec.Kind, CategoryHTTPRouteBackendInvalid, SeverityHigh, fmt.Sprintf("Backend-%d-%d-Port", ruleIndex, backendIndex), "HTTPRoute backend Service port was not found", fmt.Sprintf("Service %q does not expose the port selected by this backendRef.", name))}
	}
	return nil
}

func analyzeReferenceGrant(_ context.Context, spec dynamicResourceSpec, object *unstructured.Unstructured) []*Issue {
	from, fromFound, fromErr := unstructured.NestedSlice(object.Object, "spec", "from")
	to, toFound, toErr := unstructured.NestedSlice(object.Object, "spec", "to")
	if fromErr != nil || toErr != nil || !fromFound || !toFound || len(from) == 0 || len(to) == 0 {
		return []*Issue{dynamicIssue(object, spec.Kind, CategoryReferenceGrantInvalid, SeverityHigh, "SpecInvalid", "ReferenceGrant has incomplete from or to rules", "A ReferenceGrant must contain at least one valid spec.from and spec.to entry.")}
	}
	for index, raw := range from {
		entry, ok := raw.(map[string]interface{})
		if !ok || strings.TrimSpace(stringValueFromMap(entry, "group")) != "gateway.networking.k8s.io" || !strings.EqualFold(stringValueFromMap(entry, "kind"), "HTTPRoute") || strings.TrimSpace(stringValueFromMap(entry, "namespace")) == "" {
			return []*Issue{dynamicIssue(object, spec.Kind, CategoryReferenceGrantInvalid, SeverityHigh, fmt.Sprintf("From-%d", index), "ReferenceGrant has an invalid from rule", "spec.from entries must identify an HTTPRoute from a source namespace in the Gateway API group.")}
		}
	}
	for index, raw := range to {
		entry, ok := raw.(map[string]interface{})
		if !ok || strings.TrimSpace(stringValueFromMap(entry, "kind")) == "" {
			return []*Issue{dynamicIssue(object, spec.Kind, CategoryReferenceGrantInvalid, SeverityHigh, fmt.Sprintf("To-%d", index), "ReferenceGrant has an invalid to rule", "spec.to entries must identify a target kind and may restrict the target name.")}
		}
		group := strings.TrimSpace(stringValueFromMap(entry, "group"))
		kind := strings.TrimSpace(stringValueFromMap(entry, "kind"))
		if group != "" && group != "core" || !strings.EqualFold(kind, "Service") {
			return []*Issue{dynamicIssue(object, spec.Kind, CategoryReferenceGrantInvalid, SeverityHigh, fmt.Sprintf("To-%d", index), "ReferenceGrant targets an unsupported kind", "This scanner validates cross-namespace Service references and requires the core Service kind.")}
		}
	}
	return nil
}

func analyzeOLMResource(_ context.Context, spec dynamicResourceSpec, object *unstructured.Unstructured) []*Issue {
	var issues []*Issue
	phase := strings.ToLower(stringValue(object, "status", "phase"))
	state := strings.ToLower(stringValue(object, "status", "state"))
	connectionState := strings.ToUpper(stringValue(object, "status", "connectionState", "lastObservedState"))
	if phase == "failed" || phase == "unknown" || state == "failed" || strings.Contains(connectionState, "FAILURE") {
		details := stringValue(object, "status", "message")
		if details == "" {
			details = stringValue(object, "status", "reason")
		}
		issues = append(issues, dynamicIssue(object, spec.Kind, CategoryOLMResourceUnhealthy, SeverityHigh, "Status", spec.Kind+" reports an unhealthy status", defaultDetails(details, "The OLM resource reports a failed or unknown status.")))
	}
	for index, condition := range conditionMaps(object.Object, "status", "conditions") {
		if conditionIsFalse(condition) {
			issues = append(issues, dynamicIssue(object, spec.Kind, CategoryOLMResourceUnhealthy, SeverityHigh, fmt.Sprintf("Condition-%d-%s", index, stringValueFromMap(condition, "type")), spec.Kind+" reports a failed condition", conditionDetails(condition, "The OLM resource reports a false status condition.")))
		}
	}
	return issues
}

func analyzeIntegrationResource(_ context.Context, spec dynamicResourceSpec, object *unstructured.Unstructured) []*Issue {
	var issues []*Issue
	for index, condition := range conditionMaps(object.Object, "status", "conditions") {
		if conditionIsFalse(condition) {
			issues = append(issues, dynamicIssue(object, spec.Kind, CategoryIntegrationResourceUnhealthy, SeverityHigh, fmt.Sprintf("Condition-%d-%s", index, stringValueFromMap(condition, "type")), spec.Kind+" reports a failed condition", conditionDetails(condition, "The integration resource reports a false status condition.")))
		}
	}
	phase := strings.ToLower(stringValue(object, "status", "phase"))
	if phase == "failed" || phase == "error" {
		issues = append(issues, dynamicIssue(object, spec.Kind, CategoryIntegrationResourceUnhealthy, SeverityHigh, "Phase", spec.Kind+" reports a failed phase", defaultDetails(stringValue(object, "status", "message"), "The integration resource reports a failed phase.")))
	}
	if ready, found, _ := unstructured.NestedBool(object.Object, "status", "ready"); found && !ready {
		issues = append(issues, dynamicIssue(object, spec.Kind, CategoryIntegrationResourceUnhealthy, SeverityHigh, "Ready", spec.Kind+" is not ready", "The integration resource status.ready field is false."))
	}
	if paused, found, _ := unstructured.NestedBool(object.Object, "spec", "paused"); found && paused {
		issues = append(issues, dynamicIssue(object, spec.Kind, CategoryIntegrationResourceUnhealthy, SeverityMedium, "Paused", spec.Kind+" is paused", "The integration resource is explicitly paused and will not reconcile until resumed."))
	}
	for index, result := range policyReportResults(object) {
		status := strings.ToLower(stringValueFromMap(result, "result"))
		if status == "fail" || status == "error" {
			issues = append(issues, dynamicIssue(object, spec.Kind, CategoryIntegrationResourceUnhealthy, SeverityHigh, fmt.Sprintf("Result-%d", index), spec.Kind+" contains a failing policy result", defaultDetails(stringValueFromMap(result, "message"), "A policy report result is marked failed.")))
		}
	}
	return issues
}

func dynamicIssue(object *unstructured.Unstructured, kind string, category IssueCategory, severity Severity, suffix, summary, details string) *Issue {
	now := time.Now().UTC()
	first := object.GetCreationTimestamp().Time
	if first.IsZero() {
		first = now
	}
	return &Issue{
		ID:                    makeID(object.GetNamespace(), kind, object.GetName(), string(category)+"-"+suffix),
		Namespace:             object.GetNamespace(),
		Kind:                  kind,
		Name:                  object.GetName(),
		TargetUID:             string(object.GetUID()),
		TargetResourceVersion: object.GetResourceVersion(),
		Severity:              severity,
		Category:              category,
		Summary:               sanitizer.SanitizeText(summary),
		Details:               sanitizer.SanitizeText(details),
		FirstObserved:         first,
		LastObserved:          now,
	}
}

func conditionIssues(object *unstructured.Unstructured, kind, wanted string, category IssueCategory, severity Severity) []*Issue {
	var issues []*Issue
	for index, condition := range conditionMaps(object.Object, "status", "conditions") {
		if stringValueFromMap(condition, "type") != wanted || !conditionIsFalse(condition) {
			continue
		}
		suffix := fmt.Sprintf("%s-%d", wanted, index)
		issues = append(issues, dynamicIssue(object, kind, category, severity, suffix, fmt.Sprintf("%s condition is false", wanted), conditionDetails(condition, fmt.Sprintf("The %s condition is false.", wanted))))
	}
	return issues
}

func conditionMaps(object map[string]interface{}, fields ...string) []map[string]interface{} {
	values, found, err := unstructured.NestedSlice(object, fields...)
	if err != nil || !found {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(values))
	for _, value := range values {
		if condition, ok := value.(map[string]interface{}); ok {
			result = append(result, condition)
		}
	}
	return result
}

func conditionIsFalse(condition map[string]interface{}) bool {
	status := condition["status"]
	if boolValue, ok := status.(bool); ok {
		return !boolValue
	}
	return strings.EqualFold(stringValueFromMap(condition, "status"), "false")
}

func conditionDetails(condition map[string]interface{}, fallback string) string {
	message := stringValueFromMap(condition, "message")
	if message != "" {
		return message
	}
	reason := stringValueFromMap(condition, "reason")
	if reason != "" {
		return reason
	}
	return fallback
}

func stringValue(object *unstructured.Unstructured, fields ...string) string {
	if object == nil {
		return ""
	}
	value, found, _ := unstructured.NestedFieldCopy(object.Object, fields...)
	if !found {
		return ""
	}
	return stringValueFromAny(value)
}

func stringValueFromMap(object map[string]interface{}, field string) string {
	return stringValueFromAny(object[field])
}

func stringValueFromAny(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func integerValue(value interface{}) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		return int64(typed), true
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(typed), true
	case float32:
		return int64(typed), float32(int64(typed)) == typed
	case float64:
		return int64(typed), float64(int64(typed)) == typed
	case jsonNumber:
		parsed, err := strconv.ParseInt(string(typed), 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

// jsonNumber is kept local so dynamic analyzers do not need an encoding/json
// dependency just to accept test/fake clients that preserve number tokens.
type jsonNumber string

func backendPort(backend map[string]interface{}) (interface{}, bool) {
	value, found := backend["port"]
	if !found || value == nil {
		return nil, false
	}
	if number, ok := integerValue(value); ok {
		return number, true
	}
	if name, ok := value.(string); ok && name != "" {
		return name, true
	}
	return nil, false
}

func serviceHasPort(service *unstructured.Unstructured, wanted interface{}) bool {
	ports, found, err := unstructured.NestedSlice(service.Object, "spec", "ports")
	if err != nil || !found {
		return false
	}
	for _, rawPort := range ports {
		port, ok := rawPort.(map[string]interface{})
		if !ok {
			continue
		}
		if number, ok := wanted.(int64); ok {
			if servicePort, exists := integerValue(port["port"]); exists && servicePort == number {
				return true
			}
		}
		if name, ok := wanted.(string); ok && stringValueFromMap(port, "name") == name {
			return true
		}
	}
	return false
}

func nestedSliceFromMap(object map[string]interface{}, field string) ([]interface{}, bool, error) {
	value, found := object[field]
	if !found {
		return nil, false, nil
	}
	slice, ok := value.([]interface{})
	if !ok {
		return nil, true, fmt.Errorf("%s is not a list", field)
	}
	return slice, true, nil
}

func policyReportResults(object *unstructured.Unstructured) []map[string]interface{} {
	values, found, err := unstructured.NestedSlice(object.Object, "results")
	if err != nil || !found {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(values))
	for _, value := range values {
		if item, ok := value.(map[string]interface{}); ok {
			result = append(result, item)
		}
	}
	return result
}

func referenceGrantAllows(ctx context.Context, targetNamespace, sourceNamespace, serviceName string) (bool, bool) {
	client := dynamicClientFromContext(ctx)
	if client == nil || targetNamespace == "" || sourceNamespace == "" {
		return false, false
	}
	spec := dynamicResourceSpec{GVR: referenceGrantGVR, Kind: "ReferenceGrant", Namespaced: true}
	outcome := listDynamicResource(ctx, client, spec, targetNamespace, metav1.ListOptions{})
	if outcome.state != DynamicCapabilityAvailable || outcome.list == nil {
		return false, false
	}
	for index := range outcome.list.Items {
		grant := &outcome.list.Items[index]
		from, _, _ := unstructured.NestedSlice(grant.Object, "spec", "from")
		to, _, _ := unstructured.NestedSlice(grant.Object, "spec", "to")
		fromAllowed := false
		for _, rawFrom := range from {
			entry, ok := rawFrom.(map[string]interface{})
			if !ok {
				continue
			}
			if stringValueFromMap(entry, "namespace") == sourceNamespace && strings.EqualFold(stringValueFromMap(entry, "kind"), "HTTPRoute") {
				fromAllowed = true
			}
		}
		if !fromAllowed {
			continue
		}
		for _, rawTo := range to {
			entry, ok := rawTo.(map[string]interface{})
			if !ok {
				continue
			}
			kind := stringValueFromMap(entry, "kind")
			name := stringValueFromMap(entry, "name")
			if strings.EqualFold(kind, "Service") && (name == "" || name == serviceName) {
				return true, true
			}
		}
	}
	return false, true
}

type dynamicClientContextKey struct{}

func dynamicClientContext(ctx context.Context, client dynamic.Interface) context.Context {
	return context.WithValue(ctx, dynamicClientContextKey{}, client)
}

func dynamicClientFromContext(ctx context.Context) dynamic.Interface {
	if ctx == nil {
		return nil
	}
	client, _ := ctx.Value(dynamicClientContextKey{}).(dynamic.Interface)
	return client
}

func dynamicNamespace(ctx context.Context, namespaced bool, namespace string) string {
	if !namespaced {
		return ""
	}
	if namespace != "" {
		return namespace
	}
	if plan, ok := scanplan.FromContext(ctx); ok {
		return plan.NamespaceArgument()
	}
	return ""
}

func dynamicObjectSelected(ctx context.Context, kind string, object *unstructured.Unstructured) bool {
	plan, ok := scanplan.FromContext(ctx)
	if !ok || object == nil {
		return true
	}
	if kind == "" {
		kind = object.GetKind()
	}
	if plan.LabelSelector != "" {
		selector, err := labels.Parse(plan.LabelSelector)
		if err != nil || !selector.Matches(labels.Set(object.GetLabels())) {
			return false
		}
	}
	return dynamicPlanIncludes(plan, kind, object.GetName(), object.GetNamespace())
}

func dynamicObjectIssueSelected(ctx context.Context, issue *Issue) bool {
	plan, ok := scanplan.FromContext(ctx)
	if !ok || issue == nil {
		return true
	}
	return dynamicPlanIncludes(plan, issue.Kind, issue.Name, issue.Namespace)
}

func dynamicPlanIncludes(plan scanplan.Plan, kind, name, namespace string) bool {
	if namespace == "" {
		if len(plan.Kinds) > 0 && !containsFoldDynamic(plan.Kinds, kind) {
			return false
		}
		return len(plan.Names) == 0 || containsFoldDynamic(plan.Names, name)
	}
	return plan.Includes(kind, name, namespace)
}

func containsFoldDynamic(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func deduplicateDynamicIssues(issues []*Issue) []*Issue {
	seen := make(map[string]*Issue, len(issues))
	result := make([]*Issue, 0, len(issues))
	for _, issue := range issues {
		if issue == nil {
			continue
		}
		key := issue.ID
		if key == "" {
			key = issue.Namespace + "\x00" + issue.Kind + "\x00" + issue.Name + "\x00" + string(issue.Category) + "\x00" + issue.Summary
		}
		if existing, exists := seen[key]; exists {
			existing.AnalyzerNames = appendUniqueField(existing.AnalyzerNames, issue.AnalyzerNames...)
			continue
		}
		seen[key] = issue
		result = append(result, issue)
	}
	return result
}

func defaultDetails(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
