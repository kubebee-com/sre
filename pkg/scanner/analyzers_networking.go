package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const maxEndpointSlicesPerService int64 = 100

func endpointSliceListOptions(service *corev1.Service) metav1.ListOptions {
	if service == nil {
		return metav1.ListOptions{Limit: maxEndpointSlicesPerService}
	}
	return metav1.ListOptions{
		LabelSelector: labels.Set{discoveryv1.LabelServiceName: service.Name}.AsSelector().String(),
		Limit:         maxEndpointSlicesPerService,
	}
}

func endpointSliceEndpointIsReady(endpoint discoveryv1.Endpoint, publishNotReadyAddresses bool) bool {
	if len(endpoint.Addresses) == 0 {
		return false
	}
	if endpoint.Conditions.Serving != nil && !*endpoint.Conditions.Serving {
		return false
	}
	if endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
		return false
	}
	if publishNotReadyAddresses {
		return true
	}
	return endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready
}

// scanIngresses analyzes Ingresses for missing ingress classes, missing backend services, or missing TLS secrets
func (s *ClusterScanner) scanIngresses(ctx context.Context, namespace string) ([]*Issue, error) {
	ingresses, err := s.client.NetworkingV1().Ingresses(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	// Fetch services in this namespace to cross-check backend targets.
	svcs, err := s.client.CoreV1().Services(namespace).List(ctx, ingressDependencyListOptions(ctx))
	if err != nil {
		return nil, fmt.Errorf("list Ingress backend Services in namespace %q: %w", namespace, err)
	}
	svcMap := make(map[string]bool)
	if svcs != nil {
		for _, svc := range svcs.Items {
			svcMap[svc.Name] = true
		}
	}

	// Fetch secrets in this namespace to cross-check TLS secrets.
	secrets, err := s.client.CoreV1().Secrets(namespace).List(ctx, ingressDependencyListOptions(ctx))
	if err != nil {
		return nil, fmt.Errorf("list Ingress TLS Secrets in namespace %q: %w", namespace, err)
	}
	secretMap := make(map[string]bool)
	if secrets != nil {
		for _, sec := range secrets.Items {
			secretMap[sec.Name] = true
		}
	}

	var issues []*Issue
	for _, ing := range ingresses.Items {
		if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
			svcName := ing.Spec.DefaultBackend.Service.Name
			if !svcMap[svcName] {
				issues = append(issues, ingressBackendMissingIssue(&ing, "<default>", ing.Spec.DefaultBackend))
			}
		}
		// 1. Check Backend Services
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if !validIngressPath(path) {
					issues = append(issues, &Issue{
						ID: makeID(ing.Namespace, "Ingress", ing.Name, "PathInvalid-"+path.Path), Namespace: ing.Namespace,
						Kind: "Ingress", Name: ing.Name, Severity: SeverityHigh, Category: CategoryIngressPathInvalid,
						Summary: fmt.Sprintf("Ingress path %q is invalid", path.Path), Details: "Ingress paths must begin with / and include a pathType.",
						FirstObserved: workloadObservedTime(ing.CreationTimestamp), LastObserved: time.Now().UTC(),
					})
				}
				if path.Backend.Service != nil {
					svcName := path.Backend.Service.Name
					if !svcMap[svcName] {
						issues = append(issues, ingressBackendMissingIssue(&ing, path.Path, &path.Backend))
					}
				}
			}
		}

		// 2. Check TLS Secrets
		for _, tls := range ing.Spec.TLS {
			if tls.SecretName != "" && !secretMap[tls.SecretName] {
				issues = append(issues, &Issue{
					ID:        generateIssueID(ing.Namespace, "Ingress", ing.Name, "TLSSecretMissing-"+tls.SecretName),
					Namespace: ing.Namespace,
					Kind:      "Ingress",
					Name:      ing.Name,
					Severity:  SeverityMedium,
					Category:  CategoryIngressTLSSecretMissing,
					Summary:   fmt.Sprintf("Ingress TLS secret '%s' not found", tls.SecretName),
					Details: fmt.Sprintf("Ingress '%s' specifies TLS secret '%s' for hosts %v, but secret does not exist (cert-manager may be pending).",
						ing.Name, tls.SecretName, tls.Hosts),
					FirstObserved: ing.CreationTimestamp.Time,
					LastObserved:  ing.CreationTimestamp.Time,
				})
			}
		}
	}
	return issues, nil
}

func findService(services []corev1.Service, name string) (*corev1.Service, bool) {
	for index := range services {
		if services[index].Name == name {
			return &services[index], true
		}
	}
	return nil, false
}

func ingressBackendMissingIssue(ingress *networkingv1.Ingress, path string, backend *networkingv1.IngressBackend) *Issue {
	serviceName := ""
	if backend != nil && backend.Service != nil {
		serviceName = backend.Service.Name
	}
	return &Issue{
		ID: makeID(ingress.Namespace, "Ingress", ingress.Name, "BackendNotFound-"+serviceName+"-"+path), Namespace: ingress.Namespace,
		Kind: "Ingress", Name: ingress.Name, Severity: SeverityHigh, Category: CategoryIngressBackendNotFound,
		Summary:       fmt.Sprintf("Ingress backend service '%s' does not exist", serviceName),
		Details:       fmt.Sprintf("Ingress '%s' routes path '%s' to service '%s', which does not exist in namespace '%s'.", ingress.Name, path, serviceName, ingress.Namespace),
		FirstObserved: workloadObservedTime(ingress.CreationTimestamp), LastObserved: time.Now().UTC(),
	}
}

func ingressPortIssue(ingress *networkingv1.Ingress, path, serviceName string) *Issue {
	return &Issue{
		ID: makeID(ingress.Namespace, "Ingress", ingress.Name, "InvalidPort-"+serviceName+"-"+path), Namespace: ingress.Namespace,
		Kind: "Ingress", Name: ingress.Name, Severity: SeverityHigh, Category: CategoryIngressPortInvalid,
		Summary:       fmt.Sprintf("Ingress %s references an invalid Service port", ingress.Name),
		Details:       fmt.Sprintf("Service %s does not expose the port selected for Ingress path %q.", serviceName, path),
		FirstObserved: workloadObservedTime(ingress.CreationTimestamp), LastObserved: time.Now().UTC(),
	}
}

func validIngressPath(path networkingv1.HTTPIngressPath) bool {
	if path.Path == "" {
		return true
	}
	if path.PathType == nil || !strings.HasPrefix(path.Path, "/") {
		return false
	}
	if strings.Contains(path.Path, "//") {
		return false
	}
	return true
}

func ingressDependencyListOptions(ctx context.Context) metav1.ListOptions {
	options := listOptionsForScan(ctx)
	// Plan selectors choose Ingress objects. Referenced Services and Secrets
	// may have different labels and names, so dependency lookups must be broad
	// within the already scoped namespace.
	options.LabelSelector = ""
	options.FieldSelector = ""
	return options
}

// scanNetworkPolicies analyzes NetworkPolicies for orphaned policies that match 0 pods
func (s *ClusterScanner) scanNetworkPolicies(ctx context.Context, namespace string) ([]*Issue, error) {
	netpols, err := s.client.NetworkingV1().NetworkPolicies(namespace).List(ctx, listOptionsForScan(ctx))
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, np := range netpols.Items {
		selector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			issues = append(issues, &Issue{
				ID:            generateIssueID(np.Namespace, "NetworkPolicy", np.Name, "InvalidSelector"),
				Namespace:     np.Namespace,
				Kind:          "NetworkPolicy",
				Name:          np.Name,
				Severity:      SeverityHigh,
				Category:      CategoryNetworkPolicyOrphaned,
				Summary:       "NetworkPolicy selector is invalid",
				Details:       "The podSelector could not be converted to a Kubernetes label selector.",
				FirstObserved: np.CreationTimestamp.Time,
				LastObserved:  np.CreationTimestamp.Time,
			})
			continue
		}
		options, optionsErr := networkPolicyPodListOptions(ctx, selector)
		if optionsErr != nil {
			return nil, fmt.Errorf("build pod selector for NetworkPolicy %s/%s: %w", np.Namespace, np.Name, optionsErr)
		}
		matchingPods, listErr := s.client.CoreV1().Pods(np.Namespace).List(ctx, options)
		if listErr != nil {
			return nil, fmt.Errorf("list pods matching NetworkPolicy %s/%s: %w", np.Namespace, np.Name, listErr)
		}
		if networkPolicySelectorIsEmpty(np.Spec.PodSelector) {
			issues = append(issues, &Issue{
				ID:            generateIssueID(np.Namespace, "NetworkPolicy", np.Name, "WideSelector"),
				Namespace:     np.Namespace,
				Kind:          "NetworkPolicy",
				Name:          np.Name,
				Severity:      SeverityLow,
				Category:      CategoryNetworkPolicyWide,
				Summary:       "NetworkPolicy selector matches all pods",
				Details:       fmt.Sprintf("NetworkPolicy '%s' has an empty podSelector and applies to all %d matching pods in the namespace.", np.Name, len(matchingPods.Items)),
				FirstObserved: np.CreationTimestamp.Time,
				LastObserved:  np.CreationTimestamp.Time,
			})
		} else if len(matchingPods.Items) == 0 {
			issues = append(issues, &Issue{
				ID:        generateIssueID(np.Namespace, "NetworkPolicy", np.Name, string(CategoryNetworkPolicyOrphaned)),
				Namespace: np.Namespace,
				Kind:      "NetworkPolicy",
				Name:      np.Name,
				Severity:  SeverityLow,
				Category:  CategoryNetworkPolicyOrphaned,
				Summary:   "NetworkPolicy selector matches 0 pods (Orphaned)",
				Details: fmt.Sprintf("NetworkPolicy '%s' in namespace '%s' specifies selector '%s' which matches no pods currently running in the namespace.",
					np.Name, np.Namespace, selector.String()),
				FirstObserved: np.CreationTimestamp.Time,
				LastObserved:  np.CreationTimestamp.Time,
			})
		}
	}
	return issues, nil
}

func networkPolicyPodListOptions(ctx context.Context, policySelector labels.Selector) (metav1.ListOptions, error) {
	options := listOptionsForScan(ctx)
	// Plan names select the NetworkPolicy, not the dependent Pods. Carrying the
	// field selector over would only find a pod with the policy's name.
	options.FieldSelector = ""
	globalSelector, err := labels.Parse(options.LabelSelector)
	if err != nil {
		return metav1.ListOptions{}, err
	}
	if options.LabelSelector == "" {
		options.LabelSelector = policySelector.String()
		return options, nil
	}
	options.LabelSelector = combineLabelSelectors(policySelector.String(), globalSelector.String())
	return options, nil
}

func networkPolicySelectorIsEmpty(selector metav1.LabelSelector) bool {
	return len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0
}
