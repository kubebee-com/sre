package scanner

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// scanIngresses analyzes Ingresses for missing ingress classes, missing backend services, or missing TLS secrets
func (s *ClusterScanner) scanIngresses(ctx context.Context, namespace string) ([]*Issue, error) {
	ingresses, err := s.client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Fetch services in this namespace to cross-check backend targets
	svcs, _ := s.client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	svcMap := make(map[string]bool)
	if svcs != nil {
		for _, svc := range svcs.Items {
			svcMap[svc.Name] = true
		}
	}

	// Fetch secrets in this namespace to cross-check TLS secrets
	secrets, _ := s.client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	secretMap := make(map[string]bool)
	if secrets != nil {
		for _, sec := range secrets.Items {
			secretMap[sec.Name] = true
		}
	}

	var issues []*Issue
	for _, ing := range ingresses.Items {
		// 1. Check Backend Services
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					svcName := path.Backend.Service.Name
					if !svcMap[svcName] {
						issues = append(issues, &Issue{
							ID:            generateIssueID(ing.Namespace, "Ingress", ing.Name, "BackendNotFound-"+svcName),
							Namespace:     ing.Namespace,
							Kind:          "Ingress",
							Name:          ing.Name,
							Severity:      SeverityHigh,
							Category:      CategoryIngressBackendNotFound,
							Summary:       fmt.Sprintf("Ingress backend service '%s' does not exist", svcName),
							Details:       fmt.Sprintf("Ingress '%s' routes host '%s' path '%s' to service '%s' which does not exist in namespace '%s'.",
								ing.Name, rule.Host, path.Path, svcName, ing.Namespace),
							FirstObserved: ing.CreationTimestamp.Time,
							LastObserved:  ing.CreationTimestamp.Time,
						})
					}
				}
			}
		}

		// 2. Check TLS Secrets
		for _, tls := range ing.Spec.TLS {
			if tls.SecretName != "" && !secretMap[tls.SecretName] {
				issues = append(issues, &Issue{
					ID:            generateIssueID(ing.Namespace, "Ingress", ing.Name, "TLSSecretMissing-"+tls.SecretName),
					Namespace:     ing.Namespace,
					Kind:          "Ingress",
					Name:          ing.Name,
					Severity:      SeverityMedium,
					Category:      CategoryIngressTLSSecretMissing,
					Summary:       fmt.Sprintf("Ingress TLS secret '%s' not found", tls.SecretName),
					Details:       fmt.Sprintf("Ingress '%s' specifies TLS secret '%s' for hosts %v, but secret does not exist (cert-manager may be pending).",
						ing.Name, tls.SecretName, tls.Hosts),
					FirstObserved: ing.CreationTimestamp.Time,
					LastObserved:  ing.CreationTimestamp.Time,
				})
			}
		}
	}
	return issues, nil
}

// scanNetworkPolicies analyzes NetworkPolicies for orphaned policies that match 0 pods
func (s *ClusterScanner) scanNetworkPolicies(ctx context.Context, namespace string) ([]*Issue, error) {
	netpols, err := s.client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, np := range netpols.Items {
		// If podSelector has matchLabels, verify if at least 1 pod matches
		if len(np.Spec.PodSelector.MatchLabels) > 0 {
			selector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
			if err == nil {
				matchingPods, err := s.client.CoreV1().Pods(np.Namespace).List(ctx, metav1.ListOptions{
					LabelSelector: selector.String(),
				})
				if err == nil && len(matchingPods.Items) == 0 {
					issues = append(issues, &Issue{
						ID:            generateIssueID(np.Namespace, "NetworkPolicy", np.Name, string(CategoryNetworkPolicyOrphaned)),
						Namespace:     np.Namespace,
						Kind:          "NetworkPolicy",
						Name:          np.Name,
						Severity:      SeverityLow,
						Category:      CategoryNetworkPolicyOrphaned,
						Summary:       "NetworkPolicy selector matches 0 pods (Orphaned)",
						Details:       fmt.Sprintf("NetworkPolicy '%s' in namespace '%s' specifies selector '%s' which matches no pods currently running in the namespace.",
							np.Name, np.Namespace, selector.String()),
						FirstObserved: np.CreationTimestamp.Time,
						LastObserved:  np.CreationTimestamp.Time,
					})
				}
			}
		}
	}
	return issues, nil
}
