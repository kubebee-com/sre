package scanner

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// scanHPAs analyzes HorizontalPodAutoscalers for unreadable metrics or scaling limit traps
func (s *ClusterScanner) scanHPAs(ctx context.Context, namespace string) ([]*Issue, error) {
	hpas, err := s.client.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, h := range hpas.Items {
		for _, cond := range h.Status.Conditions {
			if cond.Type == "ScalingActive" && cond.Status == "False" {
				issues = append(issues, &Issue{
					ID:            generateIssueID(h.Namespace, "HPA", h.Name, string(CategoryHPAMetricsUnavailable)),
					Namespace:     h.Namespace,
					Kind:          "HorizontalPodAutoscaler",
					Name:          h.Name,
					Severity:      SeverityHigh,
					Category:      CategoryHPAMetricsUnavailable,
					Summary:       fmt.Sprintf("HPA cannot compute replica count: %s", cond.Reason),
					Details:       fmt.Sprintf("HPA '%s' ScalingActive is False: %s. Metric server may be down or metrics query failed.", h.Name, cond.Message),
					FirstObserved: cond.LastTransitionTime.Time,
					LastObserved:  cond.LastTransitionTime.Time,
				})
			}
			if cond.Type == "ScalingLimited" && cond.Status == "True" && cond.Reason == "TooManyReplicas" {
				issues = append(issues, &Issue{
					ID:            generateIssueID(h.Namespace, "HPA", h.Name, string(CategoryHPAScalingLimited)),
					Namespace:     h.Namespace,
					Kind:          "HorizontalPodAutoscaler",
					Name:          h.Name,
					Severity:      SeverityMedium,
					Category:      CategoryHPAScalingLimited,
					Summary:       fmt.Sprintf("HPA has capped out at maxReplicas (%d)", h.Spec.MaxReplicas),
					Details:       fmt.Sprintf("HPA '%s' desired replicas is at or exceeds maxReplicas limit %d. Workload is under sustained high load.", h.Name, h.Spec.MaxReplicas),
					FirstObserved: cond.LastTransitionTime.Time,
					LastObserved:  cond.LastTransitionTime.Time,
				})
			}
		}
	}
	return issues, nil
}

// scanPDBs analyzes PodDisruptionBudgets for 0 allowed disruptions (which blocks node drains)
func (s *ClusterScanner) scanPDBs(ctx context.Context, namespace string) ([]*Issue, error) {
	pdbs, err := s.client.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	for _, pdb := range pdbs.Items {
		if pdb.Status.DisruptionsAllowed == 0 && pdb.Status.ExpectedPods > 0 && pdb.Status.CurrentHealthy < pdb.Status.DesiredHealthy {
			issues = append(issues, &Issue{
				ID:            generateIssueID(pdb.Namespace, "PodDisruptionBudget", pdb.Name, string(CategoryPDBDisruptionsBlocked)),
				Namespace:     pdb.Namespace,
				Kind:          "PodDisruptionBudget",
				Name:          pdb.Name,
				Severity:      SeverityMedium,
				Category:      CategoryPDBDisruptionsBlocked,
				Summary:       fmt.Sprintf("PDB allows 0 disruptions (CurrentHealthy: %d < Desired: %d)", pdb.Status.CurrentHealthy, pdb.Status.DesiredHealthy),
				Details:       fmt.Sprintf("PodDisruptionBudget '%s' has 0 disruptions allowed. Node upgrades/drains will be blocked until unhealthy pods recover.", pdb.Name),
				FirstObserved: pdb.CreationTimestamp.Time,
				LastObserved:  pdb.CreationTimestamp.Time,
			})
		}
	}
	return issues, nil
}
