package scanner

import (
	"context"

	"github.com/kubebee-com/sre/pkg/scanplan"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func listOptionsForScan(ctx context.Context) metav1.ListOptions {
	if plan, ok := scanplan.FromContext(ctx); ok {
		return plan.ListOptions()
	}
	return metav1.ListOptions{}
}
