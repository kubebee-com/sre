package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

var ErrSecretResource = errors.New("Secret resources cannot be returned")

func dependentListOptionsForScan(ctx context.Context) metav1.ListOptions {
	options := listOptionsForScan(ctx)
	options.FieldSelector = ""
	return options
}

// QueryResource reads one explicitly named, non-secret Kubernetes resource.
// It is intentionally narrower than exposing the client-go interface so API
// callers cannot turn the query endpoint into an arbitrary object browser.
func (s *ClusterScanner) QueryResource(ctx context.Context, kind, namespace, name string) (interface{}, error) {
	if s == nil || s.client == nil {
		return nil, ErrKubernetesClientUnavailable
	}
	kind = canonicalResourceKind(kind)
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if kind == "" || name == "" {
		return nil, fmt.Errorf("kind and name are required")
	}
	if strings.ContainsAny(kind+name+namespace, "\r\n") {
		return nil, fmt.Errorf("resource identifiers are invalid")
	}
	if validationErrors := validation.IsDNS1123Subdomain(name); len(validationErrors) > 0 {
		return nil, fmt.Errorf("resource name is invalid")
	}
	if namespace != "" {
		if validationErrors := validation.IsDNS1123Label(namespace); len(validationErrors) > 0 {
			return nil, fmt.Errorf("namespace is invalid")
		}
	}
	options := metav1.GetOptions{}
	switch kind {
	case "pod":
		return s.client.CoreV1().Pods(namespace).Get(ctx, name, options)
	case "service":
		return s.client.CoreV1().Services(namespace).Get(ctx, name, options)
	case "configmap":
		return s.client.CoreV1().ConfigMaps(namespace).Get(ctx, name, options)
	case "persistentvolumeclaim":
		return s.client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, name, options)
	case "deployment":
		return s.client.AppsV1().Deployments(namespace).Get(ctx, name, options)
	case "statefulset":
		return s.client.AppsV1().StatefulSets(namespace).Get(ctx, name, options)
	case "daemonset":
		return s.client.AppsV1().DaemonSets(namespace).Get(ctx, name, options)
	case "replicaset":
		return s.client.AppsV1().ReplicaSets(namespace).Get(ctx, name, options)
	case "job":
		return s.client.BatchV1().Jobs(namespace).Get(ctx, name, options)
	case "cronjob":
		return s.client.BatchV1().CronJobs(namespace).Get(ctx, name, options)
	case "ingress":
		return s.client.NetworkingV1().Ingresses(namespace).Get(ctx, name, options)
	case "networkpolicy":
		return s.client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, name, options)
	case "horizontalpodautoscaler":
		return s.client.AutoscalingV2().HorizontalPodAutoscalers(namespace).Get(ctx, name, options)
	case "poddisruptionbudget":
		return s.client.PolicyV1().PodDisruptionBudgets(namespace).Get(ctx, name, options)
	case "node":
		if namespace != "" {
			return nil, fmt.Errorf("nodes are cluster-scoped")
		}
		return s.client.CoreV1().Nodes().Get(ctx, name, options)
	case "secret":
		return nil, ErrSecretResource
	default:
		return nil, fmt.Errorf("resource kind %q is not queryable", kind)
	}
}

func canonicalResourceKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if slash := strings.LastIndexByte(kind, '/'); slash >= 0 {
		kind = kind[slash+1:]
	}
	switch kind {
	case "pods":
		return "pod"
	case "services":
		return "service"
	case "configmaps":
		return "configmap"
	case "persistentvolumeclaims", "pvc", "pvcs":
		return "persistentvolumeclaim"
	case "deployments":
		return "deployment"
	case "statefulsets":
		return "statefulset"
	case "daemonsets":
		return "daemonset"
	case "replicasets":
		return "replicaset"
	case "jobs":
		return "job"
	case "cronjobs":
		return "cronjob"
	case "ingresses":
		return "ingress"
	case "networkpolicies", "netpol", "netpols":
		return "networkpolicy"
	case "hpa", "horizontalpodautoscalers":
		return "horizontalpodautoscaler"
	case "pdb", "poddisruptionbudgets":
		return "poddisruptionbudget"
	case "nodes":
		return "node"
	case "secrets", "secretlist":
		return "secret"
	default:
		return kind
	}
}

// SanitizeResource projects a typed or unstructured Kubernetes object into a
// JSON-shaped value safe for an external response. Queryable resources are
// already allowlisted by QueryResource; this second boundary rejects a
// Secret-shaped object and omits ConfigMap payload values, which may contain
// credentials despite the object's non-Secret kind.
func SanitizeResource(resource interface{}, redactor *sanitizer.Redactor) (interface{}, error) {
	return sanitizeResource(resource, "", redactor)
}

// SanitizeResourceForKind is the explicit-kind form used by API callers when
// a typed client object does not carry TypeMeta in its JSON representation.
func SanitizeResourceForKind(kind string, resource interface{}, redactor *sanitizer.Redactor) (interface{}, error) {
	return sanitizeResource(resource, kind, redactor)
}

func sanitizeResource(resource interface{}, requestedKind string, redactor *sanitizer.Redactor) (interface{}, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource is empty")
	}
	if canonicalResourceKind(requestedKind) == "secret" {
		return nil, ErrSecretResource
	}
	switch resource.(type) {
	case corev1.Secret, *corev1.Secret, corev1.SecretList, *corev1.SecretList:
		return nil, ErrSecretResource
	}
	encoded, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("encode resource")
	}
	var value interface{}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, fmt.Errorf("decode resource")
	}
	if containsSecretResource(value) {
		return nil, ErrSecretResource
	}
	value = sanitizeResourceShape(value, requestedKind, redactor)
	return value, nil
}

func sanitizeResourceShape(value interface{}, requestedKind string, redactor *sanitizer.Redactor) interface{} {
	if redactor == nil {
		redactor = sanitizer.DefaultRedactor()
	}
	if object, ok := value.(map[string]interface{}); ok {
		kind, _ := object["kind"].(string)
		if canonicalResourceKind(kind) == "configmap" || canonicalResourceKind(requestedKind) == "configmap" {
			delete(object, "data")
			delete(object, "binaryData")
		}
	}
	return redactor.SanitizeValue(value)
}

func containsSecretResource(value interface{}) bool {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, nested := range typed {
			if strings.EqualFold(strings.TrimSpace(key), "kind") {
				if kind, ok := nested.(string); ok {
					canonical := strings.ToLower(strings.TrimSpace(kind))
					if slash := strings.LastIndexByte(canonical, '/'); slash >= 0 {
						canonical = canonical[slash+1:]
					}
					if canonical == "secret" || canonical == "secretlist" {
						return true
					}
				}
			}
			if containsSecretResource(nested) {
				return true
			}
		}
	case []interface{}:
		for _, nested := range typed {
			if containsSecretResource(nested) {
				return true
			}
		}
	}
	return false
}
