package systemintegration

import (
	"context"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"os"
	"testing"
)

func checkPrivateVolumeRemount(t *testing.T, ctx context.Context, c *kubernetes.Clientset) {
	t.Helper()
	_, err := c.CoreV1().PersistentVolumeClaims(agentNamespace).Create(ctx, &core.PersistentVolumeClaim{ObjectMeta: meta.ObjectMeta{Name: "private-state"}, Spec: core.PersistentVolumeClaimSpec{AccessModes: []core.PersistentVolumeAccessMode{core.ReadWriteOnce}, Resources: core.VolumeResourceRequirements{Requests: core.ResourceList{core.ResourceStorage: resource.MustParse("1Gi")}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	uid := int64(65532)
	yes := true
	no := false
	change := core.FSGroupChangeOnRootMismatch
	for n, mode := range []string{"--write-state", "--check-state", "--check-state"} {
		name := []string{"write-state", "read-only-state", "restart-state"}[n]
		pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: core.PodSpec{RestartPolicy: core.RestartPolicyNever, AutomountServiceAccountToken: &no, SecurityContext: &core.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, RunAsGroup: &uid, FSGroup: &uid, FSGroupChangePolicy: &change, SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Containers: []core.Container{{Name: "fixture", Image: os.Getenv("SRE_ENTERPRISE_FIXTURE_IMAGE"), ImagePullPolicy: core.PullIfNotPresent, Args: []string{mode}, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, VolumeMounts: []core.VolumeMount{{Name: "state", MountPath: "/state", ReadOnly: n == 1}}}}, Volumes: []core.Volume{{Name: "state", VolumeSource: core.VolumeSource{PersistentVolumeClaim: &core.PersistentVolumeClaimVolumeSource{ClaimName: "private-state"}}}}}}
		if _, err := c.CoreV1().Pods(agentNamespace).Create(ctx, pod, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		waitFor(t, ctx, "private PVC mode preservation", func() bool {
			p, err := c.CoreV1().Pods(agentNamespace).Get(ctx, name, meta.GetOptions{})
			if err != nil {
				return false
			}
			if p.Status.Phase == core.PodFailed {
				t.Fatal("private PVC permissions widened on remount", name)
			}
			return p.Status.Phase == core.PodSucceeded
		})
		if err := c.CoreV1().Pods(agentNamespace).Delete(ctx, name, meta.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}
