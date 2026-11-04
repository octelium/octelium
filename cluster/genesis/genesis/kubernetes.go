package genesis

import (
	"context"

	"github.com/octelium/octelium/cluster/common/k8sretry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (g *Genesis) getK8sSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*corev1.Secret, error) {
		return g.k8sC.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}

func (g *Genesis) getK8sConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*corev1.ConfigMap, error) {
		return g.k8sC.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}
