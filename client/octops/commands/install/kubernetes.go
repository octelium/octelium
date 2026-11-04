package install

import (
	"context"

	"github.com/octelium/octelium/client/octops/internal/k8sretry"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func getK8sSecret(ctx context.Context, c kubernetes.Interface, namespace, name string) (*corev1.Secret, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*corev1.Secret, error) {
		return c.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}

func getK8sConfigMap(ctx context.Context, c kubernetes.Interface, namespace, name string) (*corev1.ConfigMap, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*corev1.ConfigMap, error) {
		return c.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}

func getK8sJob(ctx context.Context, c kubernetes.Interface, namespace, name string) (*batchv1.Job, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*batchv1.Job, error) {
		return c.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}
