// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
