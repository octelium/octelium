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

package upgrade

import (
	"context"
	"fmt"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func createGenesis(ctx context.Context, c kubernetes.Interface, domain,
	version string) error {

	_, err := c.BatchV1().Jobs("octelium").Create(ctx,
		getGenesisJob(domain, version),
		metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func getGenesisJob(domain, version string) *batchv1.Job {
	labels := map[string]string{
		"app":                         "octelium",
		"octelium.com/component":      "genesis",
		"octelium.com/component-type": "cluster",
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("octelium-genesis-upgrade-%s", utilrand.GetRandomStringLowercase(6)),
			Namespace: "octelium",
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "octelium-nocturne",
					RestartPolicy:      corev1.RestartPolicyNever,

					Containers: []corev1.Container{
						{
							Name: "octelium-genesis",
							Image: func() string {
								if version != "" {
									return cliutils.GetGenesisImage(version)
								}
								if ldflags.IsDev() {
									return cliutils.GetGenesisImage("")
								} else {
									return cliutils.GetGenesisImage("latest")
								}
							}(),
							ImagePullPolicy: corev1.PullAlways,
							Args:            []string{"upgrade"},
							Env: func() []corev1.EnvVar {
								ret := []corev1.EnvVar{
									{
										Name:  "OCTELIUM_DOMAIN",
										Value: domain,
									},
								}

								return ret
							}(),
						},
					},
				},
			},
		},
	}
}
