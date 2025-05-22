/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package svccontroller

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSetK8sUpstream(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	os.Setenv("OCTELIUM_REGION_NAME", "default")
	defer os.Unsetenv("OCTELIUM_REGION_NAME")

	c := NewController(fakeC.OcteliumC, fakeC.K8sC)
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Container_{
						Container: &corev1.Service_Spec_Config_Upstream_Container{
							Port:  8080,
							Image: "nginx:latest",
							Env: []*corev1.Service_Spec_Config_Upstream_Container_Env{
								{
									Name: utilrand.GetRandomStringCanonical(8),
									Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{
										Value: utilrand.GetRandomString(32),
									},
								},
							},
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	err = c.OnAdd(ctx, svcV)
	assert.Nil(t, err)

	dep, err := fakeC.K8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svcV, "default"), k8smetav1.GetOptions{})
	assert.Nil(t, err)

	assert.Equal(t, 1, len(dep.Spec.Template.Spec.Containers))
	assert.True(t, len(dep.Spec.Template.Spec.Containers[0].Name) > 0)

	assert.Equal(t, svc.Spec.Config.Upstream.GetContainer().Env[0].Name, dep.Spec.Template.Spec.Containers[0].Env[0].Name)
	assert.Equal(t, svc.Spec.Config.Upstream.GetContainer().Env[0].GetValue(), dep.Spec.Template.Spec.Containers[0].Env[0].Value)
	err = c.OnDelete(ctx, svcV)
	assert.Nil(t, err)
}

func TestSetK8sUpstreamEnvFromSecret(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	os.Setenv("OCTELIUM_REGION_NAME", "default")
	defer os.Unsetenv("OCTELIUM_REGION_NAME")

	sec, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		},
	})
	assert.Nil(t, err)

	c := NewController(fakeC.OcteliumC, fakeC.K8sC)
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Container_{
						Container: &corev1.Service_Spec_Config_Upstream_Container{
							Port:  8080,
							Image: "nginx:latest",

							Env: []*corev1.Service_Spec_Config_Upstream_Container_Env{
								{
									Name: "key1",
									Type: &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{
										FromSecret: sec.Metadata.Name,
									},
								},
							},
						},
					},
				},
			},
		},
	})

	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	err = c.OnAdd(ctx, svcV)
	assert.Nil(t, err)

	dep, err := fakeC.K8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svcV, "default"), k8smetav1.GetOptions{})
	assert.Nil(t, err)

	assert.Equal(t, 1, len(dep.Spec.Template.Spec.Containers))
	assert.True(t, len(dep.Spec.Template.Spec.Containers[0].Name) > 0)
	assert.Equal(t, dep.Spec.Template.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Name, fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, sec.Metadata.Uid))

	{
		_, err := fakeC.K8sC.CoreV1().Secrets(ns).Get(ctx, fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, sec.Metadata.Uid), k8smetav1.GetOptions{})
		assert.Nil(t, err)
	}

	err = c.OnDelete(ctx, svcV)
	assert.Nil(t, err)
}
