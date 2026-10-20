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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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
	assert.Equal(t, "data", dep.Spec.Template.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Key)

	t.Run("Value", func(t *testing.T) {
		k8sSec, err := fakeC.K8sC.CoreV1().Secrets(ns).Get(ctx, fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, sec.Metadata.Uid), k8smetav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, sec.Data.GetValue(), k8sSec.StringData["data"])
	})

	t.Run("ValueBytes", func(t *testing.T) {
		value := utilrand.GetRandomString(32)
		sec.Data.Type = &corev1.Secret_Data_ValueBytes{
			ValueBytes: []byte(value),
		}
		sec, err = fakeC.OcteliumC.CoreC().UpdateSecret(ctx, sec)
		assert.Nil(t, err)

		err = c.OnUpdate(ctx, svcV, svcV)
		assert.Nil(t, err)

		k8sSec, err := fakeC.K8sC.CoreV1().Secrets(ns).Get(ctx, fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, sec.Metadata.Uid), k8smetav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, value, k8sSec.StringData["data"])
	})

	t.Run("SpecData", func(t *testing.T) {
		value := utilrand.GetRandomString(32)
		sec.Spec.Data = &corev1.Secret_Spec_Data{
			Type: &corev1.Secret_Spec_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		}
		sec.Data.Type = &corev1.Secret_Data_Value{
			Value: value,
		}
		sec, err = fakeC.OcteliumC.CoreC().UpdateSecret(ctx, sec)
		assert.Nil(t, err)

		err = c.OnUpdate(ctx, svcV, svcV)
		assert.Nil(t, err)

		k8sSec, err := fakeC.K8sC.CoreV1().Secrets(ns).Get(ctx, fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, sec.Metadata.Uid), k8smetav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, value, k8sSec.StringData["data"])
	})

	err = c.OnDelete(ctx, svcV)
	assert.Nil(t, err)
}

func newTstContainerConfig(name string) *corev1.Service_Spec_Config {
	return &corev1.Service_Spec_Config{
		Name: name,
		Upstream: &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Container_{
				Container: &corev1.Service_Spec_Config_Upstream_Container{
					Image: "nginx:latest",
					Port:  8080,
				},
			},
		},
	}
}

type fakeSecretCoreC struct {
	rcorev1.ResourceServiceClient
	getSecret func(context.Context, *rmetav1.GetOptions) (*corev1.Secret, error)
}

func (c *fakeSecretCoreC) GetSecret(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Secret, error) {
	return c.getSecret(ctx, in)
}

func TestK8sUpstreamPod(t *testing.T) {
	ctx := context.Background()
	c := NewController(nil, nil)
	svc := newTstService()
	cfg := newTstContainerConfig("default")
	spec := cfg.Upstream.GetContainer()
	spec.Command = []string{"/bin/app"}
	spec.Args = []string{"--serve"}
	spec.ResourceLimit = &corev1.Service_Spec_Config_Upstream_Container_ResourceLimit{
		Memory: &corev1.Service_Spec_Config_Upstream_Container_ResourceLimit_Memory{Megabytes: 256},
		Cpu:    &corev1.Service_Spec_Config_Upstream_Container_ResourceLimit_CPU{Millicores: 750},
		Ext: map[string]string{
			"example.com/gpu":   "2",
			"ephemeral-storage": "1Gi",
			"invalid":           "not-a-quantity",
			"":                  "1",
		},
	}
	spec.SecurityContext = &corev1.Service_Spec_Config_Upstream_Container_SecurityContext{
		RunAsUser:              1000,
		ReadOnlyRootFilesystem: true,
		Capabilities: &corev1.Service_Spec_Config_Upstream_Container_SecurityContext_Capabilities{
			Add: []string{"NET_BIND_SERVICE"}, Drop: []string{"ALL"},
		},
	}
	spec.Volumes = []*corev1.Service_Spec_Config_Upstream_Container_Volume{
		{
			Name: "data",
			Type: &corev1.Service_Spec_Config_Upstream_Container_Volume_PersistentVolumeClaim_{
				PersistentVolumeClaim: &corev1.Service_Spec_Config_Upstream_Container_Volume_PersistentVolumeClaim{Name: "data-pvc"},
			},
		},
		{
			Name: "cache",
			Type: &corev1.Service_Spec_Config_Upstream_Container_Volume_EmptyDir_{
				EmptyDir: &corev1.Service_Spec_Config_Upstream_Container_Volume_EmptyDir{SizeLimitMegabytes: 64},
			},
		},
		{
			Name: "tmp",
			Type: &corev1.Service_Spec_Config_Upstream_Container_Volume_EmptyDir_{
				EmptyDir: &corev1.Service_Spec_Config_Upstream_Container_Volume_EmptyDir{},
			},
		},
		{Name: "unsupported"},
	}
	spec.VolumeMounts = []*corev1.Service_Spec_Config_Upstream_Container_VolumeMount{
		{Name: "data", MountPath: "/data", SubPath: "app", ReadOnly: true},
		{Name: "cache", MountPath: "/cache"},
	}
	pod, err := c.getK8sUpstreamPod(ctx, cfg, svc, nil, c.getOwnerConfigMap(svc))
	assert.Nil(t, err)
	assert.False(t, *pod.AutomountServiceAccountToken)
	assert.False(t, *pod.EnableServiceLinks)
	assert.Equal(t, k8scorev1.DNSNone, pod.DNSPolicy)
	assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, pod.DNSConfig.Nameservers)
	assert.Equal(t, "octelium", pod.Hostname)
	assert.Empty(t, pod.ImagePullSecrets)
	assert.Equal(t, map[string]string{"octelium.com/node-mode-dataplane": ""}, pod.NodeSelector)
	assert.Len(t, pod.Volumes, 3)
	assert.Equal(t, "data-pvc", pod.Volumes[0].PersistentVolumeClaim.ClaimName)
	assert.Equal(t, resource.MustParse("64Mi"), *pod.Volumes[1].EmptyDir.SizeLimit)
	assert.Nil(t, pod.Volumes[2].EmptyDir.SizeLimit)
	assert.Len(t, pod.Containers, 1)
	container := pod.Containers[0]
	assert.Equal(t, "backend", container.Name)
	assert.Equal(t, spec.Image, container.Image)
	assert.Equal(t, spec.Command, container.Command)
	assert.Equal(t, spec.Args, container.Args)
	assert.Equal(t, int64(1000), *container.SecurityContext.RunAsUser)
	assert.False(t, *container.SecurityContext.Privileged)
	assert.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
	assert.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
	assert.Equal(t, []k8scorev1.Capability{"NET_BIND_SERVICE"}, container.SecurityContext.Capabilities.Add)
	assert.Equal(t, []k8scorev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
	assert.Equal(t, resource.MustParse("256Mi"), container.Resources.Limits[k8scorev1.ResourceMemory])
	assert.Equal(t, resource.MustParse("750m"), container.Resources.Limits[k8scorev1.ResourceCPU])
	assert.Equal(t, resource.MustParse("1Gi"), container.Resources.Limits[k8scorev1.ResourceEphemeralStorage])
	assert.Equal(t, resource.MustParse("2"), container.Resources.Limits["example.com/gpu"])
	assert.NotContains(t, container.Resources.Limits, "invalid")
	assert.NotContains(t, container.Resources.Limits, "")
	assert.Equal(t, []k8scorev1.VolumeMount{
		{Name: "data", MountPath: "/data", SubPath: "app", ReadOnly: true},
		{Name: "cache", MountPath: "/cache"},
	}, container.VolumeMounts)
}

func TestK8sUpstreamPodDefaults(t *testing.T) {
	for _, uid := range []uint32{0, 1, 1000000, 1000001} {
		t.Run(fmt.Sprintf("UID%d", uid), func(t *testing.T) {
			c := NewController(nil, nil)
			svc := newTstService()
			cfg := newTstContainerConfig("default")
			for _, empty := range []bool{false, true} {
				if empty {
					cfg.Upstream.GetContainer().ResourceLimit = &corev1.Service_Spec_Config_Upstream_Container_ResourceLimit{
						Cpu:    &corev1.Service_Spec_Config_Upstream_Container_ResourceLimit_CPU{},
						Memory: &corev1.Service_Spec_Config_Upstream_Container_ResourceLimit_Memory{},
					}
					cfg.Upstream.GetContainer().SecurityContext = &corev1.Service_Spec_Config_Upstream_Container_SecurityContext{RunAsUser: uid}
				}
				pod, err := c.getK8sUpstreamPod(context.Background(), cfg, svc, nil, c.getOwnerConfigMap(svc))
				assert.Nil(t, err)
				container := pod.Containers[0]
				assert.Equal(t, resource.MustParse("512Mi"), container.Resources.Limits[k8scorev1.ResourceMemory])
				assert.Equal(t, resource.MustParse("1000m"), container.Resources.Limits[k8scorev1.ResourceCPU])
				assert.Equal(t, resource.MustParse("5000Mi"), container.Resources.Limits[k8scorev1.ResourceEphemeralStorage])
				assert.Nil(t, container.SecurityContext.Capabilities)
				if empty {
					assert.False(t, *container.SecurityContext.ReadOnlyRootFilesystem)
				} else {
					assert.Nil(t, container.SecurityContext.ReadOnlyRootFilesystem)
				}
				if empty && uid > 0 && uid <= 1000000 {
					assert.Equal(t, int64(uid), *container.SecurityContext.RunAsUser)
				} else {
					assert.Nil(t, container.SecurityContext.RunAsUser)
				}
			}
		})
	}
}

func TestK8sUpstreamProbes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe *corev1.Service_Spec_Config_Upstream_Container_Probe
	}{
		{"HTTP", &corev1.Service_Spec_Config_Upstream_Container_Probe{
			Type: &corev1.Service_Spec_Config_Upstream_Container_Probe_HttpGet{
				HttpGet: &corev1.Service_Spec_Config_Upstream_Container_Probe_HTTPGet{Path: "/health", Port: 8080},
			},
		}},
		{"GRPC", &corev1.Service_Spec_Config_Upstream_Container_Probe{
			Type: &corev1.Service_Spec_Config_Upstream_Container_Probe_Grpc{
				Grpc: &corev1.Service_Spec_Config_Upstream_Container_Probe_GRPC{Port: 8081},
			},
		}},
		{"TCP", &corev1.Service_Spec_Config_Upstream_Container_Probe{
			Type: &corev1.Service_Spec_Config_Upstream_Container_Probe_TcpSocket{
				TcpSocket: &corev1.Service_Spec_Config_Upstream_Container_Probe_TCPSocket{Port: 8082},
			},
		}},
		{"Unsupported", &corev1.Service_Spec_Config_Upstream_Container_Probe{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewController(nil, nil)
			svc := newTstService()
			cfg := newTstContainerConfig("default")
			tc.probe.InitialDelaySeconds = 10
			tc.probe.TimeoutSeconds = 2
			tc.probe.PeriodSeconds = 15
			tc.probe.SuccessThreshold = 1
			tc.probe.FailureThreshold = 4
			cfg.Upstream.GetContainer().LivenessProbe = tc.probe
			cfg.Upstream.GetContainer().ReadinessProbe = tc.probe
			pod, err := c.getK8sUpstreamPod(context.Background(), cfg, svc, nil, c.getOwnerConfigMap(svc))
			assert.Nil(t, err)
			probe := pod.Containers[0].LivenessProbe
			assert.Equal(t, probe, pod.Containers[0].ReadinessProbe)
			if tc.name == "Unsupported" {
				assert.Nil(t, probe)
				return
			}
			assert.Equal(t, int32(10), probe.InitialDelaySeconds)
			assert.Equal(t, int32(2), probe.TimeoutSeconds)
			assert.Equal(t, int32(15), probe.PeriodSeconds)
			assert.Equal(t, int32(1), probe.SuccessThreshold)
			assert.Equal(t, int32(4), probe.FailureThreshold)
			switch tc.name {
			case "HTTP":
				assert.Equal(t, "/health", probe.HTTPGet.Path)
				assert.Equal(t, int32(8080), probe.HTTPGet.Port.IntVal)
			case "GRPC":
				assert.Equal(t, int32(8081), probe.GRPC.Port)
			case "TCP":
				assert.Equal(t, int32(8082), probe.TCPSocket.Port.IntVal)
			}
		})
	}
}

func TestK8sUpstreamEnvironment(t *testing.T) {
	c := NewController(nil, nil)
	svc := newTstService()
	cfg := newTstContainerConfig("default")
	value := func(name, value string) *corev1.Service_Spec_Config_Upstream_Container_Env {
		return &corev1.Service_Spec_Config_Upstream_Container_Env{
			Name: name,
			Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: value},
		}
	}
	cfg.Upstream.GetContainer().Env = []*corev1.Service_Spec_Config_Upstream_Container_Env{
		value("VALID", "value"),
		value("", "value"),
		value(strings.Repeat("A", 257), "value"),
		value("EMPTY", ""),
		value("TOO_LONG", strings.Repeat("x", 3001)),
		value("非ASCII", "value"),
		value(strings.Repeat("A", 256), strings.Repeat("x", 3000)),
		{
			Name: "KUBERNETES_SECRET",
			Type: &corev1.Service_Spec_Config_Upstream_Container_Env_KubernetesSecretRef_{
				KubernetesSecretRef: &corev1.Service_Spec_Config_Upstream_Container_Env_KubernetesSecretRef{Name: "k8s-secret", Key: "password"},
			},
		},
	}
	pod, err := c.getK8sUpstreamPod(context.Background(), cfg, svc, nil, c.getOwnerConfigMap(svc))
	assert.Nil(t, err)
	env := pod.Containers[0].Env
	assert.Len(t, env, 3)
	assert.Equal(t, "VALID", env[0].Name)
	assert.Equal(t, "value", env[0].Value)
	assert.Equal(t, strings.Repeat("A", 256), env[1].Name)
	assert.Equal(t, strings.Repeat("x", 3000), env[1].Value)
	assert.Equal(t, "KUBERNETES_SECRET", env[2].Name)
	assert.Equal(t, "k8s-secret", env[2].ValueFrom.SecretKeyRef.Name)
	assert.Equal(t, "password", env[2].ValueFrom.SecretKeyRef.Key)
	assert.Nil(t, env[2].ValueFrom.SecretKeyRef.Optional)
}

func TestK8sUpstreamCredentials(t *testing.T) {
	ctx := context.Background()
	svc := newTstService()
	sec := &corev1.Secret{
		Metadata: &metav1.Metadata{Name: "registry-password", Uid: "secret-uid"},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{ValueBytes: []byte("secret-password")},
		},
	}
	for _, tc := range []struct {
		name   string
		image  string
		server string
		domain string
	}{
		{"DockerHub", "nginx", "", "docker.io"},
		{"DockerHubNamespace", "library/nginx:latest", "", "docker.io"},
		{"CustomRegistry", "ghcr.io/org/image:v1", "", "ghcr.io"},
		{"CustomPort", "localhost:5000/image:v1", "", "localhost:5000"},
		{"ExplicitServer", "ghcr.io/org/image:v1", "registry.example.com", "registry.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k8sC := fakek8s.NewSimpleClientset()
			coreC := &fakeSecretCoreC{
				getSecret: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Secret, error) {
					assert.Equal(t, sec.Metadata.Name, in.Name)
					return sec, nil
				},
			}
			c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
			cfg := newTstContainerConfig("default")
			spec := cfg.Upstream.GetContainer()
			spec.Image = tc.image
			spec.Credentials = &corev1.Service_Spec_Config_Upstream_Container_Credentials{
				Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_{
					UsernamePassword: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword{
						Username: "user", Server: tc.server,
						Password: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password{
							Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password_FromSecret{FromSecret: sec.Metadata.Name},
						},
					},
				},
			}
			owner := c.getOwnerConfigMap(svc)
			owner.UID = "owner-uid"
			for range 2 {
				passwordSec, err := c.setK8sUpstreamCredSecret(ctx, svc, cfg, owner)
				assert.Nil(t, err)
				assert.Equal(t, sec, passwordSec)
			}
			name := fmt.Sprintf("regcred-%s-%s", svc.Metadata.Uid, sec.Metadata.Uid)
			k8sSec, err := k8sC.CoreV1().Secrets(ns).Get(ctx, name, k8smetav1.GetOptions{})
			assert.Nil(t, err)
			assert.Equal(t, k8scorev1.SecretTypeDockerConfigJson, k8sSec.Type)
			assert.Equal(t, owner.UID, k8sSec.OwnerReferences[0].UID)
			var config struct {
				Auths map[string]struct{ Auth string } `json:"auths"`
			}
			assert.Nil(t, json.Unmarshal([]byte(k8sSec.StringData[".dockerconfigjson"]), &config))
			assert.Len(t, config.Auths, 1)
			auth, err := base64.StdEncoding.DecodeString(config.Auths[tc.domain].Auth)
			assert.Nil(t, err)
			assert.Equal(t, "user:secret-password", string(auth))
			dep, err := c.getK8sUpstreamDeployment(ctx, svc, cfg, sec, owner)
			assert.Nil(t, err)
			assert.Equal(t, []k8scorev1.LocalObjectReference{{Name: name}}, dep.Spec.Template.Spec.ImagePullSecrets)
		})
	}
}

func TestK8sUpstreamCredentialErrors(t *testing.T) {
	ctx := context.Background()
	svc := newTstService()
	c := NewController(nil, nil)
	for _, cfg := range []*corev1.Service_Spec_Config{nil, {}, {Upstream: &corev1.Service_Spec_Config_Upstream{}}, newTstContainerConfig("default")} {
		sec, err := c.setK8sUpstreamCredSecret(ctx, svc, cfg, c.getOwnerConfigMap(svc))
		assert.Nil(t, err)
		assert.Nil(t, sec)
	}
	cfg := newTstContainerConfig("default")
	creds := &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword{}
	cfg.Upstream.GetContainer().Credentials = &corev1.Service_Spec_Config_Upstream_Container_Credentials{
		Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_{UsernamePassword: creds},
	}
	_, err := c.setK8sUpstreamCredSecret(ctx, svc, cfg, c.getOwnerConfigMap(svc))
	assert.NotNil(t, err)
	creds.Password = &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password{}
	_, err = c.setK8sUpstreamCredSecret(ctx, svc, cfg, c.getOwnerConfigMap(svc))
	assert.NotNil(t, err)
	creds.Password.Type = &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password_FromSecret{FromSecret: "password"}
	for _, getErr := range []error{status.Error(codes.NotFound, "not found"), errors.New("could not get Secret")} {
		coreC := &fakeSecretCoreC{
			getSecret: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Secret, error) { return nil, getErr },
		}
		k8sC := fakek8s.NewSimpleClientset()
		c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
		_, err := c.setK8sUpstreamCredSecret(ctx, svc, cfg, c.getOwnerConfigMap(svc))
		assert.ErrorIs(t, err, getErr)
		assert.Empty(t, k8sC.Actions())
	}

	{
		errTst := errors.New("could not create registry Secret")
		coreC := &fakeSecretCoreC{
			getSecret: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Secret, error) {
				return &corev1.Secret{
					Metadata: &metav1.Metadata{Uid: "password-uid"},
					Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "password"}},
				}, nil
			},
		}
		k8sC := fakek8s.NewSimpleClientset()
		k8sC.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errTst
		})
		c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
		_, err := c.setK8sUpstreamCredSecret(ctx, svc, cfg, c.getOwnerConfigMap(svc))
		assert.ErrorIs(t, err, errTst)
		svc.Spec.Config = cfg
		assert.ErrorContains(t, c.setK8sUpstream(ctx, svc, c.getOwnerConfigMap(svc)), errTst.Error())
		svc.Spec.Config = nil
		svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{cfg}}
		assert.ErrorContains(t, c.setK8sUpstream(ctx, svc, c.getOwnerConfigMap(svc)), errTst.Error())
		deps, err := k8sC.AppsV1().Deployments(ns).List(ctx, k8smetav1.ListOptions{})
		assert.Nil(t, err)
		assert.Empty(t, deps.Items)
	}
}

func TestK8sUpstreamReconciliation(t *testing.T) {
	ctx := context.Background()
	svc := newTstService()
	svc.Spec.Mode = corev1.Service_Spec_DNS
	svc.Spec.Config = newTstContainerConfig("default")
	svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
		Configs: []*corev1.Service_Spec_Config{
			newTstContainerConfig("first"), newTstContainerConfig("second"),
			{Name: "no-upstream"},
			{Name: "url", Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://example.com"}}},
		},
	}
	svc.Spec.DynamicConfig.Configs[0].Upstream.GetContainer().Replicas = 3
	k8sC := fakek8s.NewSimpleClientset()
	c := NewController(nil, k8sC)
	owner := c.getOwnerConfigMap(svc)
	owner.UID = "owner-uid"
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	deps, err := k8sC.AppsV1().Deployments(ns).List(ctx, k8smetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Len(t, deps.Items, 3)
	for _, cfg := range []*corev1.Service_Spec_Config{svc.Spec.Config, svc.Spec.DynamicConfig.Configs[0], svc.Spec.DynamicConfig.Configs[1]} {
		name := k8sutils.GetSvcK8sUpstreamHostname(svc, cfg.Name)
		dep, err := k8sC.AppsV1().Deployments(ns).Get(ctx, name, k8smetav1.GetOptions{})
		assert.Nil(t, err)
		if cfg.Upstream.GetContainer().Replicas > 0 {
			assert.Equal(t, int32(3), *dep.Spec.Replicas)
		} else {
			assert.Nil(t, dep.Spec.Replicas)
		}
		assert.Equal(t, c.getK8sUpstreamLabels(svc, cfg.Name), dep.Spec.Selector.MatchLabels)
		assert.Equal(t, dep.Spec.Selector.MatchLabels, dep.Spec.Template.Labels)
		assert.Equal(t, owner.UID, dep.OwnerReferences[0].UID)
		svcK8s, err := k8sC.CoreV1().Services(ns).Get(ctx, name, k8smetav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, dep.Spec.Selector.MatchLabels, svcK8s.Spec.Selector)
		assert.Equal(t, k8scorev1.ProtocolUDP, svcK8s.Spec.Ports[0].Protocol)
		assert.Equal(t, int32(8080), svcK8s.Spec.Ports[0].Port)
		assert.Equal(t, int32(8080), svcK8s.Spec.Ports[0].TargetPort.IntVal)
		assert.Equal(t, dep.OwnerReferences, svcK8s.OwnerReferences)
	}
}

func TestK8sUpstreamErrors(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	for _, dynamic := range []bool{false, true} {
		for _, rsc := range []string{"deployments", "services"} {
			t.Run(fmt.Sprintf("%t/%s", dynamic, rsc), func(t *testing.T) {
				svc := newTstService()
				cfg := newTstContainerConfig("upstream")
				if dynamic {
					svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{cfg}}
				} else {
					svc.Spec.Config = cfg
				}
				errTst := errors.New("could not create upstream resource")
				k8sC := fakek8s.NewSimpleClientset()
				fail := true
				k8sC.PrependReactor("create", rsc, func(action k8stesting.Action) (bool, runtime.Object, error) {
					return fail, nil, errTst
				})
				coreC := &fakeCoreC{getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
					return svc, nil
				}}
				c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
				assert.ErrorIs(t, c.setK8sUpstream(ctx, svc, c.getOwnerConfigMap(svc)), errTst)
				assert.ErrorIs(t, c.OnAdd(ctx, svc), errTst)
				fail = false
				assert.Nil(t, c.setK8sUpstream(ctx, svc, c.getOwnerConfigMap(svc)))
			})
		}
	}
}

func newTstUpstreamController(t *testing.T) (*Controller, *corev1.Service, *k8scorev1.ConfigMap, *fakek8s.Clientset) {
	t.Helper()
	k8sC := fakek8s.NewSimpleClientset()
	k8sC.PrependReactor("create", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		obj := action.(k8stesting.CreateAction).GetObject().(k8smetav1.Object)
		if obj.GetUID() == "" {
			obj.SetUID(types.UID(obj.GetName() + "-uid"))
		}
		if obj.GetResourceVersion() == "" {
			obj.SetResourceVersion("1")
		}
		return false, nil, nil
	})
	coreC := &fakeSecretCoreC{
		getSecret: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Secret, error) {
			return &corev1.Secret{
				Metadata: &metav1.Metadata{Name: in.Name, Uid: in.Name + "-uid"},
				Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "value"}},
			}, nil
		},
	}
	c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
	svc := newTstService()
	owner, err := k8sC.CoreV1().ConfigMaps(ns).Create(context.Background(), c.getOwnerConfigMap(svc), k8smetav1.CreateOptions{})
	assert.Nil(t, err)
	return c, svc, owner, k8sC
}

func setTstUpstreamSecret(cfg *corev1.Service_Spec_Config, name string) {
	spec := cfg.Upstream.GetContainer()
	spec.Env = []*corev1.Service_Spec_Config_Upstream_Container_Env{
		{Name: "TOKEN", Type: &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{FromSecret: name}},
	}
	spec.Credentials = &corev1.Service_Spec_Config_Upstream_Container_Credentials{
		Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_{
			UsernamePassword: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword{
				Username: "user", Server: "docker.io",
				Password: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password{
					Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password_FromSecret{FromSecret: name},
				},
			},
		},
	}
}

func TestK8sUpstreamRemoval(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		update  func(*corev1.Service)
		configs []string
		secrets []string
	}{
		{"DefaultToURL", func(svc *corev1.Service) {
			svc.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{Url: "http://example.com"}
		}, []string{"first", "second"}, []string{"first", "second"}},
		{"DefaultRemoved", func(svc *corev1.Service) {
			svc.Spec.Config = nil
		}, []string{"first", "second"}, []string{"first", "second"}},
		{"DefaultUpstreamRemoved", func(svc *corev1.Service) {
			svc.Spec.Config.Upstream = nil
		}, []string{"first", "second"}, []string{"first", "second"}},
		{"NamedRemoved", func(svc *corev1.Service) {
			svc.Spec.DynamicConfig.Configs = svc.Spec.DynamicConfig.Configs[1:]
		}, []string{"default", "second"}, []string{"default", "second"}},
		{"NamedToURL", func(svc *corev1.Service) {
			svc.Spec.DynamicConfig.Configs[0].Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{Url: "http://example.com"}
		}, []string{"default", "second"}, []string{"default", "second"}},
		{"NamedRenamed", func(svc *corev1.Service) {
			svc.Spec.DynamicConfig.Configs[0].Name = "renamed"
		}, []string{"default", "renamed", "second"}, []string{"default", "first", "second"}},
		{"DynamicRemoved", func(svc *corev1.Service) {
			svc.Spec.DynamicConfig = nil
		}, []string{"default"}, []string{"default"}},
		{"AllRemoved", func(svc *corev1.Service) {
			svc.Spec.Config = nil
			svc.Spec.DynamicConfig = nil
		}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, svc, owner, k8sC := newTstUpstreamController(t)
			svc.Spec.Config = newTstContainerConfig("")
			setTstUpstreamSecret(svc.Spec.Config, "default")
			svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
				Configs: []*corev1.Service_Spec_Config{newTstContainerConfig("first"), newTstContainerConfig("second")},
			}
			for _, cfg := range svc.Spec.DynamicConfig.Configs {
				setTstUpstreamSecret(cfg, cfg.Name)
			}
			assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
			_, err := k8sC.AppsV1().Deployments(ns).Create(ctx, c.newDeployment(svc, owner), k8smetav1.CreateOptions{})
			assert.Nil(t, err)
			_, err = k8sC.CoreV1().Services(ns).Create(ctx, c.getK8sService(svc, owner), k8smetav1.CreateOptions{})
			assert.Nil(t, err)
			tc.update(svc)
			assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
			assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
			want := []string{k8sutils.GetSvcHostname(svc)}
			for _, name := range tc.configs {
				want = append(want, k8sutils.GetSvcK8sUpstreamHostname(svc, name))
			}
			deps, err := k8sC.AppsV1().Deployments(ns).List(ctx, k8smetav1.ListOptions{})
			assert.Nil(t, err)
			var got []string
			for _, dep := range deps.Items {
				got = append(got, dep.Name)
			}
			assert.ElementsMatch(t, want, got)
			services, err := k8sC.CoreV1().Services(ns).List(ctx, k8smetav1.ListOptions{})
			assert.Nil(t, err)
			got = nil
			for _, itm := range services.Items {
				got = append(got, itm.Name)
			}
			assert.ElementsMatch(t, want, got)
			want = nil
			for _, name := range tc.secrets {
				want = append(want, fmt.Sprintf("svc-env-%s-%s-uid", svc.Metadata.Uid, name),
					fmt.Sprintf("regcred-%s-%s-uid", svc.Metadata.Uid, name))
			}
			secrets, err := k8sC.CoreV1().Secrets(ns).List(ctx, k8smetav1.ListOptions{})
			assert.Nil(t, err)
			got = nil
			for _, secret := range secrets.Items {
				got = append(got, secret.Name)
			}
			assert.ElementsMatch(t, want, got)
			for _, action := range k8sC.Actions() {
				if action.GetVerb() == "delete" {
					del := action.(k8stesting.DeleteAction)
					assert.Equal(t, types.UID(del.GetName()+"-uid"), *del.GetDeleteOptions().Preconditions.UID)
					assert.Equal(t, "1", *del.GetDeleteOptions().Preconditions.ResourceVersion)
					if action.GetResource().Resource == "deployments" {
						assert.Equal(t, k8smetav1.DeletePropagationBackground, *del.GetDeleteOptions().PropagationPolicy)
					}
				}
			}
			cm, err := k8sC.CoreV1().ConfigMaps(ns).Get(ctx, owner.Name, k8smetav1.GetOptions{})
			assert.Nil(t, err)
			assert.Equal(t, owner.UID, cm.UID)
		})
	}
}

func TestK8sUpstreamSharedSecrets(t *testing.T) {
	ctx := context.Background()
	c, svc, owner, k8sC := newTstUpstreamController(t)
	svc.Spec.Config = newTstContainerConfig("default")
	setTstUpstreamSecret(svc.Spec.Config, "shared")
	cfg := newTstContainerConfig("named")
	setTstUpstreamSecret(cfg, "shared")
	svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{cfg}}
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	secrets, err := k8sC.CoreV1().Secrets(ns).List(ctx, k8smetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Len(t, secrets.Items, 2)
	svc.Spec.Config = nil
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	for _, secret := range secrets.Items {
		current, err := k8sC.CoreV1().Secrets(ns).Get(ctx, secret.Name, k8smetav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, secret.UID, current.UID)
	}
	svc.Spec.DynamicConfig = nil
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	secrets, err = k8sC.CoreV1().Secrets(ns).List(ctx, k8smetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Empty(t, secrets.Items)
}

func TestK8sUpstreamCleanupOwnership(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		modify func(*k8smetav1.ObjectMeta)
	}{
		{"other-owner", func(md *k8smetav1.ObjectMeta) { md.OwnerReferences[0].UID = "other-uid" }},
		{"other-name", func(md *k8smetav1.ObjectMeta) { md.OwnerReferences[0].Name = "other-owner" }},
		{"other-kind", func(md *k8smetav1.ObjectMeta) { md.OwnerReferences[0].Kind = "Secret" }},
		{"other-api", func(md *k8smetav1.ObjectMeta) { md.OwnerReferences[0].APIVersion = "other/v1" }},
		{"not-controller", func(md *k8smetav1.ObjectMeta) { md.OwnerReferences[0].Controller = new(false) }},
		{"no-owner", func(md *k8smetav1.ObjectMeta) { md.OwnerReferences = nil }},
		{"other-prefix", func(md *k8smetav1.ObjectMeta) { md.Name = "manual-" + md.Name }},
		{"other-namespace", func(md *k8smetav1.ObjectMeta) { md.Namespace = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, svc, owner, k8sC := newTstUpstreamController(t)
			cfg := newTstContainerConfig("obsolete")
			dep, err := c.getK8sUpstreamDeployment(ctx, svc, cfg, nil, owner)
			assert.Nil(t, err)
			tc.modify(&dep.ObjectMeta)
			_, err = k8sC.AppsV1().Deployments(dep.Namespace).Create(ctx, dep, k8smetav1.CreateOptions{})
			assert.Nil(t, err)
			upstreamSvc := c.getK8sUpstreamService(svc, cfg, owner)
			tc.modify(&upstreamSvc.ObjectMeta)
			_, err = k8sC.CoreV1().Services(upstreamSvc.Namespace).Create(ctx, upstreamSvc, k8smetav1.CreateOptions{})
			assert.Nil(t, err)
			secret := &k8scorev1.Secret{
				ObjectMeta: k8smetav1.ObjectMeta{
					Name: fmt.Sprintf("svc-env-%s-obsolete", svc.Metadata.Uid), Namespace: ns,
					OwnerReferences: []k8smetav1.OwnerReference{*k8smetav1.NewControllerRef(owner, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap"))},
				},
			}
			tc.modify(&secret.ObjectMeta)
			_, err = k8sC.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, k8smetav1.CreateOptions{})
			assert.Nil(t, err)
			assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
			_, err = k8sC.AppsV1().Deployments(dep.Namespace).Get(ctx, dep.Name, k8smetav1.GetOptions{})
			assert.Nil(t, err)
			_, err = k8sC.CoreV1().Services(upstreamSvc.Namespace).Get(ctx, upstreamSvc.Name, k8smetav1.GetOptions{})
			assert.Nil(t, err)
			_, err = k8sC.CoreV1().Secrets(secret.Namespace).Get(ctx, secret.Name, k8smetav1.GetOptions{})
			assert.Nil(t, err)
		})
	}

	{
		c, svc, owner, k8sC := newTstUpstreamController(t)
		other := proto.Clone(svc).(*corev1.Service)
		other.Metadata.Uid = "other-service-uid"
		cfg := newTstContainerConfig("obsolete")
		dep, err := c.getK8sUpstreamDeployment(ctx, other, cfg, nil, owner)
		assert.Nil(t, err)
		_, err = k8sC.AppsV1().Deployments(ns).Create(ctx, dep, k8smetav1.CreateOptions{})
		assert.Nil(t, err)
		upstreamSvc := c.getK8sUpstreamService(other, cfg, owner)
		_, err = k8sC.CoreV1().Services(ns).Create(ctx, upstreamSvc, k8smetav1.CreateOptions{})
		assert.Nil(t, err)
		assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
		_, err = k8sC.AppsV1().Deployments(ns).Get(ctx, dep.Name, k8smetav1.GetOptions{})
		assert.Nil(t, err)
		_, err = k8sC.CoreV1().Services(ns).Get(ctx, upstreamSvc.Name, k8smetav1.GetOptions{})
		assert.Nil(t, err)
	}

	{
		c, svc, owner, k8sC := newTstUpstreamController(t)
		svc.Spec.Config = newTstContainerConfig("default")
		assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
		svc.Spec.Config = nil
		owner.UID = ""
		k8sC.ClearActions()
		assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
		assert.Empty(t, k8sC.Actions())
	}
}

func TestK8sUpstreamSecretsInUse(t *testing.T) {
	ctx := context.Background()
	c, svc, owner, k8sC := newTstUpstreamController(t)
	svc.Spec.Config = newTstContainerConfig("default")
	name := func(arg string) string { return fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, arg) }
	for _, key := range []string{"desired", "env", "pull", "init", "env-from", "volume", "projected", "managed", "removed"} {
		_, err := k8sC.CoreV1().Secrets(ns).Create(ctx, &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name: name(key), Namespace: ns,
				OwnerReferences: []k8smetav1.OwnerReference{*k8smetav1.NewControllerRef(owner, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap"))},
			},
		}, k8smetav1.CreateOptions{})
		assert.Nil(t, err)
	}
	svc.Spec.Config.Upstream.GetContainer().Env = []*corev1.Service_Spec_Config_Upstream_Container_Env{
		{
			Name: "TOKEN",
			Type: &corev1.Service_Spec_Config_Upstream_Container_Env_KubernetesSecretRef_{
				KubernetesSecretRef: &corev1.Service_Spec_Config_Upstream_Container_Env_KubernetesSecretRef{Name: name("desired"), Key: "data"},
			},
		},
	}
	svc.Status.ManagedService = &corev1.Service_Status_ManagedService{ImagePullSecret: name("managed")}
	env := func(key string) k8scorev1.EnvVar {
		return k8scorev1.EnvVar{Name: "TOKEN", ValueFrom: &k8scorev1.EnvVarSource{
			SecretKeyRef: &k8scorev1.SecretKeySelector{LocalObjectReference: k8scorev1.LocalObjectReference{Name: name(key)}, Key: "data"},
		}}
	}
	pod := &k8scorev1.Pod{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "active", Namespace: ns, Labels: c.getK8sUpstreamLabels(svc, "default")},
		Spec: k8scorev1.PodSpec{
			ImagePullSecrets: []k8scorev1.LocalObjectReference{{Name: name("pull")}},
			Containers: []k8scorev1.Container{{
				Env: []k8scorev1.EnvVar{env("env"), {Name: "LITERAL", Value: "value"}, {Name: "FIELD", ValueFrom: &k8scorev1.EnvVarSource{}}},
				EnvFrom: []k8scorev1.EnvFromSource{
					{SecretRef: &k8scorev1.SecretEnvSource{LocalObjectReference: k8scorev1.LocalObjectReference{Name: name("env-from")}}},
					{ConfigMapRef: &k8scorev1.ConfigMapEnvSource{}},
				},
			}},
			InitContainers: []k8scorev1.Container{{Env: []k8scorev1.EnvVar{env("init")}}},
			Volumes: []k8scorev1.Volume{
				{VolumeSource: k8scorev1.VolumeSource{Secret: &k8scorev1.SecretVolumeSource{SecretName: name("volume")}}},
				{VolumeSource: k8scorev1.VolumeSource{Projected: &k8scorev1.ProjectedVolumeSource{Sources: []k8scorev1.VolumeProjection{
					{Secret: &k8scorev1.SecretProjection{LocalObjectReference: k8scorev1.LocalObjectReference{Name: name("projected")}}},
					{ConfigMap: &k8scorev1.ConfigMapProjection{}},
				}}}},
				{},
			},
		},
	}
	_, err := k8sC.CoreV1().Pods(ns).Create(ctx, pod, k8smetav1.CreateOptions{})
	assert.Nil(t, err)
	removed := pod.DeepCopy()
	removed.Name = "removed"
	removed.UID = ""
	removed.Labels = c.getK8sUpstreamLabels(svc, "removed")
	removed.Spec = k8scorev1.PodSpec{Containers: []k8scorev1.Container{{Env: []k8scorev1.EnvVar{env("removed")}}}}
	_, err = k8sC.CoreV1().Pods(ns).Create(ctx, removed, k8smetav1.CreateOptions{})
	assert.Nil(t, err)
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	secrets, err := k8sC.CoreV1().Secrets(ns).List(ctx, k8smetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Len(t, secrets.Items, 8)
	_, err = k8sC.CoreV1().Secrets(ns).Get(ctx, name("removed"), k8smetav1.GetOptions{})
	assert.True(t, k8serr.IsNotFound(err))
	assert.Nil(t, k8sC.CoreV1().Pods(ns).Delete(ctx, pod.Name, k8smetav1.DeleteOptions{}))
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	secrets, err = k8sC.CoreV1().Secrets(ns).List(ctx, k8smetav1.ListOptions{})
	assert.Nil(t, err)
	var got []string
	for _, secret := range secrets.Items {
		got = append(got, secret.Name)
	}
	assert.ElementsMatch(t, []string{name("desired"), name("managed")}, got)
}

func TestK8sUpstreamCleanupErrors(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		verb string
		rsc  string
	}{
		{"list", "deployments"}, {"list", "services"}, {"list", "secrets"}, {"list", "pods"},
		{"delete", "deployments"}, {"delete", "services"}, {"delete", "secrets"},
	} {
		t.Run(tc.verb+"/"+tc.rsc, func(t *testing.T) {
			c, svc, owner, k8sC := newTstUpstreamController(t)
			svc.Spec.Config = newTstContainerConfig("default")
			setTstUpstreamSecret(svc.Spec.Config, "obsolete")
			svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{newTstContainerConfig("keep")}}
			assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
			svc.Spec.Config = nil
			errTst := errors.New("could not reconcile upstream resources")
			fail := true
			k8sC.PrependReactor(tc.verb, tc.rsc, func(action k8stesting.Action) (bool, runtime.Object, error) {
				return fail, nil, errTst
			})
			k8sC.ClearActions()
			assert.ErrorIs(t, c.setK8sUpstream(ctx, svc, owner), errTst)
			if tc.verb == "list" {
				for _, action := range k8sC.Actions() {
					assert.NotEqual(t, "delete", action.GetVerb())
				}
			}
			fail = false
			assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
			_, err := k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svc, "default"), k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err))
			_, err = k8sC.CoreV1().Services(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svc, "default"), k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err))
			_, err = k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svc, "keep"), k8smetav1.GetOptions{})
			assert.Nil(t, err)
			secrets, err := k8sC.CoreV1().Secrets(ns).List(ctx, k8smetav1.ListOptions{})
			assert.Nil(t, err)
			assert.Empty(t, secrets.Items)
		})
	}
}

func TestK8sUpstreamCleanupAlreadyDeleted(t *testing.T) {
	ctx := context.Background()
	c, svc, owner, k8sC := newTstUpstreamController(t)
	svc.Spec.Config = newTstContainerConfig("default")
	setTstUpstreamSecret(svc.Spec.Config, "obsolete")
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	svc.Spec.Config = nil
	var deleted int
	k8sC.PrependReactor("delete", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		del := action.(k8stesting.DeleteAction)
		assert.Nil(t, k8sC.Tracker().Delete(action.GetResource(), action.GetNamespace(), del.GetName()))
		deleted++
		return true, nil, k8serr.NewNotFound(schema.GroupResource{Resource: action.GetResource().Resource}, del.GetName())
	})
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	assert.Equal(t, 4, deleted)
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	assert.Equal(t, 4, deleted)
}

func TestK8sUpstreamFailedReplacement(t *testing.T) {
	ctx := context.Background()
	for _, rsc := range []string{"secrets", "deployments", "services"} {
		t.Run(rsc, func(t *testing.T) {
			c, svc, owner, k8sC := newTstUpstreamController(t)
			svc.Spec.Config = newTstContainerConfig("default")
			setTstUpstreamSecret(svc.Spec.Config, "obsolete")
			assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
			svc.Spec.Config = nil
			cfg := newTstContainerConfig("replacement")
			setTstUpstreamSecret(cfg, "replacement")
			svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{cfg}}
			fail := true
			k8sC.PrependReactor("create", rsc, func(action k8stesting.Action) (bool, runtime.Object, error) {
				return fail, nil, errors.New("could not create replacement")
			})
			k8sC.ClearActions()
			assert.ErrorContains(t, c.setK8sUpstream(ctx, svc, owner), "could not create replacement")
			for _, action := range k8sC.Actions() {
				assert.NotEqual(t, "delete", action.GetVerb())
			}
			_, err := k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svc, "default"), k8smetav1.GetOptions{})
			assert.Nil(t, err)
			fail = false
			assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
			_, err = k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svc, "default"), k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err))
		})
	}
}

func TestK8sUpstreamCleanupSnapshots(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	c, svc, owner, k8sC := newTstUpstreamController(t)
	svc.Spec.Config = newTstContainerConfig("default")
	svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{newTstContainerConfig("obsolete")}}
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	old := proto.Clone(svc).(*corev1.Service)
	svc.Spec.Config = newTstService().Spec.Config
	svc.Spec.DynamicConfig = nil
	c.octeliumC = &fakeOcteliumC{coreC: &fakeCoreC{
		ResourceServiceClient: c.octeliumC.CoreC(),
		getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
			assert.Equal(t, svc.Metadata.Uid, in.Uid)
			return proto.Clone(svc).(*corev1.Service), nil
		},
	}}
	assert.Nil(t, c.OnAdd(ctx, old))
	for _, name := range []string{"default", "obsolete"} {
		_, err := k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svc, name), k8smetav1.GetOptions{})
		assert.True(t, k8serr.IsNotFound(err))
	}
	svc.Spec.Config = newTstContainerConfig("default")
	assert.Nil(t, c.OnUpdate(ctx, old, old))
	_, err := k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svc, "default"), k8smetav1.GetOptions{})
	assert.Nil(t, err)
	_, err = k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcHostname(svc), k8smetav1.GetOptions{})
	assert.Nil(t, err)
}

func TestK8sUpstreamCleanupDeleteConflict(t *testing.T) {
	ctx := context.Background()
	c, svc, owner, k8sC := newTstUpstreamController(t)
	svc.Spec.Config = newTstContainerConfig("default")
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	svc.Spec.Config = nil
	var deletes int
	k8sC.PrependReactor("delete", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		del := action.(k8stesting.DeleteAction)
		obj, err := k8sC.Tracker().Get(action.GetResource(), ns, del.GetName())
		assert.Nil(t, err)
		dep := obj.(*appsv1.Deployment).DeepCopy()
		assert.Equal(t, dep.UID, *del.GetDeleteOptions().Preconditions.UID)
		assert.Equal(t, dep.ResourceVersion, *del.GetDeleteOptions().Preconditions.ResourceVersion)
		dep.UID = "replacement-uid"
		dep.ResourceVersion = "2"
		dep.OwnerReferences[0].UID = "other-owner-uid"
		assert.Nil(t, k8sC.Tracker().Update(action.GetResource(), dep, ns))
		deletes++
		return true, nil, k8serr.NewConflict(schema.GroupResource{Resource: "deployments"}, dep.Name, errors.New("resource changed"))
	})
	assert.True(t, k8serr.IsConflict(c.setK8sUpstream(ctx, svc, owner)))
	assert.Nil(t, c.setK8sUpstream(ctx, svc, owner))
	dep, err := k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcK8sUpstreamHostname(svc, "default"), k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.Equal(t, types.UID("replacement-uid"), dep.UID)
	assert.Equal(t, 1, deletes)
}

func TestK8sUpstreamEnvironmentSecretErrors(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		lookup error
		verb   string
	}{
		{"NotFound", status.Error(codes.NotFound, "not found"), ""},
		{"Unavailable", status.Error(codes.Unavailable, "unavailable"), ""},
		{"Internal", status.Error(codes.Internal, "internal"), ""},
		{"PermissionDenied", status.Error(codes.PermissionDenied, "permission denied"), ""},
		{"Cancelled", context.Canceled, ""},
		{"DeadlineExceeded", context.DeadlineExceeded, ""},
		{"CreateMirror", nil, "create"},
		{"GetMirror", nil, "get"},
		{"UpdateMirror", nil, "update"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, svc, owner, k8sC := newTstUpstreamController(t)
			cfg := newTstContainerConfig("default")
			cfg.Upstream.GetContainer().Env = []*corev1.Service_Spec_Config_Upstream_Container_Env{
				{Name: "MODE", Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: "production"}},
				{Name: "TOKEN", Type: &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{FromSecret: "token"}},
			}
			name := fmt.Sprintf("svc-env-%s-token-uid", svc.Metadata.Uid)
			if tc.verb == "get" || tc.verb == "update" {
				_, err := c.getK8sUpstreamPod(ctx, cfg, svc, nil, owner)
				assert.Nil(t, err)
			}
			errTst := tc.lookup
			if tc.verb != "" {
				errTst = k8serr.NewForbidden(schema.GroupResource{Resource: "secrets"}, name, errors.New("forbidden"))
			}
			fail := true
			secretC := c.octeliumC.CoreC()
			c.octeliumC = &fakeOcteliumC{coreC: &fakeSecretCoreC{
				getSecret: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Secret, error) {
					assert.Equal(t, "token", in.Name)
					if fail && tc.lookup != nil {
						return nil, tc.lookup
					}
					return secretC.GetSecret(ctx, in)
				},
			}}
			if tc.verb != "" {
				k8sC.PrependReactor(tc.verb, "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					return fail, nil, errTst
				})
			}
			k8sC.ClearActions()
			pod, err := c.getK8sUpstreamPod(ctx, cfg, svc, nil, owner)
			assert.ErrorIs(t, err, errTst)
			assert.Nil(t, pod)
			if tc.lookup != nil {
				assert.Empty(t, k8sC.Actions())
			}

			fail = false
			pod, err = c.getK8sUpstreamPod(ctx, cfg, svc, nil, owner)
			if !assert.Nil(t, err) {
				return
			}
			env := pod.Containers[0].Env
			if !assert.Len(t, env, 2) {
				return
			}
			assert.Equal(t, "production", env[0].Value)
			assert.Equal(t, "TOKEN", env[1].Name)
			assert.Empty(t, env[1].Value)
			if assert.NotNil(t, env[1].ValueFrom) && assert.NotNil(t, env[1].ValueFrom.SecretKeyRef) {
				assert.Equal(t, name, env[1].ValueFrom.SecretKeyRef.Name)
				assert.Equal(t, "data", env[1].ValueFrom.SecretKeyRef.Key)
				assert.Nil(t, env[1].ValueFrom.SecretKeyRef.Optional)
			}
			secret, err := k8sC.CoreV1().Secrets(ns).Get(ctx, name, k8smetav1.GetOptions{})
			assert.Nil(t, err)
			assert.Equal(t, "value", secret.StringData["data"])
		})
	}
}

func TestK8sUpstreamEnvironmentSecretReconciliation(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	for _, dynamic := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			for _, stage := range []string{"lookup", "create", "get", "update"} {
				t.Run(fmt.Sprintf("Dynamic%t/Existing%t/%s", dynamic, existing, stage), func(t *testing.T) {
					c, svc, owner, k8sC := newTstUpstreamController(t)
					cfg := newTstContainerConfig("default")
					if dynamic {
						cfg.Name = "named"
						svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{cfg}}
					} else {
						svc.Spec.Config = cfg
					}
					cfg.Upstream.GetContainer().Env = []*corev1.Service_Spec_Config_Upstream_Container_Env{
						{Name: "TOKEN", Type: &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{FromSecret: "token"}},
					}
					secretC := c.octeliumC.CoreC()
					var fail bool
					lookupErr := status.Error(codes.Unavailable, "could not get Secret")
					c.octeliumC = &fakeOcteliumC{coreC: &fakeSecretCoreC{
						ResourceServiceClient: &fakeCoreC{
							getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
								return proto.Clone(svc).(*corev1.Service), nil
							},
						},
						getSecret: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Secret, error) {
							if fail && stage == "lookup" {
								return nil, lookupErr
							}
							return secretC.GetSecret(ctx, in)
						},
					}}
					var original, proxy *appsv1.Deployment
					var service *k8scorev1.Service
					name := k8sutils.GetSvcK8sUpstreamHostname(svc, cfg.Name)
					if existing {
						assert.Nil(t, c.OnAdd(ctx, svc))
						var err error
						original, err = k8sC.AppsV1().Deployments(ns).Get(ctx, name, k8smetav1.GetOptions{})
						assert.Nil(t, err)
						proxy, err = k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcHostname(svc), k8smetav1.GetOptions{})
						assert.Nil(t, err)
						service, err = k8sC.CoreV1().Services(ns).Get(ctx, name, k8smetav1.GetOptions{})
						assert.Nil(t, err)
					} else if stage == "get" || stage == "update" {
						_, err := c.getK8sUpstreamPod(ctx, cfg, svc, nil, owner)
						assert.Nil(t, err)
					}
					old := proto.Clone(svc).(*corev1.Service)
					cfg.Upstream.GetContainer().Image = "nginx:replacement"
					if stage == "create" {
						cfg.Upstream.GetContainer().Env[0].Type = &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{FromSecret: "replacement"}
					}
					errTst := error(lookupErr)
					if stage != "lookup" {
						errTst = k8serr.NewForbidden(schema.GroupResource{Resource: "secrets"}, "token", errors.New("forbidden"))
						k8sC.PrependReactor(stage, "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
							return fail, nil, errTst
						})
					}
					fail = true
					k8sC.ClearActions()
					assert.ErrorIs(t, c.setK8sUpstream(ctx, svc, owner), errTst)
					assert.ErrorIs(t, c.OnAdd(ctx, old), errTst)
					assert.ErrorIs(t, c.OnUpdate(ctx, svc, old), errTst)
					for _, action := range k8sC.Actions() {
						assert.NotEqual(t, "delete", action.GetVerb())
						if action.GetResource().Resource == "deployments" || action.GetResource().Resource == "services" {
							assert.NotContains(t, []string{"create", "update"}, action.GetVerb())
						}
					}
					current, err := k8sC.AppsV1().Deployments(ns).Get(ctx, name, k8smetav1.GetOptions{})
					if existing {
						assert.Nil(t, err)
						assert.Equal(t, original, current)
						currentProxy, err := k8sC.AppsV1().Deployments(ns).Get(ctx, proxy.Name, k8smetav1.GetOptions{})
						assert.Nil(t, err)
						assert.Equal(t, proxy, currentProxy)
						currentService, err := k8sC.CoreV1().Services(ns).Get(ctx, name, k8smetav1.GetOptions{})
						assert.Nil(t, err)
						assert.Equal(t, service, currentService)
					} else {
						assert.True(t, k8serr.IsNotFound(err), "%+v", err)
						deployments, err := k8sC.AppsV1().Deployments(ns).List(ctx, k8smetav1.ListOptions{})
						assert.Nil(t, err)
						assert.Empty(t, deployments.Items)
						services, err := k8sC.CoreV1().Services(ns).List(ctx, k8smetav1.ListOptions{})
						assert.Nil(t, err)
						assert.Empty(t, services.Items)
					}
					assert.Empty(t, c.serviceLocks)

					fail = false
					assert.Nil(t, c.OnUpdate(ctx, svc, old))
					current, err = k8sC.AppsV1().Deployments(ns).Get(ctx, name, k8smetav1.GetOptions{})
					if !assert.Nil(t, err) {
						return
					}
					assert.Equal(t, "nginx:replacement", current.Spec.Template.Spec.Containers[0].Image)
					env := current.Spec.Template.Spec.Containers[0].Env[0]
					if assert.NotNil(t, env.ValueFrom) {
						assert.Equal(t, fmt.Sprintf("svc-env-%s-%s-uid", svc.Metadata.Uid, cfg.Upstream.GetContainer().Env[0].GetFromSecret()), env.ValueFrom.SecretKeyRef.Name)
						assert.Equal(t, "data", env.ValueFrom.SecretKeyRef.Key)
					}
					assert.Empty(t, c.serviceLocks)
				})
			}
		}
	}
}

func TestK8sUpstreamEnvironmentSecretWatcherRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	tst, err := tests.Initialize(nil)
	if !assert.Nil(t, err, "%+v", err) {
		return
	}
	t.Cleanup(func() { tst.Destroy() })
	realC := tst.C.OcteliumC.CoreC()
	secret, err := realC.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec:     &corev1.Secret_Spec{},
		Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "original"}},
	})
	if !assert.Nil(t, err, "%+v", err) {
		return
	}
	svc := newTstService()
	svc.Metadata = &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8) + ".default"}
	svc.Spec.Config = newTstContainerConfig("default")
	svc.Spec.Config.Upstream.GetContainer().Env = []*corev1.Service_Spec_Config_Upstream_Container_Env{
		{Name: "TOKEN", Type: &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{FromSecret: secret.Metadata.Name}},
	}
	svc, err = realC.CreateService(ctx, svc)
	if !assert.Nil(t, err, "%+v", err) {
		return
	}
	var failLookup atomic.Bool
	failLookup.Store(true)
	var lookups atomic.Int32
	coreC := &fakeSecretCoreC{
		ResourceServiceClient: realC,
		getSecret: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Secret, error) {
			lookups.Add(1)
			if failLookup.Swap(false) {
				return nil, status.Error(codes.Unavailable, "could not get Secret")
			}
			return realC.GetSecret(ctx, in)
		},
	}
	c := NewController(&fakeOcteliumC{coreC: coreC}, tst.C.K8sC)
	created := make(chan struct{}, 1)
	updated := make(chan struct{}, 1)
	var updateFailures atomic.Int32
	watcher, err := watchers.NewWatcher("core", "v1", "Service",
		func(ctx context.Context, item umetav1.ResourceObjectI) error {
			if item.GetMetadata().Uid != svc.Metadata.Uid {
				return nil
			}
			if err := c.OnAdd(ctx, item.(*corev1.Service)); err != nil {
				return err
			}
			created <- struct{}{}
			return nil
		},
		func(ctx context.Context, new, old umetav1.ResourceObjectI) error {
			if new.GetMetadata().Uid != svc.Metadata.Uid {
				return nil
			}
			if err := c.OnUpdate(ctx, new.(*corev1.Service), old.(*corev1.Service)); err != nil {
				updateFailures.Add(1)
				return err
			}
			updated <- struct{}{}
			return nil
		}, nil, realC,
		func() (umetav1.ResourceObjectI, error) { return &corev1.Service{}, nil })
	if !assert.Nil(t, err, "%+v", err) {
		return
	}
	defer watcher.Close()
	assert.Nil(t, watcher.Run(ctx))
	select {
	case <-created:
	case <-ctx.Done():
		assert.Fail(t, "the watcher did not retry the Secret lookup", "%+v", ctx.Err())
		return
	}
	assert.Equal(t, int32(2), lookups.Load())

	var mirrorWrites atomic.Int32
	tst.C.K8sC.(*fakek8s.Clientset).PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if mirrorWrites.Add(1) == 1 {
			return true, nil, k8serr.NewForbidden(schema.GroupResource{Resource: "secrets"}, "token", errors.New("forbidden"))
		}
		return false, nil, nil
	})
	secret.Data.Type = &corev1.Secret_Data_Value{Value: "updated"}
	_, err = realC.UpdateSecret(ctx, secret)
	assert.Nil(t, err, "%+v", err)
	svc.Spec.Config.Upstream.GetContainer().Image = "nginx:replacement"
	_, err = realC.UpdateService(ctx, svc)
	assert.Nil(t, err, "%+v", err)
	select {
	case <-updated:
	case <-ctx.Done():
		assert.Fail(t, "the watcher did not retry the Secret mirror update", "%+v", ctx.Err())
		return
	}
	assert.Equal(t, int32(1), updateFailures.Load())
	assert.Equal(t, int32(2), mirrorWrites.Load())
	dep, err := tst.C.K8sC.AppsV1().Deployments(ns).Get(ctx,
		k8sutils.GetSvcK8sUpstreamHostname(svc, "default"), k8smetav1.GetOptions{})
	if !assert.Nil(t, err) {
		return
	}
	assert.Equal(t, "nginx:replacement", dep.Spec.Template.Spec.Containers[0].Image)
	env := dep.Spec.Template.Spec.Containers[0].Env[0]
	if !assert.NotNil(t, env.ValueFrom) {
		return
	}
	mirror, err := tst.C.K8sC.CoreV1().Secrets(ns).Get(ctx, env.ValueFrom.SecretKeyRef.Name, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.Equal(t, "updated", mirror.StringData["data"])
}

func TestK8sUpstreamCredentialRegistry(t *testing.T) {
	ctx := context.Background()
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		image  string
		server string
		domain string
	}{
		{"TaggedImage", "nginx:latest", "", "docker.io"},
		{"VersionedImage", "nginx:1.27", "", "docker.io"},
		{"DottedImage", "my.app", "", "docker.io"},
		{"DottedTaggedImage", "my.app:1.0", "", "docker.io"},
		{"Digest", "nginx@" + digest, "", "docker.io"},
		{"TaggedDigest", "nginx:latest@" + digest, "", "docker.io"},
		{"LocalhostImage", "localhost", "", "docker.io"},
		{"LocalhostTaggedImage", "localhost:latest", "", "docker.io"},
		{"Namespace", "team/image:latest", "", "docker.io"},
		{"NamespaceDottedImage", "team/my.app:1.0", "", "docker.io"},
		{"NamespaceDigest", "team/image@" + digest, "", "docker.io"},
		{"ShortNamespace", "registry/image:latest", "", "docker.io"},
		{"LocalhostRegistry", "localhost/image:latest", "", "localhost"},
		{"LocalhostRegistryDigest", "localhost/team/image@" + digest, "", "localhost"},
		{"LocalhostRegistryPort", "localhost:5000/team/image:latest", "", "localhost:5000"},
		{"RegistryPort", "registry:5000/team/image:latest", "", "registry:5000"},
		{"RegistryHostname", "registry.example.com/team/image:latest", "", "registry.example.com"},
		{"RegistryHostnamePort", "registry.example.com:5000/team/image@" + digest, "", "registry.example.com:5000"},
		{"IPv4Registry", "192.0.2.1/image:latest", "", "192.0.2.1"},
		{"IPv4RegistryPort", "192.0.2.1:5000/team/image@" + digest, "", "192.0.2.1:5000"},
		{"IPv6Registry", "[::1]/image:latest", "", "[::1]"},
		{"IPv6RegistryPort", "[2001:db8::1]:5000/team/image@" + digest, "", "[2001:db8::1]:5000"},
		{"UppercaseRegistry", "REGISTRY/image:latest", "", "REGISTRY"},
		{"ExplicitDockerHub", "docker.io/library/nginx:latest", "", "docker.io"},
		{"LegacyDockerHub", "index.docker.io/library/nginx:latest", "", "index.docker.io"},
		{"ServerOverride", "nginx:latest", "registry.example.com", "registry.example.com"},
		{"ServerOverrideDigest", "nginx@" + digest, "registry.example.com:5000", "registry.example.com:5000"},
		{"ServerOverrideRegistry", "localhost/image:latest", "registry.example.com", "registry.example.com"},
		{"EmptyImage", "", "", "docker.io"},
	} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/Existing%t", tc.name, existing), func(t *testing.T) {
				c, svc, owner, k8sC := newTstUpstreamController(t)
				cfg := newTstContainerConfig("default")
				spec := cfg.Upstream.GetContainer()
				spec.Image = tc.image
				spec.Credentials = &corev1.Service_Spec_Config_Upstream_Container_Credentials{
					Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_{
						UsernamePassword: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword{
							Username: "user", Server: tc.server,
							Password: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password{
								Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password_FromSecret{FromSecret: "password"},
							},
						},
					},
				}
				name := fmt.Sprintf("regcred-%s-password-uid", svc.Metadata.Uid)
				var original *k8scorev1.Secret
				if existing {
					var err error
					original, err = k8sC.CoreV1().Secrets(ns).Create(ctx, &k8scorev1.Secret{
						ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: ns},
						Type:       k8scorev1.SecretTypeDockerConfigJson,
						StringData: map[string]string{
							".dockerconfigjson": `{"auths":{"obsolete.invalid":{"auth":"b2xkOnBhc3N3b3Jk"}}}`,
						},
					}, k8smetav1.CreateOptions{})
					assert.Nil(t, err)
				}
				for range 2 {
					password, err := c.setK8sUpstreamCredSecret(ctx, svc, cfg, owner)
					if !assert.Nil(t, err) {
						return
					}
					assert.Equal(t, "password-uid", password.Metadata.Uid)
					secret, err := k8sC.CoreV1().Secrets(ns).Get(ctx, name, k8smetav1.GetOptions{})
					if !assert.Nil(t, err) {
						return
					}
					assert.Equal(t, k8scorev1.SecretTypeDockerConfigJson, secret.Type)
					assert.Equal(t, owner.UID, secret.OwnerReferences[0].UID)
					if existing {
						assert.Equal(t, original.UID, secret.UID)
					}
					var config struct {
						Auths map[string]struct{ Auth string } `json:"auths"`
					}
					assert.Nil(t, json.Unmarshal([]byte(secret.StringData[".dockerconfigjson"]), &config))
					assert.Len(t, config.Auths, 1)
					entry, ok := config.Auths[tc.domain]
					assert.True(t, ok, "credentials for %s are missing: %v", tc.domain, config.Auths)
					auth, err := base64.StdEncoding.DecodeString(entry.Auth)
					assert.Nil(t, err)
					assert.Equal(t, "user:value", string(auth))
					dep, err := c.getK8sUpstreamDeployment(ctx, svc, cfg, password, owner)
					if !assert.Nil(t, err) {
						return
					}
					assert.Equal(t, tc.image, dep.Spec.Template.Spec.Containers[0].Image)
					assert.Equal(t, []k8scorev1.LocalObjectReference{{Name: name}}, dep.Spec.Template.Spec.ImagePullSecrets)
				}
			})
		}
	}
}
