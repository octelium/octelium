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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	k8scorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
