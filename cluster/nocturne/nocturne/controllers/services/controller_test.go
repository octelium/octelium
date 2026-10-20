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
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestServiceLock(t *testing.T) {
	c := &Controller{serviceLocks: make(map[string]*serviceLock)}
	svc1 := &corev1.Service{Metadata: &metav1.Metadata{Uid: "svc-1"}}
	svc2 := &corev1.Service{Metadata: &metav1.Metadata{Uid: "svc-2"}}

	unlock := c.lockService(svc1)

	acquiredSame := make(chan func(), 1)
	go func() {
		acquiredSame <- c.lockService(svc1)
	}()

	select {
	case sameUnlock := <-acquiredSame:
		sameUnlock()
		assert.Fail(t, "the same Service lock was acquired concurrently")
	case <-time.After(50 * time.Millisecond):
	}

	acquiredOther := make(chan func(), 1)
	go func() {
		acquiredOther <- c.lockService(svc2)
	}()

	select {
	case otherUnlock := <-acquiredOther:
		otherUnlock()
	case <-time.After(time.Second):
		assert.Fail(t, "a different Service lock was blocked")
	}

	unlock()
	select {
	case sameUnlock := <-acquiredSame:
		sameUnlock()
	case <-time.After(time.Second):
		assert.Fail(t, "the same Service lock was not released")
	}
}

func TestController(t *testing.T) {

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
	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	os.Setenv("OCTELIUM_REGION_NAME", "default")
	defer os.Unsetenv("OCTELIUM_REGION_NAME")

	c := NewController(fakeC.OcteliumC, fakeC.K8sC)
	svc, err := adminSrv.CreateService(ctx, tests.GenService(netw.Metadata.Name))
	assert.Nil(t, err)
	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	err = c.OnAdd(ctx, svcV)
	assert.Nil(t, err)

	err = c.OnAdd(ctx, svcV)
	assert.Nil(t, err)

	rdpReq := tests.GenService(netw.Metadata.Name)
	rdpReq.Spec.Mode = corev1.Service_Spec_RDP_WEB
	rdpReq.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "rdp://localhost",
	}
	rdpSvc, err := adminSrv.CreateService(ctx, rdpReq)
	assert.Nil(t, err)

	rdpPodSpec := c.newPodSpec(rdpSvc)
	assert.Equal(t, 1, len(rdpPodSpec.Containers))
	assert.Equal(t, "vigil", rdpPodSpec.Containers[0].Name)

	err = c.OnDelete(ctx, svcV)
	assert.Nil(t, err)
}

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *fakeOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

type fakeCoreC struct {
	rcorev1.ResourceServiceClient
	getService func(context.Context, *rmetav1.GetOptions) (*corev1.Service, error)
}

func (c *fakeCoreC) GetService(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Service, error) {
	return c.getService(ctx, in)
}

func newTstService() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "svc.default",
			Uid:  "svc-uid",
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Name: "default",
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "http://example.com",
					},
				},
			},
		},
		Status: &corev1.Service_Status{
			Port: 80,
			NamespaceRef: &metav1.ObjectReference{
				Name: "default",
				Uid:  "namespace-uid",
			},
		},
	}
}

func TestServiceReconciliation(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	svc := newTstService()
	k8sC := fakek8s.NewSimpleClientset()
	coreC := &fakeCoreC{
		getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
			assert.Equal(t, svc.Metadata.Uid, in.Uid)
			return proto.Clone(svc).(*corev1.Service), nil
		},
	}
	c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
	hostname := k8sutils.GetSvcHostname(svc)

	assert.Nil(t, c.OnAdd(ctx, svc))
	assert.Nil(t, c.OnAdd(ctx, svc))
	cm, err := k8sC.CoreV1().ConfigMaps(ns).Get(ctx, hostname, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.Equal(t, map[string]string{"uid": svc.Metadata.Uid}, cm.Data)

	oldSvc := proto.Clone(svc).(*corev1.Service)
	svc.Spec.Mode = corev1.Service_Spec_UDP
	svc.Spec.Deployment = &corev1.Service_Spec_Deployment{Replicas: 3}
	svc.Status.Port = 5353

	svcK8s, err := k8sC.CoreV1().Services(ns).Get(ctx, hostname, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	svcK8s.Spec.ClusterIP = "10.0.0.12"
	_, err = k8sC.CoreV1().Services(ns).Update(ctx, svcK8s, k8smetav1.UpdateOptions{})
	assert.Nil(t, err)

	assert.Nil(t, c.OnUpdate(ctx, oldSvc, oldSvc))
	dep, err := k8sC.AppsV1().Deployments(ns).Get(ctx, hostname, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.Equal(t, int32(3), *dep.Spec.Replicas)
	assert.Equal(t, c.getPodLabels(svc), dep.Spec.Selector.MatchLabels)
	assert.Equal(t, dep.Spec.Selector.MatchLabels, dep.Spec.Template.Labels)
	assert.Equal(t, c.getPodAnnotations(svc), dep.Spec.Template.Annotations)
	assert.Equal(t, "ConfigMap", dep.OwnerReferences[0].Kind)
	assert.Equal(t, hostname, dep.OwnerReferences[0].Name)
	assert.True(t, *dep.OwnerReferences[0].Controller)

	svcK8s, err = k8sC.CoreV1().Services(ns).Get(ctx, hostname, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.Equal(t, "10.0.0.12", svcK8s.Spec.ClusterIP)
	assert.Equal(t, k8scorev1.ProtocolUDP, svcK8s.Spec.Ports[0].Protocol)
	assert.Equal(t, int32(5353), svcK8s.Spec.Ports[0].Port)
	assert.Equal(t, int32(5353), svcK8s.Spec.Ports[0].TargetPort.IntVal)
	assert.Equal(t, dep.Spec.Selector.MatchLabels, svcK8s.Spec.Selector)
	assert.Equal(t, dep.OwnerReferences, svcK8s.OwnerReferences)
	assert.Empty(t, c.serviceLocks)

	assert.Nil(t, c.OnDelete(ctx, svc))
	assert.Nil(t, c.OnDelete(ctx, svc))
	_, err = k8sC.CoreV1().ConfigMaps(ns).Get(ctx, hostname, k8smetav1.GetOptions{})
	assert.True(t, k8serr.IsNotFound(err))
}

func TestServiceRegions(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	local := newTstService()
	remote := proto.Clone(local).(*corev1.Service)
	remote.Spec.Region = "other"

	for _, tc := range []struct {
		name string
		old  *corev1.Service
		new  *corev1.Service
	}{
		{"LocalToRemote", local, remote},
		{"RemoteToLocal", remote, local},
		{"RemoteToRemote", remote, remote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k8sC := fakek8s.NewSimpleClientset()
			current := tc.old
			coreC := &fakeCoreC{
				getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
					return proto.Clone(current).(*corev1.Service), nil
				},
			}
			c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
			assert.Nil(t, c.OnAdd(ctx, tc.old))
			current = tc.new
			assert.Nil(t, c.OnUpdate(ctx, tc.new, tc.old))
			cms, err := k8sC.CoreV1().ConfigMaps(ns).List(ctx, k8smetav1.ListOptions{})
			assert.Nil(t, err)
			if tc.new.Spec.Region == "other" {
				assert.Empty(t, cms.Items)
				assert.Nil(t, c.OnUpdate(ctx, tc.new, tc.old))
				k8sC.ClearActions()
				assert.Nil(t, c.OnDelete(ctx, tc.new))
				assert.Empty(t, k8sC.Actions())
			} else {
				assert.Len(t, cms.Items, 1)
			}
			assert.Empty(t, c.serviceLocks)
		})
	}
}

func TestServiceReconciliationErrors(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	svc := newTstService()
	errTst := errors.New("could not reconcile")

	for _, errGet := range []error{status.Error(codes.NotFound, "not found"), errTst} {
		coreC := &fakeCoreC{
			getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
				return nil, errGet
			},
		}
		k8sC := fakek8s.NewSimpleClientset()
		c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
		for _, fn := range []func() error{
			func() error { return c.OnAdd(ctx, svc) },
			func() error { return c.OnUpdate(ctx, svc, svc) },
		} {
			if status.Code(errGet) == codes.NotFound {
				assert.Nil(t, fn())
			} else {
				assert.ErrorIs(t, fn(), errTst)
			}
		}
		assert.Empty(t, k8sC.Actions())
		assert.Empty(t, c.serviceLocks)
	}

	for _, rsc := range []string{"configmaps", "deployments", "services"} {
		t.Run(rsc, func(t *testing.T) {
			k8sC := fakek8s.NewSimpleClientset()
			fail := true
			k8sC.PrependReactor("create", rsc, func(action k8stesting.Action) (bool, runtime.Object, error) {
				return fail, nil, errTst
			})
			coreC := &fakeCoreC{
				getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
					return proto.Clone(svc).(*corev1.Service), nil
				},
			}
			c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
			assert.ErrorIs(t, c.OnAdd(ctx, svc), errTst)
			assert.ErrorIs(t, c.OnUpdate(ctx, svc, svc), errTst)
			fail = false
			assert.Nil(t, c.OnAdd(ctx, svc))
			assert.Empty(t, c.serviceLocks)
		})
	}

	{
		k8sC := fakek8s.NewSimpleClientset()
		k8sC.PrependReactor("delete", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errTst
		})
		remote := proto.Clone(svc).(*corev1.Service)
		remote.Spec.Region = "other"
		coreC := &fakeCoreC{
			getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
				return remote, nil
			},
		}
		c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
		assert.ErrorIs(t, c.OnUpdate(ctx, remote, svc), errTst)
	}
}

func TestServiceLockContention(t *testing.T) {
	c := NewController(nil, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := make(map[string]int)

	for i := range 100 {
		wg.Go(func() {
			svc := newTstService()
			if i%2 == 0 {
				svc.Metadata.Uid = ""
			}
			unlock := c.lockService(svc)
			defer unlock()
			key := svc.Metadata.Uid
			if key == "" {
				key = svc.Metadata.Name
			}
			mu.Lock()
			active[key]++
			assert.Equal(t, 1, active[key])
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			active[key]--
			mu.Unlock()
		})
	}
	wg.Wait()
	assert.Empty(t, c.serviceLocks)
}

func TestVigilPodSpec(t *testing.T) {
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	t.Setenv("OCTELIUM_REGION_UID", "region-uid")
	svc := newTstService()

	for _, tc := range []struct {
		name   string
		enable string
		driver string
		domain string
	}{
		{"Disabled", "false", "custom.csi", "example.com"},
		{"Default", "true", "", ""},
		{"Custom", "true", "custom.csi", "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", tc.enable)
			t.Setenv("OCTELIUM_SPIFFE_CSI_DRIVER", tc.driver)
			t.Setenv("OCTELIUM_SPIFFE_TRUST_DOMAIN", tc.domain)
			c := NewController(nil, nil)
			pod := c.newPodSpec(svc)
			assert.Equal(t, map[string]string{"octelium.com/node-mode-dataplane": ""}, pod.NodeSelector)
			assert.Equal(t, "net.ipv4.ip_unprivileged_port_start", pod.SecurityContext.Sysctls[0].Name)
			assert.Equal(t, "1", pod.SecurityContext.Sysctls[0].Value)
			assert.Len(t, pod.Containers, 1)
			container := pod.Containers[0]
			assert.Equal(t, "vigil", container.Name)
			assert.NotEmpty(t, container.Image)
			assert.False(t, *container.SecurityContext.Privileged)
			assert.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
			assert.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
			assert.Equal(t, []k8scorev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
			assert.Equal(t, []k8scorev1.Capability{"NET_BIND_SERVICE"}, container.SecurityContext.Capabilities.Add)
			assert.Equal(t, getDefaultRequests(), container.Resources.Requests)
			assert.Equal(t, getDefaultLimits(), container.Resources.Limits)
			assert.Equal(t, int32(vutils.HealthCheckPortVigil), container.LivenessProbe.GRPC.Port)
			env := make(map[string]k8scorev1.EnvVar)
			for _, e := range container.Env {
				env[e.Name] = e
			}
			assert.Equal(t, svc.Metadata.Uid, env["OCTELIUM_SVC_UID"].Value)
			assert.Equal(t, svc.Metadata.Name, env["OCTELIUM_SVC_NAME"].Value)
			assert.Equal(t, "default", env["OCTELIUM_REGION_NAME"].Value)
			assert.Equal(t, "region-uid", env["OCTELIUM_REGION_UID"].Value)
			assert.Equal(t, "metadata.uid", env["OCTELIUM_POD_UID"].ValueFrom.FieldRef.FieldPath)
			assert.Equal(t, "metadata.name", env["OCTELIUM_POD_NAME"].ValueFrom.FieldRef.FieldPath)
			if tc.enable == "true" {
				assert.Equal(t, "true", env["OCTELIUM_ENABLE_SPIFFE_CSI"].Value)
				assert.Equal(t, tc.driver, env["OCTELIUM_SPIFFE_CSI_DRIVER"].Value)
				assert.Equal(t, tc.domain, env["OCTELIUM_SPIFFE_TRUST_DOMAIN"].Value)
				assert.Len(t, pod.Volumes, 1)
				assert.Equal(t, k8sutils.GetSPIFFEVolume(tc.driver), pod.Volumes[0])
				assert.Equal(t, []k8scorev1.VolumeMount{k8sutils.GetSPIFFEVolumeMount()}, container.VolumeMounts)
			} else {
				assert.Empty(t, pod.Volumes)
				assert.Empty(t, container.VolumeMounts)
				assert.NotContains(t, env, "OCTELIUM_ENABLE_SPIFFE_CSI")
			}
		})
	}
}

func TestManagedServicePodSpec(t *testing.T) {
	for _, tc := range []struct {
		name    string
		managed *corev1.Service_Status_ManagedService
		count   int
		port    int32
	}{
		{"Vigil", &corev1.Service_Status_ManagedService{Type: "vigil", Image: "registry/vigil:v1"}, 1, int32(vutils.HealthCheckPortVigil)},
		{"NoImage", &corev1.Service_Status_ManagedService{Type: "portal"}, 1, int32(vutils.HealthCheckPortVigil)},
		{"API", &corev1.Service_Status_ManagedService{Type: "apiserver", Image: "registry/api:v1"}, 2, int32(vutils.HealthCheckPortManagedService)},
		{"Auth", &corev1.Service_Status_ManagedService{Type: "authserver", Image: "registry/auth:v1"}, 2, int32(vutils.HealthCheckPortManagedService)},
		{"DNS", &corev1.Service_Status_ManagedService{Type: "dnsserver", Image: "registry/dns:v1"}, 2, int32(vutils.HealthCheckPortManagedService)},
		{"Portal", &corev1.Service_Status_ManagedService{Type: "portal", Image: "registry/portal:v1"}, 2, 0},
		{"CustomProbe", &corev1.Service_Status_ManagedService{
			Type: "custom", Image: "registry/custom:v1",
			HealthCheck: &corev1.Service_Status_ManagedService_HealthCheck{
				Type: &corev1.Service_Status_ManagedService_HealthCheck_Grpc{
					Grpc: &corev1.Service_Status_ManagedService_HealthCheck_GRPC{Port: 12345},
				},
			},
		}, 2, 12345},
		{"DefaultProbe", &corev1.Service_Status_ManagedService{
			Type: "custom", Image: "registry/custom:v1",
			HealthCheck: &corev1.Service_Status_ManagedService_HealthCheck{
				Type: &corev1.Service_Status_ManagedService_HealthCheck_Grpc{
					Grpc: &corev1.Service_Status_ManagedService_HealthCheck_GRPC{},
				},
			},
		}, 2, int32(vutils.HealthCheckPortManagedService)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewController(nil, nil)
			svc := newTstService()
			svc.Status.ManagedService = proto.Clone(tc.managed).(*corev1.Service_Status_ManagedService)
			svc.Status.ManagedService.ImagePullSecret = "registry-secret"
			svc.Status.ManagedService.Command = []string{"/bin/app"}
			svc.Status.ManagedService.Args = []string{"--serve"}
			svc.Status.ManagedService.ReadOnlyFileSystem = true
			pod := c.newPodSpec(svc)
			assert.Len(t, pod.Containers, tc.count)
			assert.Equal(t, []k8scorev1.LocalObjectReference{{Name: "registry-secret"}}, pod.ImagePullSecrets)
			container := pod.Containers[tc.count-1]
			if tc.managed.Image != "" {
				assert.Equal(t, tc.managed.Image, container.Image)
			}
			if tc.port > 0 {
				assert.Equal(t, tc.port, container.LivenessProbe.GRPC.Port)
			} else {
				assert.Nil(t, container.LivenessProbe)
			}
			if tc.count == 2 {
				assert.Equal(t, "managed", container.Name)
				assert.Equal(t, svc.Status.ManagedService.Command, container.Command)
				assert.Equal(t, svc.Status.ManagedService.Args, container.Args)
				assert.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
				assert.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
				assert.Equal(t, k8sutils.GetDefaultLimits(), container.Resources.Limits)
				svc.Status.ManagedService.ReadOnlyFileSystem = false
				assert.Nil(t, c.newPodSpec(svc).Containers[1].SecurityContext.ReadOnlyRootFilesystem)
			}
		})
	}
}

func TestManagedServiceResources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits *corev1.Service_Status_ManagedService_ResourceLimit
		memory int64
		cpu    int64
	}{
		{"Empty", &corev1.Service_Status_ManagedService_ResourceLimit{}, int64(k8sutils.DefaultLimitMemoryMegabytes), int64(k8sutils.DefaultLimitCPUMillicores)},
		{"Zero", &corev1.Service_Status_ManagedService_ResourceLimit{
			Memory: &corev1.Service_Status_ManagedService_ResourceLimit_Memory{},
			Cpu:    &corev1.Service_Status_ManagedService_ResourceLimit_CPU{},
		}, int64(k8sutils.DefaultLimitMemoryMegabytes), int64(k8sutils.DefaultLimitCPUMillicores)},
		{"Custom", &corev1.Service_Status_ManagedService_ResourceLimit{
			Memory: &corev1.Service_Status_ManagedService_ResourceLimit_Memory{Megabytes: 256},
			Cpu:    &corev1.Service_Status_ManagedService_ResourceLimit_CPU{Millicores: 500},
		}, 256, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "true")
			c := NewController(nil, nil)
			svc := newTstService()
			svc.Status.ManagedService = &corev1.Service_Status_ManagedService{
				Image:         "registry/app:v1",
				ResourceLimit: tc.limits,
				K8SLabels:     map[string]string{"custom-label": "custom-value"},
			}
			container := c.newPodSpec(svc).Containers[1]
			memory := container.Resources.Limits.Memory()
			cpu := container.Resources.Limits.Cpu()
			assert.Equal(t, tc.memory*1024*1024, memory.Value())
			assert.Equal(t, tc.cpu, cpu.MilliValue())
			assert.Equal(t, resource.MustParse("5Mi"), container.Resources.Requests[k8scorev1.ResourceMemory])
			assert.Equal(t, []k8scorev1.VolumeMount{k8sutils.GetSPIFFEVolumeMount()}, container.VolumeMounts)
			assert.Contains(t, container.Env, k8scorev1.EnvVar{Name: "OCTELIUM_ENABLE_SPIFFE_CSI", Value: "true"})
			assert.Equal(t, "custom-value", c.getPodLabels(svc)["custom-label"])
		})
	}
}

func TestPodAnnotations(t *testing.T) {
	c := NewController(nil, nil)
	svc := newTstService()
	before := c.getPodAnnotations(svc)
	assert.Equal(t, "octelium/octelium", before["k8s.v1.cni.cncf.io/networks"])
	assert.Empty(t, before["octelium.com/svc-upgrade-uid"])
	assert.Equal(t, before, c.getPodAnnotations(svc))

	for _, tc := range []struct {
		name string
		fn   func(*corev1.Service)
	}{
		{"Port", func(svc *corev1.Service) { svc.Status.Port = 8080 }},
		{"Mode", func(svc *corev1.Service) { svc.Spec.Mode = corev1.Service_Spec_TCP }},
		{"TLS", func(svc *corev1.Service) { svc.Spec.IsTLS = true }},
		{"HTTP2", func(svc *corev1.Service) {
			svc.Spec.Config.Type = &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{ListenHTTP2: true},
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updated := proto.Clone(svc).(*corev1.Service)
			tc.fn(updated)
			assert.NotEqual(t, before["octelium.com/svc-deployment-id"], c.getPodAnnotations(updated)["octelium.com/svc-deployment-id"])
		})
	}

	svc.Metadata.DisplayName = "new display name"
	svc.Spec.IsDisabled = true
	svc.Metadata.SystemLabels = map[string]string{vutils.UpgradeIDKey: "upgrade-uid"}
	after := c.getPodAnnotations(svc)
	assert.Equal(t, before["octelium.com/svc-deployment-id"], after["octelium.com/svc-deployment-id"])
	assert.Equal(t, "upgrade-uid", after["octelium.com/svc-upgrade-uid"])
}

func TestConcurrentServiceReconciliation(t *testing.T) {
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	ctx := context.Background()
	svc := newTstService()
	svc.Spec.Deployment = &corev1.Service_Spec_Deployment{Replicas: 3}
	svc.Status.Port = 8080
	stale := proto.Clone(svc).(*corev1.Service)
	stale.Spec.Deployment.Replicas = 1
	stale.Status.Port = 80
	coreC := &fakeCoreC{
		getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
			return proto.Clone(svc).(*corev1.Service), nil
		},
	}
	k8sC := fakek8s.NewSimpleClientset()
	c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			if i%2 == 0 {
				assert.Nil(t, c.OnAdd(ctx, stale))
			} else {
				assert.Nil(t, c.OnUpdate(ctx, stale, stale))
			}
		})
	}
	wg.Wait()
	deps, err := k8sC.AppsV1().Deployments(ns).List(ctx, k8smetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Len(t, deps.Items, 1)
	assert.Equal(t, int32(3), *deps.Items[0].Spec.Replicas)
	services, err := k8sC.CoreV1().Services(ns).List(ctx, k8smetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Len(t, services.Items, 1)
	assert.Equal(t, int32(8080), services.Items[0].Spec.Ports[0].Port)
	cms, err := k8sC.CoreV1().ConfigMaps(ns).List(ctx, k8smetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Len(t, cms.Items, 1)
	assert.Empty(t, c.serviceLocks)
}

func TestServiceDeleteErrors(t *testing.T) {
	ctx := context.Background()
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	errConfigMap := k8serr.NewServiceUnavailable("could not delete ConfigMap")
	errSession := status.Error(codes.Unavailable, "could not remove Session upstream")

	for _, tc := range []struct {
		name             string
		configMapErr     error
		missingConfigMap bool
		sessionError     string
	}{
		{"Success", nil, false, ""},
		{"ConfigMapNotFound", nil, true, ""},
		{"ConfigMapUnavailable", errConfigMap, false, ""},
		{"ConfigMapForbidden", k8serr.NewForbidden(k8scorev1.Resource("configmaps"), "svc", errors.New("forbidden")), false, ""},
		{"ConfigMapCancelled", context.Canceled, false, ""},
		{"ConfigMapDeadlineExceeded", context.DeadlineExceeded, false, ""},
		{"ListSession", nil, false, "list"},
		{"GetSession", nil, false, "get"},
		{"UpdateSession", nil, false, "update"},
		{"ConfigMapAndListSession", errConfigMap, false, "list"},
		{"ConfigMapAndGetSession", errConfigMap, false, "get"},
		{"ConfigMapAndUpdateSession", errConfigMap, false, "update"},
		{"ConfigMapNotFoundAndSessionError", nil, true, "update"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, sess := newTstUpstreamSession()
			sess.Status.Connection.Upstreams = append(sess.Status.Connection.Upstreams,
				&corev1.Session_Status_Connection_Upstream{
					ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid}, Port: 20001,
				})
			other := proto.Clone(sess.Status.Connection.Upstreams[0]).(*corev1.Session_Status_Connection_Upstream)
			fail := true
			var lists int
			coreC := &fakeSessionCoreC{
				listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
					lists++
					if fail && tc.sessionError == "list" {
						return nil, errSession
					}
					return &corev1.SessionList{Items: []*corev1.Session{proto.Clone(sess).(*corev1.Session)}}, nil
				},
				getSession: func(in *rmetav1.GetOptions) (*corev1.Session, error) {
					assert.Equal(t, sess.Metadata.Uid, in.Uid)
					if fail && tc.sessionError == "get" {
						return nil, errSession
					}
					return proto.Clone(sess).(*corev1.Session), nil
				},
				updateSession: func(in *corev1.Session) (*corev1.Session, error) {
					if fail && tc.sessionError == "update" {
						return nil, errSession
					}
					sess = proto.Clone(in).(*corev1.Session)
					return in, nil
				},
			}
			unrelated := &k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: "other", Namespace: ns}}
			k8sC := fakek8s.NewSimpleClientset(unrelated)
			c := NewController(&fakeOcteliumC{coreC: coreC}, k8sC)
			cm := c.getOwnerConfigMap(svc)
			if !tc.missingConfigMap {
				_, err := k8sC.CoreV1().ConfigMaps(ns).Create(ctx, cm, k8smetav1.CreateOptions{})
				assert.Nil(t, err)
			}
			k8sC.PrependReactor("delete", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
				assert.Equal(t, ns, action.GetNamespace())
				assert.Equal(t, cm.Name, action.(k8stesting.DeleteAction).GetName())
				if fail && tc.configMapErr != nil {
					return true, nil, tc.configMapErr
				}
				return false, nil, nil
			})

			err := c.OnDelete(ctx, svc)
			if tc.configMapErr == nil && tc.sessionError == "" {
				assert.Nil(t, err)
			}
			if tc.configMapErr != nil {
				assert.ErrorIs(t, err, tc.configMapErr)
			}
			if tc.sessionError != "" {
				assert.ErrorIs(t, err, errSession)
			}
			assert.Equal(t, 1, lists)
			assert.Equal(t, tc.sessionError != "", sessionHasUpstreamForSvc(sess, svc))
			_, err = k8sC.CoreV1().ConfigMaps(ns).Get(ctx, cm.Name, k8smetav1.GetOptions{})
			if tc.configMapErr != nil {
				assert.Nil(t, err)
			} else {
				assert.True(t, k8serr.IsNotFound(err), "%+v", err)
			}
			assert.Empty(t, c.serviceLocks)

			fail = false
			assert.Nil(t, c.OnDelete(ctx, svc))
			assert.Nil(t, c.OnDelete(ctx, svc))
			assert.Equal(t, 3, lists)
			assert.False(t, sessionHasUpstreamForSvc(sess, svc))
			if assert.Len(t, sess.Status.Connection.Upstreams, 1) {
				assert.True(t, proto.Equal(other, sess.Status.Connection.Upstreams[0]))
			}
			_, err = k8sC.CoreV1().ConfigMaps(ns).Get(ctx, cm.Name, k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err), "%+v", err)
			ret, err := k8sC.CoreV1().ConfigMaps(ns).Get(ctx, unrelated.Name, k8smetav1.GetOptions{})
			assert.Nil(t, err)
			assert.Equal(t, unrelated, ret)
			assert.Empty(t, c.serviceLocks)
		})
	}
}

func TestServiceDeleteWatcherRetry(t *testing.T) {
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() { tst.Destroy() })
	realC := tst.C.OcteliumC.CoreC()

	for _, tc := range []struct {
		name    string
		deleted bool
	}{
		{"Unavailable", false},
		{"DeletedBeforeError", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			svc, sess := newTstUpstreamSession()
			svc.Metadata.Name = utilrand.GetRandomStringCanonical(8) + ".default"
			svc.Metadata.Uid = ""
			svc, err := realC.CreateService(ctx, svc)
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			sess.Metadata = &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)}
			sess, err = realC.CreateSession(ctx, sess)
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			defer realC.DeleteSession(ctx, &rmetav1.DeleteOptions{Uid: sess.Metadata.Uid})
			k8sC := fakek8s.NewSimpleClientset()
			c := NewController(tst.C.OcteliumC, k8sC)
			if !assert.Nil(t, c.OnAdd(ctx, svc)) {
				return
			}
			current, err := realC.GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, sessionHasUpstreamForSvc(current, svc))

			cm := c.getOwnerConfigMap(svc)
			var attempts atomic.Int32
			k8sC.PrependReactor("delete", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
				assert.Equal(t, cm.Name, action.(k8stesting.DeleteAction).GetName())
				if attempts.Add(1) == 1 {
					if tc.deleted {
						err := k8sC.Tracker().Delete(k8scorev1.SchemeGroupVersion.WithResource("configmaps"), ns, cm.Name)
						assert.Nil(t, err)
					}
					return true, nil, k8serr.NewServiceUnavailable("could not delete ConfigMap")
				}
				return false, nil, nil
			})
			ready := make(chan struct{}, 1)
			done := make(chan struct{}, 1)
			watcher, err := watchers.NewWatcher("core", "v1", "Service",
				func(ctx context.Context, item umetav1.ResourceObjectI) error {
					if item.GetMetadata().Uid == svc.Metadata.Uid {
						select {
						case ready <- struct{}{}:
						default:
						}
					}
					return nil
				}, nil,
				func(ctx context.Context, item umetav1.ResourceObjectI) error {
					if item.GetMetadata().Uid != svc.Metadata.Uid {
						return nil
					}
					if err := c.OnDelete(ctx, item.(*corev1.Service)); err != nil {
						return err
					}
					done <- struct{}{}
					return nil
				}, realC,
				func() (umetav1.ResourceObjectI, error) { return &corev1.Service{}, nil })
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			defer watcher.Close()
			assert.Nil(t, watcher.Run(ctx))
			select {
			case <-ready:
			case <-ctx.Done():
				assert.Fail(t, "the watcher did not observe the Service", "%+v", ctx.Err())
				return
			}

			_, err = realC.DeleteService(ctx, &rmetav1.DeleteOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err, "%+v", err)
			select {
			case <-done:
			case <-ctx.Done():
				assert.Fail(t, "the watcher did not retry the failed Service deletion", "%+v", ctx.Err())
				return
			}
			assert.Equal(t, int32(2), attempts.Load())
			_, err = k8sC.CoreV1().ConfigMaps(ns).Get(ctx, cm.Name, k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err), "%+v", err)
			current, err = realC.GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
			assert.Nil(t, err, "%+v", err)
			assert.False(t, sessionHasUpstreamForSvc(current, svc))
			if assert.Len(t, current.Status.Connection.Upstreams, 1) {
				assert.True(t, proto.Equal(sess.Status.Connection.Upstreams[0], current.Status.Connection.Upstreams[0]))
			}
		})
	}
}
