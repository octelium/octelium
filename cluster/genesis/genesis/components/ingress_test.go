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

package components

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"
)

func ingressOpts(o *CommonOpts) *CommonOpts {
	o.Region = &corev1.Region{}
	return o
}

func TestIngressEnvoyBootstrapValidation(t *testing.T) {
	binary := os.Getenv("OCTELIUM_TEST_ENVOY_PATH")
	if binary == "" {
		var err error
		binary, err = exec.LookPath("envoy")
		if err != nil {
			t.Skip("Envoy is not installed")
		}
	}
	for _, spiffe := range []bool{false, true} {
		t.Run(fmt.Sprint(spiffe), func(t *testing.T) {
			cfg := getEnvoyIngressDataPlaneConfig(optsWithInstallation(spiffeInstallation(spiffe, "", "")))
			file := filepath.Join(t.TempDir(), "envoy.yaml")
			require.Nil(t, os.WriteFile(file, []byte(cfg), 0600))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, binary, "--mode", "validate", "--disable-hot-restart", "-l", "warning", "-c", file).CombinedOutput()
			assert.Nil(t, err, "%s", output)
			assert.NotContains(t, strings.ToLower(string(output)), "deprecated", "%s", output)
		})
	}
}

func TestIngressEnvoyBootstrapDiscovery(t *testing.T) {
	for _, spiffe := range []bool{false, true} {
		t.Run(fmt.Sprint(spiffe), func(t *testing.T) {
			var cfg map[string]any
			require.Nil(t, yaml.Unmarshal([]byte(getEnvoyIngressDataPlaneConfig(optsWithInstallation(spiffeInstallation(spiffe, "", "")))), &cfg))
			assert.Equal(t, map[string]any{"cluster": "octelium", "id": "octelium-ingress"}, cfg["node"])
			admin := cfg["admin"].(map[string]any)["address"].(map[string]any)["socket_address"].(map[string]any)
			assert.Equal(t, "127.0.0.1", admin["address"])
			assert.Equal(t, float64(11011), admin["port_value"])
			for _, name := range []string{"lds_config", "cds_config"} {
				source := cfg["dynamic_resources"].(map[string]any)[name].(map[string]any)
				assert.Equal(t, "V3", source["resource_api_version"])
				api := source["api_config_source"].(map[string]any)
				assert.Equal(t, "GRPC", api["api_type"])
				assert.Equal(t, "V3", api["transport_api_version"])
				assert.Equal(t, []any{map[string]any{"envoy_grpc": map[string]any{"cluster_name": "xds_cluster"}}}, api["grpc_services"])
			}
			clusters := cfg["static_resources"].(map[string]any)["clusters"].([]any)
			if spiffe {
				require.Len(t, clusters, 2)
			} else {
				require.Len(t, clusters, 1)
			}
			for _, item := range clusters {
				cluster := item.(map[string]any)
				assert.Equal(t, "3s", cluster["connect_timeout"])
				http := cluster["typed_extension_protocol_options"].(map[string]any)["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].(map[string]any)
				assert.Equal(t, "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions", http["@type"])
				assert.Equal(t, map[string]any{"http2_protocol_options": map[string]any{}}, http["explicit_http_config"])
				if cluster["name"] == "xds_cluster" {
					assert.NotContains(t, cluster, "type")
					assert.Equal(t, map[string]any{"name": "envoy.clusters.dns", "typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.clusters.dns.v3.DnsCluster"}}, cluster["cluster_type"])
					if spiffe {
						require.Contains(t, cluster, "transport_socket")
						tls := cluster["transport_socket"].(map[string]any)["typed_config"].(map[string]any)["common_tls_context"].(map[string]any)
						assert.Equal(t, []any{"h2"}, tls["alpn_protocols"])
						assert.Contains(t, tls, "tls_certificate_sds_secret_configs")
						assert.Contains(t, tls, "validation_context_sds_secret_config")
					} else {
						assert.NotContains(t, cluster, "transport_socket")
					}
				} else {
					assert.Equal(t, "spire_agent", cluster["name"])
					assert.Equal(t, "STATIC", cluster["type"])
				}
			}
		})
	}
}

func TestIngressDataPlaneServiceConfiguration(t *testing.T) {
	for _, frontProxy := range []bool{false, true} {
		for _, tc := range []struct {
			name string
			data string
			want []string
		}{
			{"Missing", "", nil},
			{"InvalidJSON", "invalid", nil},
			{"WrongType", `{"ip":"203.0.113.1"}`, nil},
			{"Empty", `[]`, []string{}},
			{"DualStack", `["203.0.113.1","2001:db8::1"]`, []string{"203.0.113.1", "2001:db8::1"}},
		} {
			t.Run(fmt.Sprintf("%t/%s", frontProxy, tc.name), func(t *testing.T) {
				o := optsWithInstallation(&corev1.ClusterConfig_Status_Installation{Ingress: &corev1.ClusterConfig_Status_Installation_Ingress{
					FrontProxy: &corev1.ClusterConfig_Status_Installation_Ingress_FrontProxy{Enable: frontProxy},
				}})
				o.Region = &corev1.Region{Metadata: &metav1.Metadata{Name: "default"}}
				if tc.data != "" {
					o.Region.Metadata.SystemLabels = map[string]string{"external-ips": tc.data}
				}
				svc := getIngressDataPlaneService(o)
				assert.Equal(t, k8scorev1.ServiceTypeLoadBalancer, svc.Spec.Type)
				assert.Equal(t, tc.want, svc.Spec.ExternalIPs)
				assert.Equal(t, getComponentLabels(componentIngressDataPlane), svc.Spec.Selector)
				require.Len(t, svc.Spec.Ports, 1)
				assert.Equal(t, int32(8080), svc.Spec.Ports[0].TargetPort.IntVal)
				if frontProxy {
					assert.Equal(t, int32(8080), svc.Spec.Ports[0].Port)
				} else {
					assert.Equal(t, int32(443), svc.Spec.Ports[0].Port)
				}
			})
		}
	}
}

func TestIngressEnvoyDeploymentConfiguration(t *testing.T) {
	for _, dev := range []bool{false, true} {
		t.Run(fmt.Sprint(dev), func(t *testing.T) {
			t.Setenv("OCTELIUM_DEV", fmt.Sprint(dev))
			t.Setenv("OCTELIUM_PRODUCTION", "true")
			o := ingressOpts(optsWithInstallation(nil))
			dep := getIngressDataPlaneDeployment(o)
			spec := dep.Spec.Template.Spec
			require.NotNil(t, spec.AutomountServiceAccountToken)
			assert.False(t, *spec.AutomountServiceAccountToken)
			require.Len(t, spec.Containers, 1)
			container := spec.Containers[0]
			assert.Equal(t, "envoyproxy/envoy:v1.40.0", container.Image)
			assert.Equal(t, []string{"envoy"}, container.Command)
			if dev {
				assert.Equal(t, []string{"-c", "/etc/envoy/envoy.yaml", "-l", "debug"}, container.Args)
			} else {
				assert.Equal(t, []string{"-c", "/etc/envoy/envoy.yaml"}, container.Args)
			}
			assert.True(t, container.VolumeMounts[0].ReadOnly)
			assert.Equal(t, "config", container.VolumeMounts[0].SubPath)
			assert.Equal(t, "/ready", container.LivenessProbe.HTTPGet.Path)
			assert.Equal(t, int32(11012), container.LivenessProbe.HTTPGet.Port.IntVal)
			assert.Equal(t, int32(4), container.LivenessProbe.TimeoutSeconds)
			assert.True(t, *container.SecurityContext.RunAsNonRoot)
			assert.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
			assert.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
			assert.False(t, *container.SecurityContext.Privileged)
		})
	}
}

func TestCreateIngressReconciliation(t *testing.T) {
	ctx := context.Background()
	o := optsWithInstallation(nil)
	o.Region = &corev1.Region{Metadata: &metav1.Metadata{Name: "default"}}
	o.K8sC = fake.NewClientset()
	for range 2 {
		require.Nil(t, CreateIngress(ctx, o))
	}
	cm, err := o.K8sC.CoreV1().ConfigMaps(ns).Get(ctx, "ingress-dataplane-envoy-config", k8smetav1.GetOptions{})
	require.Nil(t, err)
	assert.Equal(t, getEnvoyIngressDataPlaneConfig(o), cm.Data["config"])
	deployments, err := o.K8sC.AppsV1().Deployments(ns).List(ctx, k8smetav1.ListOptions{})
	require.Nil(t, err)
	assert.Len(t, deployments.Items, 2)
	services, err := o.K8sC.CoreV1().Services(ns).List(ctx, k8smetav1.ListOptions{})
	require.Nil(t, err)
	assert.Len(t, services.Items, 2)
	policies, err := o.K8sC.NetworkingV1().NetworkPolicies(ns).List(ctx, k8smetav1.ListOptions{})
	require.Nil(t, err)
	require.Len(t, policies.Items, 1)
	assert.Equal(t, int32(8080), policies.Items[0].Spec.Ingress[0].Ports[0].Port.IntVal)
}

func TestCreateIngressErrors(t *testing.T) {
	for _, tc := range []struct {
		resource string
		name     string
	}{
		{"configmaps", "ingress-dataplane-envoy-config"},
		{"deployments", getComponentName(componentIngressDataPlane)},
		{"services", getComponentName(componentIngressDataPlane)},
		{"deployments", getComponentName(componentIngress)},
		{"services", getComponentName(componentIngress)},
		{"networkpolicies", getComponentName(componentIngress)},
	} {
		for _, verb := range []string{"create", "update"} {
			t.Run(tc.resource+"/"+tc.name+"/"+verb, func(t *testing.T) {
				c := fake.NewClientset()
				o := optsWithInstallation(nil)
				o.Region = &corev1.Region{Metadata: &metav1.Metadata{Name: "default"}}
				o.K8sC = c
				if verb == "update" {
					require.Nil(t, CreateIngress(t.Context(), o))
				}
			want := fmt.Errorf("could not %s %s", verb, tc.name)
				c.PrependReactor(verb, tc.resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
					var obj runtime.Object
					if verb == "create" {
						obj = action.(k8stesting.CreateAction).GetObject()
					} else {
						obj = action.(k8stesting.UpdateAction).GetObject()
					}
					if obj.(k8smetav1.Object).GetName() == tc.name {
						return true, nil, want
					}
					return false, nil, nil
				})
				assert.ErrorIs(t, CreateIngress(t.Context(), o), want)
			})
		}
	}
}

func volumeNames(volumes []k8scorev1.Volume) []string {
	var ret []string
	for _, itm := range volumes {
		ret = append(ret, itm.Name)
	}
	return ret
}

func volumeMountPaths(mounts []k8scorev1.VolumeMount) []string {
	var ret []string
	for _, itm := range mounts {
		ret = append(ret, itm.MountPath)
	}
	return ret
}

func TestGetEnvoyIngressDataPlaneConfig(t *testing.T) {
	t.Run("a Cluster without SPIFFE keeps the config it already has", func(t *testing.T) {
		for _, o := range []*CommonOpts{
			nil,
			{},
			{ClusterConfig: &corev1.ClusterConfig{}},
			optsWithInstallation(nil),
			optsWithInstallation(&corev1.ClusterConfig_Status_Installation{}),
			optsWithInstallation(spiffeInstallation(false, "", "octelium.local")),
		} {
			assert.Equal(t, envoyGatewayConfigTemplate, getEnvoyIngressDataPlaneConfig(o))
		}
	})

	t.Run("a Cluster with SPIFFE reaches the control plane over the SPIRE Agent",
		func(t *testing.T) {
			config := getEnvoyIngressDataPlaneConfig(optsWithInstallation(
				spiffeInstallation(true, "", "octelium.local")))

			assert.Equal(t, envoyGatewayConfigTemplateSPIFFE, config)

			assert.Contains(t, config, "cluster_name: spire_agent")
			assert.Contains(t, config, "path: /run/spire/sockets/spire-agent.sock")
			assert.Contains(t, config,
				"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext")
			assert.Contains(t, config, "tls_certificate_sds_secret_configs")
			assert.Contains(t, config, "validation_context_sds_secret_config")
			assert.Contains(t, config, "name: default")
			assert.Contains(t, config, "name: ROOTCA")
			assert.Contains(t, config, "- h2")
		})

	t.Run("both configs point the xds cluster at the ingress control plane",
		func(t *testing.T) {
			for _, config := range []string{
				envoyGatewayConfigTemplate,
				envoyGatewayConfigTemplateSPIFFE,
			} {
				assert.Contains(t, config, "address: octelium-ingress.octelium.svc")
				assert.Contains(t, config, "port_value: 8080")
				assert.Contains(t, config, "id: octelium-ingress")
			}
		})
}

func TestGetEnvoyIngressDataPlaneConfigMap(t *testing.T) {

	cm := getEnvoyIngressDataPlaneConfigMap(optsWithInstallation(
		spiffeInstallation(false, "", "")))

	assert.Equal(t, "ingress-dataplane-envoy-config", cm.Name)
	assert.Equal(t, vutils.K8sNS, cm.Namespace)
	assert.Equal(t, envoyGatewayConfigTemplate, cm.Data["config"])

	cm = getEnvoyIngressDataPlaneConfigMap(optsWithInstallation(
		spiffeInstallation(true, "", "")))

	assert.Equal(t, envoyGatewayConfigTemplateSPIFFE, cm.Data["config"])
}

func TestGetIngressDataPlaneDeployment(t *testing.T) {
	t.Run("a Cluster without SPIFFE mounts nothing but its own config", func(t *testing.T) {
		dep := getIngressDataPlaneDeployment(ingressOpts(optsWithInstallation(
			spiffeInstallation(false, "", ""))))

		spec := dep.Spec.Template.Spec

		assert.Equal(t, []string{"envoy-config"}, volumeNames(spec.Volumes))
		assert.Equal(t, []string{"/etc/envoy/envoy.yaml"},
			volumeMountPaths(spec.Containers[0].VolumeMounts))

		assert.Equal(t,
			vutils.Sha256SumHex([]byte(envoyGatewayConfigTemplate)),
			dep.Spec.Template.Annotations["octelium.com/envoy-config-hash"])
	})

	t.Run("a Cluster with SPIFFE mounts the Workload API socket", func(t *testing.T) {
		dep := getIngressDataPlaneDeployment(ingressOpts(optsWithInstallation(
			spiffeInstallation(true, "csi.example.com", ""))))

		spec := dep.Spec.Template.Spec

		assert.Equal(t, []string{"envoy-config", "spiffe-agent"}, volumeNames(spec.Volumes))
		assert.NotNil(t, spec.Volumes[1].CSI)
		assert.Equal(t, "csi.example.com", spec.Volumes[1].CSI.Driver)

		assert.Equal(t, []string{"/etc/envoy/envoy.yaml", "/run/spire/sockets"},
			volumeMountPaths(spec.Containers[0].VolumeMounts))

		assert.Equal(t,
			vutils.Sha256SumHex([]byte(envoyGatewayConfigTemplateSPIFFE)),
			dep.Spec.Template.Annotations["octelium.com/envoy-config-hash"])
	})

	t.Run("the Envoy container is restarted whenever its config changes", func(t *testing.T) {
		without := getIngressDataPlaneDeployment(ingressOpts(optsWithInstallation(
			spiffeInstallation(false, "", ""))))
		with := getIngressDataPlaneDeployment(ingressOpts(optsWithInstallation(
			spiffeInstallation(true, "", ""))))

		assert.NotEqual(t,
			without.Spec.Template.Annotations["octelium.com/envoy-config-hash"],
			with.Spec.Template.Annotations["octelium.com/envoy-config-hash"])
	})
}
