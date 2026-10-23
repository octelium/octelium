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

package suite

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func serviceAddrs(svc *corev1.Service, qtype uint16) []string {
	var ret []string
	for _, addr := range svc.Status.Addresses {
		if addr.DualStackIP == nil {
			continue
		}
		switch qtype {
		case dns.TypeA:
			if addr.DualStackIP.Ipv4 != "" {
				ret = append(ret, addr.DualStackIP.Ipv4)
			}
		case dns.TypeAAAA:
			if addr.DualStackIP.Ipv6 != "" {
				ret = append(ret, addr.DualStackIP.Ipv6)
			}
		}
	}

	return ret
}

func waitDNSAnswer(t *testing.T, h *harness.H, c *harness.DNSClient,
	name string, qtype uint16, want []string) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the Cluster DNS to resolve %s", name),
		harness.DecisionBudget, func(ctx context.Context) error {
			msg, err := c.Exchange(ctx, name, qtype)
			if err != nil {
				return err
			}
			if msg.Rcode != dns.RcodeSuccess {
				return errors.Errorf("%s returned %s", name, dns.RcodeToString[msg.Rcode])
			}
			if !msg.Authoritative {
				return errors.Errorf("%s was not answered authoritatively", name)
			}

			got := harness.DNSAnswerAddrs(msg)
			if len(got) == 0 {
				return errors.Errorf("%s returned no address records", name)
			}
			for _, addr := range got {
				if !slices.Contains(want, addr) {
					return errors.Errorf("%s resolved to %s, want one of %v",
						name, addr, want)
				}
			}
			return nil
		})
}

func waitDNSRcode(t *testing.T, h *harness.H, c *harness.DNSClient,
	name string, qtype uint16, want int) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the Cluster DNS to answer %s with %s",
		name, dns.RcodeToString[want]), harness.DecisionBudget,
		func(ctx context.Context) error {
			msg, err := c.Exchange(ctx, name, qtype)
			if err != nil {
				return err
			}
			if msg.Rcode != want {
				return errors.Errorf("%s returned %s, want %s", name,
					dns.RcodeToString[msg.Rcode], dns.RcodeToString[want])
			}
			return nil
		})
}

func testDNSResolution(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)

	ns := h.EnsureTestNamespace(t)

	rootSvc := h.NewPublicService(t, "default")
	nsSvc := h.NewPublicService(t, ns.Metadata.Name)

	rootSvc = h.GetService(t, rootSvc.Metadata.Name)
	nsSvc = h.GetService(t, nsSvc.Metadata.Name)

	rootName, _, _ := strings.Cut(rootSvc.Metadata.Name, ".")
	nsName, _, _ := strings.Cut(nsSvc.Metadata.Name, ".")

	require.True(t, len(serviceAddrs(rootSvc, dns.TypeA)) > 0,
		"the Service %s has no IPv4 address", rootSvc.Metadata.Name)

	h.Connect(t, harness.ConnectOpts{
		Root: true,
		Args: []string{"--no-dns"},
	})

	c := h.DNSClient(t)

	zap.L().Info("Querying the Cluster DNS",
		zap.String("server", c.Server), zap.String("source", c.Source))

	t.Run("Hostnames", func(t *testing.T) {
		want := serviceAddrs(rootSvc, dns.TypeA)

		for _, name := range []string{
			fmt.Sprintf("%s.local", rootName),
			fmt.Sprintf("%s.default.local", rootName),
			fmt.Sprintf("%s.local.%s", rootName, h.Domain),
			fmt.Sprintf("%s.default.local.%s", rootName, h.Domain),
			fmt.Sprintf("%s.%s.local", rootName, h.Domain),
			fmt.Sprintf("%s.default.%s.local", rootName, h.Domain),
		} {
			waitDNSAnswer(t, h, c, name, dns.TypeA, want)
		}
	})

	t.Run("Namespaced", func(t *testing.T) {
		want := serviceAddrs(nsSvc, dns.TypeA)

		for _, name := range []string{
			fmt.Sprintf("%s.%s.local", nsName, ns.Metadata.Name),
			fmt.Sprintf("%s.%s.local.%s", nsName, ns.Metadata.Name, h.Domain),
		} {
			waitDNSAnswer(t, h, c, name, dns.TypeA, want)
		}

		waitDNSRcode(t, h, c, fmt.Sprintf("%s.local", nsName),
			dns.TypeA, dns.RcodeNameError)
	})

	t.Run("IPv6", func(t *testing.T) {
		h.Require(t, capIPv6)

		want := serviceAddrs(rootSvc, dns.TypeAAAA)
		if len(want) == 0 {
			t.Skipf("the Service %s has no IPv6 address", rootSvc.Metadata.Name)
		}

		waitDNSAnswer(t, h, c, fmt.Sprintf("%s.default.local", rootName),
			dns.TypeAAAA, want)
	})

	t.Run("UnknownService", func(t *testing.T) {
		waitDNSRcode(t, h, c,
			fmt.Sprintf("%s.default.local", utilrand.GetRandomStringCanonical(10)),
			dns.TypeA, dns.RcodeNameError)
	})

	t.Run("Lifecycle", func(t *testing.T) {
		svc := h.NewPublicService(t, "default")
		svc = h.GetService(t, svc.Metadata.Name)

		name, _, _ := strings.Cut(svc.Metadata.Name, ".")
		fqdn := fmt.Sprintf("%s.default.local", name)

		waitDNSAnswer(t, h, c, fqdn, dns.TypeA, serviceAddrs(svc, dns.TypeA))

		h.DeleteService(t, svc)

		waitDNSRcode(t, h, c, fqdn, dns.TypeA, dns.RcodeNameError)
	})

	t.Run("NonAddressQueryIsProxied", func(t *testing.T) {
		msg, err := c.Exchange(t.Context(),
			fmt.Sprintf("%s.default.local", rootName), dns.TypeMX)
		if err != nil {
			t.Skipf("the fallback zone is not reachable from this Cluster: %+v", err)
		}

		assert.False(t, msg.Authoritative,
			"only address queries are answered from the Cluster Service zone, "+
				"everything else must be handed to the fallback zone")
	})
}

func testDNSLifecycleLoad(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)
	ns := h.EnsureTestNamespace(t)
	services := []*corev1.Service{
		h.NewPublicService(t, "default"),
		h.NewPublicService(t, ns.Metadata.Name),
	}
	h.Connect(t, harness.ConnectOpts{Root: true, Args: []string{"--no-dns"}})
	c := h.DNSClient(t)

	type query struct {
		name  string
		qtype uint16
		want  []string
		rcode int
	}
	var queries []query
	for _, svc := range services {
		svc = h.GetService(t, svc.Metadata.Name)
		name := svc.Metadata.Name + ".local"
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			addrs := serviceAddrs(svc, qtype)
			if len(addrs) == 0 {
				continue
			}
			waitDNSAnswer(t, h, c, name, qtype, addrs)
			queries = append(queries, query{name: strings.ToUpper(name), qtype: qtype, want: addrs})
		}
	}
	queries = append(queries,
		query{name: h.Name() + ".default.local", qtype: dns.TypeA, rcode: dns.RcodeNameError},
		query{name: "bad\x00.local", qtype: dns.TypeA, rcode: dns.RcodeRefused},
	)
	var completed atomic.Int64
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan *harness.PoolResult, 1)
	go func() {
		done <- harness.RunFor(ctx, 4*harness.DecisionBudget, 16,
			func(ctx context.Context, worker, iteration int) error {
				q := queries[(worker+iteration)%len(queries)]
				msg, err := c.Exchange(ctx, q.name, q.qtype)
				if err != nil {
					return err
				}
				if msg.Rcode != q.rcode {
					return errors.Errorf("%s returned %s, want %s", q.name,
						dns.RcodeToString[msg.Rcode], dns.RcodeToString[q.rcode])
				}
				addrs := harness.DNSAnswerAddrs(msg)
				if len(q.want) > 0 {
					if !msg.Authoritative || len(addrs) != 1 || !slices.Contains(q.want, addrs[0]) {
						return errors.Errorf("%s returned unexpected addresses %v", q.name, addrs)
					}
				} else if len(addrs) != 0 {
					return errors.Errorf("%s unexpectedly returned addresses %v", q.name, addrs)
				}
				completed.Add(1)
				return harness.Sleep(ctx, 5*time.Millisecond)
			})
	}()
	t.Cleanup(func() {
		cancel()
		result := <-done
		harness.LogPool("Cluster DNS lifecycle load", result)
		assert.Positive(t, result.Succeeded)
		assert.Zero(t, result.Failed(), result.Errors.String())
	})
	h.Eventually(t, "concurrent DNS queries to start", harness.DecisionBudget,
		func(ctx context.Context) error {
			if completed.Load() < 32 {
				return errors.New("the DNS query workers have not started")
			}
			return nil
		})

	before := completed.Load()
	svc := h.NewPublicService(t, "default")
	svc = h.GetService(t, svc.Metadata.Name)
	name := svc.Metadata.Name + ".local"
	waitDNSAnswer(t, h, c, name, dns.TypeA, serviceAddrs(svc, dns.TypeA))
	h.DeleteService(t, svc)
	waitDNSRcode(t, h, c, name, dns.TypeA, dns.RcodeNameError)

	recreated := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{Name: svc.Metadata.Name},
		Spec:     pbutils.Clone(svc.Spec).(*corev1.Service_Spec),
	})
	recreated = h.GetService(t, recreated.Metadata.Name)
	assert.NotEqual(t, svc.Metadata.Uid, recreated.Metadata.Uid)
	waitDNSAnswer(t, h, c, name, dns.TypeA, serviceAddrs(recreated, dns.TypeA))
	assert.Greater(t, completed.Load(), before)
}

func startDNSZoneUpstream(t *testing.T, h *harness.H, names []string) []string {
	t.Helper()
	ctx := t.Context()
	deployments, err := h.K8sC().AppsV1().Deployments("kube-system").List(ctx, k8smetav1.ListOptions{})
	require.Nil(t, err)
	var image string
	for _, dep := range deployments.Items {
		for _, container := range dep.Spec.Template.Spec.Containers {
			if strings.Contains(container.Image, "coredns") {
				image = container.Image
				break
			}
		}
	}
	if image == "" {
		t.Skip("the Cluster does not have a CoreDNS image for the DNS zone fixture")
	}

	name := "e2e-dns-" + h.Name()
	labels := map[string]string{"app": name}
	var config strings.Builder
	for i := range 3 {
		fmt.Fprintf(&config, ".:%d {\n hosts {\n", 1053+i)
		for _, domain := range names {
			fmt.Fprintf(&config, "198.51.100.%d %s\n2001:db8::%d %s\n", i+1, domain, i+1, domain)
		}
		config.WriteString("ttl 300\nno_reverse\n}\n}\n")
	}
	kc := h.K8sC().CoreV1()
	_, err = kc.ConfigMaps(vutils.K8sNS).Create(ctx, &k8scorev1.ConfigMap{
		ObjectMeta: k8smetav1.ObjectMeta{Name: name},
		Data:       map[string]string{"Corefile": config.String()},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, err := range []error{
			kc.Pods(vutils.K8sNS).Delete(ctx, name, k8smetav1.DeleteOptions{}),
			kc.Services(vutils.K8sNS).Delete(ctx, name, k8smetav1.DeleteOptions{}),
			kc.ConfigMaps(vutils.K8sNS).Delete(ctx, name, k8smetav1.DeleteOptions{}),
		} {
			if !k8serr.IsNotFound(err) {
				assert.Nil(t, err)
			}
		}
	})
	_, err = kc.Pods(vutils.K8sNS).Create(ctx, &k8scorev1.Pod{
		ObjectMeta: k8smetav1.ObjectMeta{Name: name, Labels: labels},
		Spec: k8scorev1.PodSpec{
			Containers: []k8scorev1.Container{{
				Name: "coredns", Image: image, Args: []string{"-conf", "/etc/coredns/Corefile"},
				VolumeMounts: []k8scorev1.VolumeMount{{Name: "config", MountPath: "/etc/coredns", ReadOnly: true}},
				ReadinessProbe: &k8scorev1.Probe{ProbeHandler: k8scorev1.ProbeHandler{
					TCPSocket: &k8scorev1.TCPSocketAction{Port: intstr.FromInt32(1053)},
				}},
			}},
			Volumes: []k8scorev1.Volume{{Name: "config", VolumeSource: k8scorev1.VolumeSource{
				ConfigMap: &k8scorev1.ConfigMapVolumeSource{LocalObjectReference: k8scorev1.LocalObjectReference{Name: name}},
			}}},
		},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	var ports []k8scorev1.ServicePort
	for i := range 3 {
		ports = append(ports, k8scorev1.ServicePort{
			Name: fmt.Sprintf("dns-%d", i), Port: int32(1053 + i),
			Protocol: k8scorev1.ProtocolUDP, TargetPort: intstr.FromInt32(int32(1053 + i)),
		})
	}
	svc, err := kc.Services(vutils.K8sNS).Create(ctx, &k8scorev1.Service{
		ObjectMeta: k8smetav1.ObjectMeta{Name: name},
		Spec:       k8scorev1.ServiceSpec{Selector: labels, Ports: ports},
	}, k8smetav1.CreateOptions{})
	require.Nil(t, err)
	h.Eventually(t, "the DNS zone upstream to become ready", harness.DeploymentBudget,
		func(ctx context.Context) error {
			pod, err := kc.Pods(vutils.K8sNS).Get(ctx, name, k8smetav1.GetOptions{})
			if err != nil {
				return err
			}
			for _, condition := range pod.Status.Conditions {
				if condition.Type == k8scorev1.PodReady && condition.Status == k8scorev1.ConditionTrue {
					return nil
				}
			}
			return errors.New("the DNS zone upstream is not ready")
		})
	var ret []string
	for _, port := range ports {
		ret = append(ret, "udp://"+net.JoinHostPort(svc.Spec.ClusterIP, fmt.Sprintf("%d", port.Port)))
	}
	return ret
}

func testDNSZones(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)
	domain := h.Name() + ".e2e-dns.test"
	parent := "www." + domain
	sub := "api.sub." + domain
	fallback := "external." + h.Name() + ".test"
	boundary := "not" + domain
	badSuffix := domain + ".invalid"
	servers := startDNSZoneUpstream(t, h, []string{parent, sub, fallback, boundary, badSuffix})
	original := pbutils.Clone(h.ClusterConfig(t)).(*corev1.ClusterConfig)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cc, err := h.CoreC().GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		if !assert.Nil(t, err) {
			return
		}
		cc.Spec.Dns = original.Spec.Dns
		_, err = h.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	})
	cc := h.ClusterConfig(t)
	cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
		FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{servers[0]}},
		Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
			{Domains: []string{domain}, Servers: []string{servers[1]}},
			{Domains: []string{"sub." + domain}, Servers: []string{servers[2]}},
		},
	}
	h.UpdateClusterConfig(t, cc)
	svc := h.NewPublicService(t, "default")
	svc = h.GetService(t, svc.Metadata.Name)
	h.Connect(t, harness.ConnectOpts{Root: true, Args: []string{"--no-dns"}})
	c := h.DNSClient(t)

	t.Run("LongestSuffix", func(t *testing.T) {
		for _, tc := range []struct{ name, ipv4, ipv6 string }{
			{name: parent, ipv4: "198.51.100.2", ipv6: "2001:db8::2"},
			{name: sub, ipv4: "198.51.100.3", ipv6: "2001:db8::3"},
			{name: fallback, ipv4: "198.51.100.1", ipv6: "2001:db8::1"},
			{name: boundary, ipv4: "198.51.100.1", ipv6: "2001:db8::1"},
			{name: badSuffix, ipv4: "198.51.100.1", ipv6: "2001:db8::1"},
		} {
			waitDNSAnswerAt(t, h, c, strings.ToUpper(tc.name), dns.TypeA, tc.ipv4)
			waitDNSAnswerAt(t, h, c, tc.name, dns.TypeAAAA, tc.ipv6)
		}
		waitDNSAnswer(t, h, c, svc.Metadata.Name+".local", dns.TypeA, serviceAddrs(svc, dns.TypeA))
	})

	t.Run("UpdateZone", func(t *testing.T) {
		cc := h.ClusterConfig(t)
		cc.Spec.Dns.Zones[0].Servers = []string{servers[0]}
		h.UpdateClusterConfig(t, cc)
		waitDNSAnswerAt(t, h, c, parent, dns.TypeA, "198.51.100.1")
		waitDNSAnswerAt(t, h, c, sub, dns.TypeA, "198.51.100.3")
	})

	t.Run("UpstreamFailureAndRecovery", func(t *testing.T) {
		cc := h.ClusterConfig(t)
		cc.Spec.Dns.Zones[1].Servers = []string{"udp://127.0.0.1:1"}
		h.UpdateClusterConfig(t, cc)
		waitDNSRcode(t, h, c, sub, dns.TypeA, dns.RcodeServerFailure)
		waitDNSAnswerAt(t, h, c, parent, dns.TypeA, "198.51.100.1")
		waitDNSAnswer(t, h, c, svc.Metadata.Name+".local", dns.TypeA, serviceAddrs(svc, dns.TypeA))

		cc = h.ClusterConfig(t)
		cc.Spec.Dns.Zones[1].Servers = []string{servers[2]}
		h.UpdateClusterConfig(t, cc)
		waitDNSAnswerAt(t, h, c, sub, dns.TypeA, "198.51.100.3")
	})

	t.Run("RemoveZone", func(t *testing.T) {
		cc := h.ClusterConfig(t)
		cc.Spec.Dns.Zones = nil
		h.UpdateClusterConfig(t, cc)
		waitDNSAnswerAt(t, h, c, sub, dns.TypeA, "198.51.100.1")
		waitDNSAnswerAt(t, h, c, parent, dns.TypeAAAA, "2001:db8::1")
	})
}

func testDNSFailover(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)
	domain := h.Name() + ".e2e-dns.test"
	probe := "probe." + domain
	fallbackProbe := "probe." + h.Name() + ".test"
	private := "private.sub." + domain
	type query struct {
		name string
		ipv4 string
		ipv6 string
	}
	var queries []query
	names := []string{probe, fallbackProbe, private}
	for i := range 32 {
		name := fmt.Sprintf("query%d.%s", i, domain)
		fallback := fmt.Sprintf("query%d.%s.test", i, h.Name())
		names = append(names, name, fallback)
		queries = append(queries,
			query{name: name, ipv4: "198.51.100.2", ipv6: "2001:db8::2"},
			query{name: fallback, ipv4: "198.51.100.1", ipv6: "2001:db8::1"},
		)
	}
	servers := startDNSZoneUpstream(t, h, names)
	original := pbutils.Clone(h.ClusterConfig(t)).(*corev1.ClusterConfig)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cc, err := h.CoreC().GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		if !assert.Nil(t, err) {
			return
		}
		cc.Spec.Dns = original.Spec.Dns
		_, err = h.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	})
	cc := h.ClusterConfig(t)
	cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
		FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{"udp://127.0.0.1:1", servers[0]}},
		Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
			{Domains: []string{domain}, Servers: []string{"udp://127.0.0.1:1", servers[1]}},
			{Domains: []string{"sub." + domain}, Servers: []string{"udp://127.0.0.1:1", "udp://127.0.0.1:2"}},
		},
	}
	h.UpdateClusterConfig(t, cc)
	svc := h.NewPublicService(t, "default")
	svc = h.GetService(t, svc.Metadata.Name)
	h.Connect(t, harness.ConnectOpts{Root: true, Args: []string{"--no-dns"}})
	c := h.DNSClient(t)
	waitDNSAnswerAt(t, h, c, probe, dns.TypeA, "198.51.100.2")
	waitDNSAnswerAt(t, h, c, fallbackProbe, dns.TypeA, "198.51.100.1")
	waitDNSRcode(t, h, c, private, dns.TypeA, dns.RcodeServerFailure)
	waitDNSAnswer(t, h, c, svc.Metadata.Name+".local", dns.TypeA, serviceAddrs(svc, dns.TypeA))

	t.Run("ConcurrentQueries", func(t *testing.T) {
		result := harness.ForEach(t.Context(), 2*len(queries), 16,
			func(ctx context.Context, i int) error {
				q := queries[i/2]
				qtype := dns.TypeA
				want := q.ipv4
				if i%2 == 1 {
					qtype = dns.TypeAAAA
					want = q.ipv6
				}
				for range 2 {
					msg, err := c.Exchange(ctx, q.name, qtype)
					if err != nil {
						return err
					}
					if msg.Rcode != dns.RcodeSuccess {
						return errors.Errorf("%s returned %s", q.name, dns.RcodeToString[msg.Rcode])
					}
					addrs := harness.DNSAnswerAddrs(msg)
					if len(addrs) != 1 || addrs[0] != want {
						return errors.Errorf("%s returned addresses %v, want %s", q.name, addrs, want)
					}
				}
				return nil
			})
		harness.LogPool("Cluster DNS upstream failover", result)
		assert.Equal(t, 2*len(queries), result.Succeeded)
		assert.Zero(t, result.Failed(), result.Errors.String())
	})

	t.Run("Recovery", func(t *testing.T) {
		cc := h.ClusterConfig(t)
		cc.Spec.Dns.Zones[1].Servers = []string{"udp://127.0.0.1:1", servers[2]}
		h.UpdateClusterConfig(t, cc)
		waitDNSAnswerAt(t, h, c, private, dns.TypeA, "198.51.100.3")
		waitDNSAnswerAt(t, h, c, private, dns.TypeAAAA, "2001:db8::3")
		waitDNSAnswerAt(t, h, c, probe, dns.TypeA, "198.51.100.2")
		waitDNSAnswerAt(t, h, c, fallbackProbe, dns.TypeA, "198.51.100.1")
	})
}
