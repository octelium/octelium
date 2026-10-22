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

package gwagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	goruntime "runtime"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	gwtests "github.com/octelium/octelium/cluster/gwagent/internal/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	k8scorev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func TestDoIsPublicIP(t *testing.T) {
	for _, addr := range []string{
		"", "invalid", "0.0.0.0", "::", "127.0.0.1", "::1", "10.0.0.1",
		"172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.1.1",
		"fe80::1", "fc00::1", "fdff::1", "224.0.0.1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:192.168.1.1",
	} {
		assert.False(t, doIsPublicIP(net.ParseIP(addr)), addr)
	}
	for _, addr := range []string{"1.2.3.4", "8.8.8.8", "172.15.255.255", "172.32.0.1", "2001:4860:4860::8888"} {
		assert.True(t, doIsPublicIP(net.ParseIP(addr)), addr)
	}
}

func TestAppendPublicIPAddr(t *testing.T) {
	srv := &Server{}
	for _, addr := range []string{"", "invalid", "10.1.2.3", "::1", "1.2.3.4/32", "1.2.3.4:443", "[2001:4860::1]"} {
		srv.doAppendPublicIPAddr(addr)
	}
	assert.Empty(t, srv.publicIPs)
	for _, addr := range []string{" 1.2.3.4\n", "1.2.3.4", "::ffff:1.2.3.4", "2001:4860:0:0:0:0:0:1", "2001:4860::1"} {
		srv.doAppendPublicIPAddr(addr)
	}
	assert.Equal(t, []string{"1.2.3.4", "2001:4860::1"}, srv.publicIPs)
}

func TestSetNodePublicIPs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		expected    []string
	}{
		{name: "override", annotations: map[string]string{
			"octelium.com/override-gw-ip": " 10.0.0.1 ", "octelium.com/public-ip-test": "1.2.3.4",
			"octelium.com/public-ipv4": "5.6.7.8",
		}, expected: []string{"10.0.0.1"}},
		{name: "testOverride", annotations: map[string]string{
			"octelium.com/override-gw-ip": "invalid", "octelium.com/public-ip-test": " fd00::1 ",
		}, expected: []string{"fd00::1"}},
		{name: "dualStack", annotations: map[string]string{
			"octelium.com/public-ipv4": " 1.2.3.4 ", "octelium.com/public-ipv6": "2001:4860::1",
			"octelium.com/public-ip": "5.6.7.8",
		}, expected: []string{"1.2.3.4", "2001:4860::1"}},
		{name: "invalidFamilyAnnotation", annotations: map[string]string{
			"octelium.com/public-ipv4": "invalid", "octelium.com/public-ipv6": "2001:4860::1",
		}, expected: []string{"2001:4860::1"}},
		{name: "legacyFallback", annotations: map[string]string{
			"octelium.com/public-ipv4": "192.168.1.1", "octelium.com/public-ipv6": "fd00::1",
			"octelium.com/public-ip": " 5.6.7.8 ",
		}, expected: []string{"5.6.7.8"}},
		{name: "duplicate", annotations: map[string]string{
			"octelium.com/public-ipv4": "1.2.3.4", "octelium.com/public-ipv6": "::ffff:1.2.3.4",
		}, expected: []string{"1.2.3.4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{node: &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Annotations: tc.annotations}}}
			require.Nil(t, srv.setNodePublicIPs(t.Context()))
			assert.Equal(t, tc.expected, srv.publicIPs)
		})
	}
}

func TestSetExternalIPFromNode(t *testing.T) {
	for _, code := range []int{http.StatusOK, http.StatusNotFound, http.StatusForbidden} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v1/nodes/node-1", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				if code == http.StatusOK {
					fmt.Fprint(w, `{"apiVersion":"v1","kind":"Node","status":{"addresses":[
      {"type":"InternalIP","address":"8.8.8.8"},
      {"type":"ExternalIP","address":"invalid"},
      {"type":"ExternalIP","address":"192.168.1.1"},
      {"type":"ExternalIP","address":"1.2.3.4"},
      {"type":"ExternalIP","address":"1.2.3.4"},
      {"type":"ExternalIP","address":"2001:4860::1"}]}}`)
				}
			}))
			defer api.Close()
			client, err := kubernetes.NewForConfig(&rest.Config{Host: api.URL})
			require.Nil(t, err)
			srv := &Server{k8sC: client, nodeName: "node-1", node: &k8scorev1.Node{}}
			err = srv.setExternalIPFromNode(t.Context())
			if code != http.StatusOK {
				assert.NotNil(t, err)
				assert.Empty(t, srv.publicIPs)
				return
			}
			require.Nil(t, err)
			assert.Equal(t, []string{"1.2.3.4", "2001:4860::1"}, srv.publicIPs)
			srv.publicIPs = nil
			require.Nil(t, srv.setNodePublicIPs(t.Context()))
			assert.Equal(t, []string{"1.2.3.4", "2001:4860::1"}, srv.publicIPs)
		})
	}
}

func TestSetPublicIPAddrFromAPI(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     int
		body     string
		expected []string
	}{
		{name: "IPv4", code: http.StatusOK, body: " 1.2.3.4\n", expected: []string{"1.2.3.4"}},
		{name: "IPv6", code: http.StatusOK, body: "2001:4860::1\n", expected: []string{"2001:4860::1"}},
		{name: "empty", code: http.StatusOK},
		{name: "invalid", code: http.StatusOK, body: "<html>1.2.3.4</html>"},
		{name: "multiple", code: http.StatusOK, body: "1.2.3.4\n5.6.7.8"},
		{name: "private", code: http.StatusOK, body: "10.0.0.1"},
		{name: "error", code: http.StatusBadGateway, body: "1.2.3.4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}))
			defer api.Close()
			srv := &Server{}
			err := srv.doSetPublicIPAddrFromAPI(t.Context(), api.URL, "tcp4")
			if tc.code != http.StatusOK {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tc.expected, srv.publicIPs)
		})
	}

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		srv := &Server{}
		err := srv.doSetPublicIPAddrFromAPI(ctx, "http://127.0.0.1:1", "tcp4")
		assert.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, srv.publicIPs)
		assert.Nil(t, srv.setPublicIPAddrsFromPublicAPIs(ctx))
		assert.Empty(t, srv.publicIPs)
		srv.publicIPs = []string{"1.2.3.4"}
		assert.Nil(t, srv.setPublicIPAddrsFromPublicAPIs(ctx))
		assert.Equal(t, []string{"1.2.3.4"}, srv.publicIPs)
	})
}

func TestUntaintNode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		labels   map[string]string
		taints   []k8scorev1.Taint
		updates  int
		conflict bool
	}{
		{name: "unregistered", updates: 1},
		{name: "alreadyRegistered", labels: map[string]string{vutils.NodeLabelGatewayRegistered: "true"}},
		{name: "tainted", labels: map[string]string{"other": "keep"}, taints: []k8scorev1.Taint{
			{Key: vutils.NodeTaintGatewayInit, Effect: k8scorev1.TaintEffectNoSchedule},
			{Key: "other", Value: "keep", Effect: k8scorev1.TaintEffectNoExecute},
			{Key: vutils.NodeTaintGatewayInit, Effect: k8scorev1.TaintEffectNoExecute},
		}, updates: 1},
		{name: "conflict", updates: 2, conflict: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node-1", Labels: tc.labels},
				Spec: k8scorev1.NodeSpec{Taints: tc.taints}}
			client := fake.NewSimpleClientset(node)
			updates := 0
			client.PrependReactor("update", "nodes", func(action k8stesting.Action) (bool, runtime.Object, error) {
				updates++
				if tc.conflict && updates == 1 {
					return true, nil, k8serrors.NewConflict(schema.GroupResource{Resource: "nodes"}, node.Name, fmt.Errorf("conflict"))
				}
				return false, nil, nil
			})
			require.Nil(t, untaintNode(t.Context(), client, node.Name))
			assert.Equal(t, tc.updates, updates)
			updated, err := client.CoreV1().Nodes().Get(t.Context(), node.Name, k8smetav1.GetOptions{})
			require.Nil(t, err)
			assert.Equal(t, "true", updated.Labels[vutils.NodeLabelGatewayRegistered])
			if tc.name == "tainted" {
				assert.Equal(t, "keep", updated.Labels["other"])
				assert.Equal(t, []k8scorev1.Taint{tc.taints[1]}, updated.Spec.Taints)
			}
			require.Nil(t, untaintNode(t.Context(), client, node.Name))
			assert.Equal(t, tc.updates, updates)
		})
	}

	t.Run("errors", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		assert.True(t, k8serrors.IsNotFound(untaintNode(t.Context(), client, "missing")))
		_, err := client.CoreV1().Nodes().Create(t.Context(), &k8scorev1.Node{
			ObjectMeta: k8smetav1.ObjectMeta{Name: "node-1"},
		}, k8smetav1.CreateOptions{})
		require.Nil(t, err)
		expected := fmt.Errorf("update failed")
		client.PrependReactor("update", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, expected
		})
		assert.ErrorIs(t, untaintNode(t.Context(), client, "node-1"), expected)
	})
}

func TestServerRun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("The gateway devices require root")
	}
	gwtests.LockGateway(t)
	for _, enableQUIC := range []bool{false, true} {
		t.Run(fmt.Sprint(enableQUIC), func(t *testing.T) {
			tst, err := tests.Initialize(nil)
			require.Nil(t, err)
			t.Cleanup(func() { tst.Destroy() })
			t.Setenv(vutils.MultusConfDirEnv, t.TempDir())
			t.Setenv("OCTELIUM_REGION_NAME", "default")
			cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(t.Context())
			require.Nil(t, err)
			if cc.Status.NetworkConfig == nil {
				cc.Status.NetworkConfig = &corev1.ClusterConfig_Status_NetworkConfig{
					Mode: corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK,
				}
			}
			cc.Status.NetworkConfig.Quicv0 = &corev1.ClusterConfig_Status_NetworkConfig_QUICV0{Enable: enableQUIC}
			_, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(t.Context(), cc)
			require.Nil(t, err)
			node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{
				Name: "node-1", UID: "node-uid", Annotations: map[string]string{"octelium.com/public-ip-test": "1.2.3.4"},
			}, Spec: k8scorev1.NodeSpec{Taints: []k8scorev1.Taint{
				{Key: vutils.NodeTaintGatewayInit, Effect: k8scorev1.TaintEffectNoSchedule},
			}}}
			var mu sync.Mutex
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				assert.Equal(t, "/api/v1/nodes/node-1", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPut {
					updated := &k8scorev1.Node{}
					if err := json.NewDecoder(r.Body).Decode(updated); !assert.Nil(t, err) {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					node = updated
				}
				assert.Nil(t, json.NewEncoder(w).Encode(node))
			}))
			t.Cleanup(api.Close)
			client, err := kubernetes.NewForConfig(&rest.Config{
				Host: api.URL, ContentConfig: rest.ContentConfig{ContentType: "application/json"},
			})
			require.Nil(t, err)
			srv := &Server{octeliumC: tst.C.OcteliumC, k8sC: client, nodeName: node.Name}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(func() {
				cancel()
				if srv.quicCtl != nil {
					srv.quicCtl.Close()
				}
				srv.cleanup()
			})
			require.Nil(t, srv.Run(ctx))
			assert.Equal(t, enableQUIC, srv.hasQUICV0)
			assert.Equal(t, []string{"1.2.3.4"}, srv.publicIPs)
			assert.Equal(t, "default", srv.regionRef.Name)
			gw, err := tst.C.OcteliumC.CoreC().GetGateway(t.Context(), &rmetav1.GetOptions{Name: k8sutils.GetGatewayName(srv.node)})
			require.Nil(t, err)
			assert.Equal(t, string(node.UID), gw.Status.NodeRef.Uid)
			updated, err := client.CoreV1().Nodes().Get(t.Context(), node.Name, k8smetav1.GetOptions{})
			require.Nil(t, err)
			assert.Empty(t, updated.Spec.Taints)
			assert.Equal(t, "true", updated.Labels[vutils.NodeLabelGatewayRegistered])
		})
	}
}

func TestPublicIPFromDevice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("The network device requires root")
	}
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	original, err := netns.Get()
	require.Nil(t, err)
	defer original.Close()
	ns, err := netns.New()
	require.Nil(t, err)
	defer ns.Close()
	defer netns.Set(original)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gwagent-ip-test"}}
	require.Nil(t, netlink.LinkAdd(link))
	defer netlink.LinkDel(link)
	require.Nil(t, netlink.LinkSetUp(link))
	for _, cidr := range []string{"1.2.3.4/32", "2001:4860::1/128"} {
		addr, err := netlink.ParseAddr(cidr)
		require.Nil(t, err)
		addr.Flags = unix.IFA_F_NODAD
		require.Nil(t, netlink.AddrAdd(link, addr))
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}
	require.Nil(t, netlink.RouteAdd(route))
	name, err := getDefaultInterface()
	require.Nil(t, err)
	assert.Equal(t, link.Attrs().Name, name)
	srv := &Server{}
	require.Nil(t, srv.setExternalIPFromDev())
	assert.ElementsMatch(t, []string{"1.2.3.4", "2001:4860::1"}, srv.publicIPs)
	require.Nil(t, netlink.RouteDel(route))
	_, err = getDefaultInterface()
	assert.NotNil(t, err)
	assert.NotNil(t, srv.setExternalIPFromDev())
	require.Nil(t, netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index, Family: netlink.FAMILY_V6,
		Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}))
	name, err = getDefaultInterface()
	require.Nil(t, err)
	assert.Equal(t, link.Attrs().Name, name)
}
