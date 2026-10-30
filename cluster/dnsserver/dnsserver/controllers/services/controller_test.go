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

package servicecontroller

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/dnsserver/dnsserver/dnsserver"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tstDNSClient struct {
	octeliumc.ClientInterface
}

func (c *tstDNSClient) CoreV1Utils() octeliumc.CoreV1Utils { return c }

func (c *tstDNSClient) GetClusterConfig(context.Context) (*corev1.ClusterConfig, error) {
	return &corev1.ClusterConfig{
		Spec:   &corev1.ClusterConfig_Spec{},
		Status: &corev1.ClusterConfig_Status{Domain: "example.com"},
	}, nil
}

type tstDNSWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w *tstDNSWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg.Copy()
	return nil
}

func newTstController(t *testing.T) (*Controller, *dnsserver.DNSServer) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s, err := dnsserver.Initialize(ctx, &tstDNSClient{})
	require.Nil(t, err)
	return NewController(s), s
}

func TestControllerLifecycle(t *testing.T) {
	c, s := newTstController(t)
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "svc.default"},
		Status: &corev1.Service_Status{
			PrimaryHostname:     "svc",
			AdditionalHostnames: []string{"svc.default"},
			Addresses: []*corev1.Service_Status_Address{
				{DualStackIP: &metav1.DualStackIP{Ipv4: "192.0.2.1", Ipv6: "2001:db8::1"}},
			},
		},
	}
	check := func(ipv4, ipv6 string) {
		t.Helper()
		for _, name := range []string{"svc.local.", "svc.default.local."} {
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				r := &dns.Msg{}
				r.SetQuestion(name, qtype)
				w := &tstDNSWriter{}
				s.ServeDNS(w, r)
				require.NotNil(t, w.msg)
				if ipv4 == "" && ipv6 == "" {
					assert.Equal(t, dns.RcodeNameError, w.msg.Rcode)
					assert.Empty(t, w.msg.Answer)
					continue
				}
				assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
				require.Equal(t, 1, len(w.msg.Answer))
				if qtype == dns.TypeA {
					assert.True(t, w.msg.Answer[0].(*dns.A).A.Equal(net.ParseIP(ipv4)))
				} else {
					assert.True(t, w.msg.Answer[0].(*dns.AAAA).AAAA.Equal(net.ParseIP(ipv6)))
				}
			}
		}
	}

	check("", "")
	assert.Nil(t, c.OnAdd(t.Context(), svc))
	assert.Nil(t, c.OnAdd(t.Context(), svc))
	check("192.0.2.1", "2001:db8::1")

	updated := pbutils.Clone(svc).(*corev1.Service)
	updated.Status.Addresses[0].DualStackIP = &metav1.DualStackIP{Ipv4: "192.0.2.2", Ipv6: "2001:db8::2"}
	assert.Nil(t, c.OnUpdate(t.Context(), updated, svc))
	check("192.0.2.2", "2001:db8::2")

	empty := pbutils.Clone(updated).(*corev1.Service)
	empty.Status.Addresses = nil
	assert.Nil(t, c.OnUpdate(t.Context(), empty, updated))
	check("", "")
	assert.Nil(t, c.OnUpdate(t.Context(), svc, empty))
	check("192.0.2.1", "2001:db8::1")

	assert.Nil(t, c.OnDelete(t.Context(), svc))
	assert.Nil(t, c.OnDelete(t.Context(), svc))
	check("", "")
}

func TestControllerConcurrentEvents(t *testing.T) {
	c, s := newTstController(t)
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("svc%d", worker)
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Name: name + ".default"},
				Status: &corev1.Service_Status{
					PrimaryHostname:     name,
					AdditionalHostnames: []string{name + ".default"},
					Addresses: []*corev1.Service_Status_Address{
						{DualStackIP: &metav1.DualStackIP{Ipv4: "192.0.2.1"}},
					},
				},
			}
			for range 50 {
				assert.Nil(t, c.OnAdd(t.Context(), svc))
				updated := pbutils.Clone(svc).(*corev1.Service)
				updated.Status.Addresses[0].DualStackIP.Ipv4 = "192.0.2.2"
				assert.Nil(t, c.OnUpdate(t.Context(), updated, svc))
				r := &dns.Msg{}
				r.SetQuestion(name+".default.local.", dns.TypeA)
				w := &tstDNSWriter{}
				s.ServeDNS(w, r)
				if !assert.NotNil(t, w.msg) || !assert.Equal(t, 1, len(w.msg.Answer)) {
					return
				}
				assert.True(t, w.msg.Answer[0].(*dns.A).A.Equal(net.ParseIP("192.0.2.2")))
				assert.Nil(t, c.OnDelete(t.Context(), updated))
				w = &tstDNSWriter{}
				s.ServeDNS(w, r)
				assert.Equal(t, dns.RcodeNameError, w.msg.Rcode)
			}
		}()
	}
	wg.Wait()
}
