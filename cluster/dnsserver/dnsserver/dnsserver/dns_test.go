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

package dnsserver

import (
	"context"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

func TestGetHostname(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	dnsSrv, err := Initialize(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)

	/*
		{
			res, err := dnsSrv.getHostname("svc1.local.example.com.")
			assert.Nil(t, err)
			assert.Equal(t, "svc1", res)
		}
	*/

	{
		res, err := dnsSrv.getHostname("svc1.ns0.local.example.com.")
		assert.Nil(t, err)
		assert.Equal(t, "svc1.ns0", res)
	}

	{
		res, err := dnsSrv.getHostname("svc1.local.example.com.")
		assert.Nil(t, err)
		assert.Equal(t, "svc1", res)
	}

	/*
		{
			res, err := dnsSrv.getHostname("local.")
			assert.Nil(t, err)
			assert.Equal(t, "default.default", res)
		}
	*/

	{
		res, err := dnsSrv.getHostname("svc1.local.")
		assert.Nil(t, err)
		assert.Equal(t, "svc1", res)
	}

	{
		res, err := dnsSrv.getHostname("svc1.ns1.local.")
		assert.Nil(t, err)
		assert.Equal(t, "svc1.ns1", res)
	}

	{
		invalidVals := []string{
			"",
			".",
			"aa",
			"example.com",
			// "example.com.",
			"aa.example.com",
			"aa.ixample.com.",
			// "aa.sub.sub.example.com.",
		}

		for _, val := range invalidVals {
			_, err := dnsSrv.getHostname(val)
			assert.NotNil(t, err, "%s", val)
		}
	}
}

func TestFallbackUpstreams(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	dnsSrv, err := Initialize(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)

	assert.True(t, len(dnsSrv.upstreams) > 0)

	dnsSrv.setDefaultUpstreams(&corev1.ClusterConfig{
		Spec: &corev1.ClusterConfig_Spec{
			Dns: &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
					Servers: []string{"udp://1.2.3.4"},
				},
			},
		},
	})

	assert.Equal(t, "1.2.3.4", dnsSrv.upstreams[0].host)
	assert.Equal(t, 53, dnsSrv.upstreams[0].port)
}

/*
func TestParseSvcNs(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	dnsSrv, err := Initialize(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)

	invalidVals := []string{
		"",
		".",
		"aa",
		"example.com",
		"example.com.",
		"aa.example.com",
		"aa.ixample.com.",
		"aa.sub.sub.example.com.",
	}

	for _, val := range invalidVals {
		assert.Nil(t, dnsSrv.parseSvcNs(val))
	}

	{
		res := dnsSrv.parseSvcNs("svc1.local.example.com.")
		assert.NotNil(t, res)
		assert.Equal(t, res.svc, "svc1")
		assert.Equal(t, res.namespace, "default")
	}

	{
		res := dnsSrv.parseSvcNs("svc1.ns1.example.com.")
		assert.NotNil(t, res)
		assert.Equal(t, res.svc, "svc1")
		assert.Equal(t, res.namespace, "ns1")
	}

	{
		res := dnsSrv.parseSvcNs("svc1.local.example.com.local.")
		assert.NotNil(t, res)
		assert.Equal(t, res.svc, "svc1")
		assert.Equal(t, res.namespace, "default")
	}

	{
		res := dnsSrv.parseSvcNs("svc1.local.")
		assert.NotNil(t, res)
		assert.Equal(t, res.svc, "svc1")
		assert.Equal(t, res.namespace, "default")
	}

	{
		res := dnsSrv.parseSvcNs("svc1.local.example.com.")
		assert.NotNil(t, res)
		assert.Equal(t, res.svc, "svc1")
		assert.Equal(t, res.namespace, "default")
	}

	{
		res := dnsSrv.parseSvcNs("svc2.ns2.local.example.com.")
		assert.NotNil(t, res)
		assert.Equal(t, res.svc, "svc2")
		assert.Equal(t, res.namespace, "ns2")
	}

	{
		res := dnsSrv.parseSvcNs("svc1_ns2.local.example.com.")
		assert.NotNil(t, res)
		assert.Equal(t, res.svc, "svc1")
		assert.Equal(t, res.namespace, "ns2")
	}
}
*/

func TestResolve(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	dnsSrv, err := Initialize(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)

	addr := "127.0.0.1:8553"

	startCh := make(chan bool)

	srv := &dns.Server{
		Addr: addr,
		Net:  "udp",
		NotifyStartedFunc: func() {
			startCh <- true
		},
	}
	srv.Handler = dnsSrv

	go func() {

		if err := srv.ListenAndServe(); err != nil {
			zap.S().Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()

	defer srv.Shutdown()

	<-startCh

	{
		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion("svc1.local.example.com.", dns.TypeA)
		r, _, err := c.Exchange(m, addr)
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeNameError, r.Rcode)
	}

	{

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				PrimaryHostname: "svc1",
				NamespaceRef: &metav1.ObjectReference{
					Name: "default",
				},
				Addresses: []*corev1.Service_Status_Address{
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv4: "1.2.3.4",
							Ipv6: "::1",
						},
					},
				},
			},
		}

		dnsSrv.Set(svc)

		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("svc1.local.example.com.", dns.TypeA)
			r, _, err := c.ExchangeContext(context.Background(), m, addr)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode)
			assert.Equal(t, "1.2.3.4", (r.Answer[0].(*dns.A)).A.String())
		}
		{

			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("svc1.local.example.com.", dns.TypeAAAA)
			r, _, err := c.Exchange(m, addr)
			assert.Nil(t, err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode)
			assert.Equal(t, "::1", (r.Answer[0].(*dns.AAAA)).AAAA.String())

		}
		svc.Status.Addresses[0].DualStackIP.Ipv4 = "1.2.3.5"
		dnsSrv.Set(svc)
		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("svc1.local.example.com.", dns.TypeA)
			r, _, err := c.Exchange(m, addr)
			assert.Nil(t, err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode)
			assert.Equal(t, "1.2.3.5", (r.Answer[0].(*dns.A)).A.String())
		}

		dnsSrv.Unset(svc)

		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("svc1.local.example.com.", dns.TypeA)
			r, _, err := c.Exchange(m, addr)
			assert.Nil(t, err)
			assert.Equal(t, dns.RcodeNameError, r.Rcode)
		}
		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("svc1.local.example.com.", dns.TypeAAAA)
			r, _, err := c.Exchange(m, addr)
			assert.Nil(t, err)
			assert.Equal(t, dns.RcodeNameError, r.Rcode)
		}

		{

			{
				r := dnsSrv.fallbackZoneCache.get("one.one.one.one.", dns.TypeA)
				assert.Nil(t, r)
			}
			res, err := dnsSrv.getProxiedAnswer("one.one.one.one.", dns.TypeA)
			assert.Nil(t, err)

			nip := res.Answer[0].(*dns.A).A
			assert.True(t, nip.Equal([]byte{1, 1, 1, 1}) || nip.Equal([]byte{1, 0, 0, 1}))
		}

		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("one.one.one.one.", dns.TypeA)
			r, _, err := c.Exchange(m, addr)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode)

			r2 := dnsSrv.fallbackZoneCache.get("one.one.one.one.", dns.TypeA)
			assert.NotNil(t, r2)
			assert.Equal(t, r.Answer, r2.Answer)
		}

		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("one.one.one.one.", dns.TypeA)
			r, _, err := c.Exchange(m, addr)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode)
		}
	}
}

func TestGetHostnameFromPossibleHostname(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	dnsSrv, err := Initialize(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				PrimaryHostname: "svc1",
				AdditionalHostnames: []string{
					"svc1.default",
				},
				NamespaceRef: &metav1.ObjectReference{
					Name: "default",
				},
				Addresses: []*corev1.Service_Status_Address{
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv4: "1.2.3.4",
							Ipv6: "::1",
						},
					},
				},
			},
		}

		dnsSrv.Set(svc)

		_, err = dnsSrv.getHostnameFromPossibleHostname("")
		assert.NotNil(t, err)

		_, err = dnsSrv.getHostnameFromPossibleHostname(".")
		assert.NotNil(t, err)

		_, err = dnsSrv.getHostnameFromPossibleHostname(fmt.Sprintf("%s.", utilrand.GetRandomStringCanonical(8)))
		assert.NotNil(t, err)

		{
			ret, err := dnsSrv.getHostnameFromPossibleHostname("svc1.")
			assert.Nil(t, err)

			assert.Equal(t, "svc1.default", ret)
		}

		{
			ret, err := dnsSrv.getHostnameFromPossibleHostname("svc1.default.")
			assert.Nil(t, err)

			assert.Equal(t, "svc1.default", ret)
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.ns1",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				PrimaryHostname: "svc1.ns1",

				NamespaceRef: &metav1.ObjectReference{
					Name: "ns1",
				},
				Addresses: []*corev1.Service_Status_Address{
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv4: "1.2.3.4",
							Ipv6: "::1",
						},
					},
				},
			},
		}

		dnsSrv.Set(svc)

		{
			ret, err := dnsSrv.getHostnameFromPossibleHostname("svc1.ns1.")
			assert.Nil(t, err)

			assert.Equal(t, "svc1.ns1", ret)
		}
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "google.com",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				PrimaryHostname: "google.com",

				NamespaceRef: &metav1.ObjectReference{
					Name: "com",
				},
				Addresses: []*corev1.Service_Status_Address{
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv4: "1.2.3.4",
							Ipv6: "::1",
						},
					},
				},
			},
		}

		dnsSrv.Set(svc)

		{
			_, err := dnsSrv.getHostnameFromPossibleHostname("google.com.")
			assert.NotNil(t, err)

			assert.True(t, errors.Is(err, errNotFound))
		}
	}
}
