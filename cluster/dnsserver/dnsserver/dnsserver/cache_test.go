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
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

func TestCache(t *testing.T) {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	cache := newCache()

	{
		res := cache.get("svc1.default", dns.TypeA)
		assert.Nil(t, res)
	}

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

		cache.set(svc)
		{
			res := cache.get("svc1.default", dns.TypeA)
			assert.True(t, res.Equal(net.ParseIP("1.2.3.4")))
		}
		{
			res := cache.get("svc1", dns.TypeA)
			assert.True(t, res.Equal(net.ParseIP("1.2.3.4")))
		}
		{
			res := cache.get("svc1.default", dns.TypeAAAA)
			assert.True(t, res.Equal(net.ParseIP("::1")))
		}

		{
			res := cache.get("svc1.default", dns.TypeA)
			assert.True(t, res.Equal(net.ParseIP("1.2.3.4")))
		}
		{
			res := cache.get("svc1.default", dns.TypeAAAA)
			assert.True(t, res.Equal(net.ParseIP("::1")))
		}

		{
			assert.True(t, cache.has("svc1.default"))
		}

		cache.delete(svc)

		{
			res := cache.get("svc1.default", dns.TypeA)
			assert.Nil(t, res)
		}
		{
			res := cache.get("svc1.default", dns.TypeAAAA)
			assert.Nil(t, res)
		}

	}
}

func TestCacheDefaultService(t *testing.T) {
	c := newCache()
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "default.default"},
		Status: &corev1.Service_Status{
			AdditionalHostnames: []string{"default.default"},
			Addresses: []*corev1.Service_Status_Address{
				{DualStackIP: &metav1.DualStackIP{Ipv4: "192.0.2.1", Ipv6: "2001:db8::1"}},
			},
		},
	}

	assert.False(t, c.has(""))
	assert.Nil(t, c.get("", dns.TypeA))

	c.set(svc)
	assert.True(t, c.has(""))
	assert.True(t, c.has("default.default"))
	assert.True(t, c.get("", dns.TypeA).Equal(net.ParseIP("192.0.2.1")))
	assert.True(t, c.get("", dns.TypeAAAA).Equal(net.ParseIP("2001:db8::1")))

	c.delete(svc)
	c.delete(svc)
	assert.False(t, c.has(""))
	assert.Nil(t, c.get("", dns.TypeA))
	assert.Nil(t, c.get("", dns.TypeAAAA))
}

func TestCacheReplacement(t *testing.T) {
	c := newCache()
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "svc.default"},
		Status: &corev1.Service_Status{
			PrimaryHostname:     "svc",
			AdditionalHostnames: []string{"svc.default", "alias.default"},
			Addresses: []*corev1.Service_Status_Address{
				{DualStackIP: &metav1.DualStackIP{Ipv4: "192.0.2.1", Ipv6: "2001:db8::1"}},
			},
		},
	}
	c.set(svc)

	updated := pbutils.Clone(svc).(*corev1.Service)
	updated.Status.Addresses = []*corev1.Service_Status_Address{
		{DualStackIP: &metav1.DualStackIP{Ipv4: "192.0.2.2"}},
	}
	c.set(updated)

	for _, hostname := range []string{"svc", "svc.default", "alias.default"} {
		assert.True(t, c.has(hostname))
		assert.True(t, c.get(hostname, dns.TypeA).Equal(net.ParseIP("192.0.2.2")))
		assert.Nil(t, c.get(hostname, dns.TypeAAAA))
		assert.Nil(t, c.get(hostname, dns.TypeTXT))
	}
	assert.False(t, c.has("unrelated.default"))

	updated = pbutils.Clone(updated).(*corev1.Service)
	updated.Status.Addresses = nil
	c.set(updated)
	for _, hostname := range []string{"svc", "svc.default", "alias.default"} {
		assert.False(t, c.has(hostname))
		assert.Nil(t, c.get(hostname, dns.TypeA))
	}

	c.set(svc)
	c.delete(svc)
	for _, hostname := range []string{"svc", "svc.default", "alias.default"} {
		assert.False(t, c.has(hostname))
	}
}

func TestCacheIPv6Only(t *testing.T) {
	c := newCache()
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "svc.ns1"},
		Status: &corev1.Service_Status{
			PrimaryHostname: "svc.ns1",
			Addresses: []*corev1.Service_Status_Address{
				nil,
				{},
				{DualStackIP: &metav1.DualStackIP{}},
				{DualStackIP: &metav1.DualStackIP{Ipv6: "2001:db8::1"}},
				{DualStackIP: &metav1.DualStackIP{Ipv6: "2001:db8::2"}},
			},
		},
	}
	c.set(svc)
	assert.True(t, c.has("svc.ns1"))
	assert.Nil(t, c.get("svc.ns1", dns.TypeA))
	for range 100 {
		addr := c.get("svc.ns1", dns.TypeAAAA)
		assert.True(t, addr.Equal(net.ParseIP("2001:db8::1")) || addr.Equal(net.ParseIP("2001:db8::2")))
	}
	c.delete(svc)
	assert.False(t, c.has("svc.ns1"))
	assert.Nil(t, c.get("svc.ns1", dns.TypeAAAA))
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := newCache()
	var wg sync.WaitGroup

	for worker := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostname := fmt.Sprintf("svc%d.default", worker)
			for range 100 {
				svc := &corev1.Service{
					Metadata: &metav1.Metadata{Name: hostname},
					Status: &corev1.Service_Status{
						PrimaryHostname: hostname,
						Addresses: []*corev1.Service_Status_Address{
							{DualStackIP: &metav1.DualStackIP{Ipv4: "192.0.2.1", Ipv6: "2001:db8::1"}},
						},
					},
				}
				c.set(svc)
				assert.True(t, c.has(hostname))
				assert.True(t, c.get(hostname, dns.TypeA).Equal(net.ParseIP("192.0.2.1")))
				assert.True(t, c.get(hostname, dns.TypeAAAA).Equal(net.ParseIP("2001:db8::1")))
				c.has("missing.default")
				c.get("missing.default", dns.TypeA)
				c.delete(svc)
			}
		}()
	}
	wg.Wait()
	assert.Empty(t, c.cMap)
}

func TestCacheEmptyAddresses(t *testing.T) {
	cache := newCache()

	newSvc := func(addrs []*corev1.Service_Status_Address) *corev1.Service {
		return &corev1.Service{
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
				Addresses: addrs,
			},
		}
	}

	{
		cache.set(newSvc(nil))
		assert.False(t, cache.has("svc1.default"))
		assert.Nil(t, cache.get("svc1.default", dns.TypeA))
		assert.Nil(t, cache.get("svc1.default", dns.TypeAAAA))
	}

	{
		cache.set(newSvc([]*corev1.Service_Status_Address{}))
		assert.False(t, cache.has("svc1.default"))
		assert.Nil(t, cache.get("svc1.default", dns.TypeA))
	}

	{
		cache.set(newSvc([]*corev1.Service_Status_Address{
			nil,
			{},
			{
				DualStackIP: &metav1.DualStackIP{},
			},
		}))
		assert.False(t, cache.has("svc1.default"))
		assert.Nil(t, cache.get("svc1.default", dns.TypeA))
		assert.Nil(t, cache.get("svc1.default", dns.TypeAAAA))
	}

	{
		cache.set(newSvc([]*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.4",
					Ipv6: "::1",
				},
			},
		}))
		assert.True(t, cache.has("svc1.default"))
		assert.True(t, cache.get("svc1.default", dns.TypeA).Equal(net.ParseIP("1.2.3.4")))

		cache.set(newSvc(nil))
		assert.False(t, cache.has("svc1.default"))
		assert.Nil(t, cache.get("svc1.default", dns.TypeA))
		assert.Nil(t, cache.get("svc1", dns.TypeA))
		assert.Nil(t, cache.get("svc1.default", dns.TypeAAAA))
	}
}

func TestCacheSingleFamilyAddresses(t *testing.T) {
	cache := newCache()

	newSvc := func(addrs []*corev1.Service_Status_Address) *corev1.Service {
		return &corev1.Service{
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
				Addresses: addrs,
			},
		}
	}

	{
		cache.set(newSvc([]*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.4",
				},
			},
		}))

		assert.True(t, cache.has("svc1.default"))
		assert.True(t, cache.get("svc1.default", dns.TypeA).Equal(net.ParseIP("1.2.3.4")))
		assert.Nil(t, cache.get("svc1.default", dns.TypeAAAA))
	}

	{
		cache.set(newSvc([]*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.4",
				},
			},
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.5",
					Ipv6: "::2",
				},
			},
			{
				DualStackIP: nil,
			},
		}))

		for range 100 {
			res := cache.get("svc1.default", dns.TypeAAAA)
			assert.True(t, res.Equal(net.ParseIP("::2")))
		}

		for range 100 {
			res := cache.get("svc1.default", dns.TypeA)
			assert.True(t, res.Equal(net.ParseIP("1.2.3.4")) || res.Equal(net.ParseIP("1.2.3.5")))
		}
	}

	{
		assert.Nil(t, cache.get("svc1.default", dns.TypeMX))
	}
}
