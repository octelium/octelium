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
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
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
