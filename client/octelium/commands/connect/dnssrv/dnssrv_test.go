// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnssrv

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {
	cache := newCache()
	cache.duration = 2 * time.Second

	{
		c := dns.Client{}
		m := dns.Msg{}

		domain := "google.com."
		typ := dns.TypeA

		m.SetQuestion(domain, typ)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		r, _, err := c.ExchangeContext(ctx, &m, "8.8.8.8:53")
		assert.Nil(t, err)

		cache.set(domain, typ, r)
		res := cache.get(domain, typ)
		assert.NotNil(t, res)

		time.Sleep(3 * time.Second)
		res = cache.get(domain, typ)
		assert.Nil(t, res)
	}
}

type tstDNSGetter struct {
}

func (s *tstDNSGetter) GetClusterDNSServers() []string {
	return []string{"8.8.8.8"}
}

type tstEmptyDNSGetter struct {
}

func (s *tstEmptyDNSGetter) GetClusterDNSServers() []string {
	return nil
}

func TestNewDNSServerInvalidOpts(t *testing.T) {
	{
		srv, err := NewDNSServer(nil)
		assert.NotNil(t, err)
		assert.Nil(t, srv)
	}

	{
		srv, err := NewDNSServer(&Opts{
			ClusterDomain: "example.com",
			HasV4:         true,
		})
		assert.NotNil(t, err)
		assert.Nil(t, srv)
	}
}

func TestServerNoClusterDNSServers(t *testing.T) {
	srv, err := NewDNSServer(&Opts{
		ClusterDomain: "example.com",
		ListenAddr:    "127.0.0.100:18054",
		HasV4:         true,
		DNSGetter:     &tstEmptyDNSGetter{},
	})
	assert.Nil(t, err)
	assert.Nil(t, srv.Run())

	time.Sleep(1 * time.Second)

	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX} {
		c := dns.Client{}
		m := dns.Msg{}
		m.SetQuestion("svc1.local.example.com.", typ)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		r, _, err := c.ExchangeContext(ctx, &m, "127.0.0.100:18054")
		cancel()

		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeServerFailure, r.Rcode)
	}

	assert.Nil(t, srv.Close())
}

func TestServer(t *testing.T) {

	srv, err := NewDNSServer(&Opts{
		ClusterDomain: "example.com",
		ListenAddr:    "127.0.0.100:18053",
		HasV4:         true,
		DNSGetter:     &tstDNSGetter{},
	})
	assert.Nil(t, err)
	err = srv.Run()
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	{
		c := dns.Client{}
		m := dns.Msg{}

		domain := "google.com."
		typ := dns.TypeA

		m.SetQuestion(domain, typ)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, _, err := c.ExchangeContext(ctx, &m, "127.0.0.100:18053")
		assert.Nil(t, err)

	}

	{
		assert.Equal(t, "127.0.0.100", srv.ListenHost())
	}

	{
		assert.True(t, srv.isClusterName("svc1."))
		assert.True(t, srv.isClusterName("svc1.local."))
		assert.True(t, srv.isClusterName("svc1.ns1.local."))
		assert.True(t, srv.isClusterName("svc1.local.example.com."))
		assert.True(t, srv.isClusterName("SVC1.Local.Example.COM."))
		assert.True(t, srv.isClusterName("svc1.example.com.local."))

		assert.False(t, srv.isClusterName("svc1.com."))
		assert.False(t, srv.isClusterName("svc1.io."))
		assert.False(t, srv.isClusterName("svc1.default."))
		assert.False(t, srv.isClusterName("example.com."))
		assert.False(t, srv.isClusterName("portal.example.com."))
		assert.False(t, srv.isClusterName("something.cloud."))
		assert.False(t, srv.isClusterName("foo.online."))
	}

	err = srv.Close()
	assert.Nil(t, err)
}

func TestServerRunReportsBindFailure(t *testing.T) {
	addr := "127.0.0.100:18055"

	blocker, err := net.ListenPacket("udp", addr)
	assert.Nil(t, err)
	defer blocker.Close()

	srv, err := NewDNSServer(&Opts{
		ClusterDomain: "example.com",
		ListenAddr:    addr,
		HasV4:         true,
		DNSGetter:     &tstDNSGetter{},
	})
	assert.Nil(t, err)

	assert.NotNil(t, srv.Run())
	assert.Nil(t, srv.Close())
}

func TestServerRunIsListeningWhenItReturns(t *testing.T) {
	addr := "127.0.0.100:18056"

	srv, err := NewDNSServer(&Opts{
		ClusterDomain: "example.com",
		ListenAddr:    addr,
		HasV4:         true,
		DNSGetter:     &tstDNSGetter{},
	})
	assert.Nil(t, err)
	assert.Nil(t, srv.Run())

	c := dns.Client{Timeout: 5 * time.Second}
	m := dns.Msg{}
	m.SetQuestion("svc1.local.example.com.", dns.TypeA)

	_, _, err = c.Exchange(&m, addr)
	assert.Nil(t, err)

	assert.Nil(t, srv.Close())
}
