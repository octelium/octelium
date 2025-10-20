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

	err = srv.Close()
	assert.Nil(t, err)
}
