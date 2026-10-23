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
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/octelium/octelium/cluster/common/tests"
)

func TestZoneCache(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	zc := newZoneCache(0)

	domain := "www.google.com."
	typ := dns.TypeA
	assert.Nil(t, zc.get(domain, typ))

	{
		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(domain, typ)
		r, _, err := c.Exchange(m, "8.8.8.8:53")
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)

		zc.set(domain, typ, r)

		cr := zc.get(domain, typ)
		assert.NotNil(t, cr)

		{
			assert.Nil(t, zc.get("does-not.exist.com.", typ))
		}

		assert.Equal(t, (cr.Answer[0].(*dns.A)).A.String(), (r.Answer[0].(*dns.A)).A.String())

		zc.doCleanup()

		cr = zc.get(domain, typ)
		assert.NotNil(t, cr)
	}
}

func TestZoneCacheResponseTypes(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeMX, dns.TypeCNAME, dns.TypeANY} {
		for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeRefused} {
			t.Run(fmt.Sprintf("%s/%s", dns.TypeToString[qtype], dns.RcodeToString[rcode]), func(t *testing.T) {
				c := newZoneCache(time.Minute)
				msg := &dns.Msg{}
				msg.SetQuestion("example.com.", qtype)
				msg.SetRcode(msg, rcode)
				c.set("example.com.", qtype, msg)
				if rcode == dns.RcodeSuccess && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
					assert.Equal(t, msg.Copy(), c.get("example.com.", qtype))
					assert.Equal(t, 1, len(c.cMap))
				} else {
					assert.Nil(t, c.get("example.com.", qtype))
					assert.Empty(t, c.cMap)
				}
			})
		}
	}
}

func TestZoneCacheCopyIsolation(t *testing.T) {
	c := newZoneCache(time.Minute)
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.1"),
	}}
	msg.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns.example.com.",
	}}
	msg.SetEdns0(1232, true)
	want := msg.Copy()
	c.set("example.com.", dns.TypeA, msg)

	msg.Id++
	msg.Question[0].Name = "changed.example."
	msg.Answer[0].(*dns.A).A[0]++
	msg.Ns[0].(*dns.NS).Ns = "changed.example."
	msg.IsEdns0().SetUDPSize(512)
	assert.Equal(t, want, c.get("example.com.", dns.TypeA))

	got := c.get("example.com.", dns.TypeA)
	require.NotNil(t, got)
	got.Id++
	got.Question[0].Name = "another.example."
	got.Answer[0].(*dns.A).A[0]++
	got.Ns[0].(*dns.NS).Ns = "another.example."
	got.IsEdns0().SetUDPSize(4096)
	assert.Equal(t, want, c.get("example.com.", dns.TypeA))

	assert.Nil(t, c.get("example.com.", dns.TypeAAAA))
	assert.Nil(t, c.get("other.example.com.", dns.TypeA))
}

func TestZoneCacheExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newZoneCache(0)
		assert.Equal(t, 30*time.Second, c.duration)
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.SetReply(msg)
		c.set("example.com.", dns.TypeA, msg)

		time.Sleep(29 * time.Second)
		assert.NotNil(t, c.get("example.com.", dns.TypeA))
		time.Sleep(2 * time.Second)
		assert.Nil(t, c.get("example.com.", dns.TypeA))
		assert.Equal(t, 1, len(c.cMap))
		c.doCleanup()
		assert.Empty(t, c.cMap)

		c.setDuration(time.Minute)
		assert.Equal(t, time.Minute, c.duration)
		c.set("example.com.", dns.TypeA, msg)
		time.Sleep(31 * time.Second)
		assert.NotNil(t, c.get("example.com.", dns.TypeA))
		time.Sleep(30 * time.Second)
		assert.Nil(t, c.get("example.com.", dns.TypeA))

		c.setDuration(0)
		assert.Equal(t, 30*time.Second, c.duration)
		c.set("example.com.", dns.TypeA, msg)
		assert.NotNil(t, c.get("example.com.", dns.TypeA))
		time.Sleep(31 * time.Second)
		assert.Nil(t, c.get("example.com.", dns.TypeA))
	})
}

func TestZoneCacheCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newZoneCache(time.Minute)
		msg := &dns.Msg{}
		msg.SetQuestion("old.example.com.", dns.TypeA)
		msg.SetReply(msg)
		c.set("old.example.com.", dns.TypeA, msg)
		time.Sleep(31 * time.Second)
		msg.SetQuestion("new.example.com.", dns.TypeA)
		msg.SetReply(msg)
		c.set("new.example.com.", dns.TypeA, msg)
		time.Sleep(30 * time.Second)

		c.doCleanup()
		assert.Nil(t, c.get("old.example.com.", dns.TypeA))
		assert.NotNil(t, c.get("new.example.com.", dns.TypeA))
		assert.Equal(t, 1, len(c.cMap))
	})
}

func TestZoneCacheCleanupLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		c := newZoneCache(time.Minute)
		msg := &dns.Msg{}
		msg.SetQuestion("expired.example.com.", dns.TypeA)
		msg.SetReply(msg)
		c.set("expired.example.com.", dns.TypeA, msg)
		c.setDuration(2 * time.Hour)
		c.set("live.example.com.", dns.TypeA, msg)

		done := make(chan struct{})
		go func() {
			c.startCleanupLoop(ctx)
			close(done)
		}()
		synctest.Wait()
		time.Sleep(6 * time.Minute)
		synctest.Wait()
		assert.Nil(t, c.get("expired.example.com.", dns.TypeA))
		assert.NotNil(t, c.get("live.example.com.", dns.TypeA))
		c.RLock()
		assert.Equal(t, 1, len(c.cMap))
		c.RUnlock()

		time.Sleep(54 * time.Minute)
		synctest.Wait()
		c.RLock()
		assert.Empty(t, c.cMap)
		c.RUnlock()
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("The zone cache cleanup loop did not stop")
		}
	})
}

func TestZoneCacheConcurrentAccess(t *testing.T) {
	c := newZoneCache(time.Minute)
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			domain := fmt.Sprintf("svc%d.example.com.", worker)
			for range 100 {
				msg := &dns.Msg{}
				msg.SetQuestion(domain, dns.TypeA)
				msg.SetReply(msg)
				c.set(domain, dns.TypeA, msg)
				assert.Equal(t, msg.Copy(), c.get(domain, dns.TypeA))
				c.setDuration(time.Minute)
				c.doCleanup()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 16, len(c.cMap))
}
