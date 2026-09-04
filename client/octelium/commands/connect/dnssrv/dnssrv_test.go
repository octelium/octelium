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
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func newTestCachedMsg(domain string, ttl uint32) *dns.Msg {
	m := &dns.Msg{}
	m.SetQuestion(domain, dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	m.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl,
			},
			A: net.ParseIP("1.2.3.4"),
		},
	}

	return m
}

func TestCache(t *testing.T) {
	c := newCache()

	domain := "svc1.local.example.com."

	c.set(domain, dns.TypeA, newTestCachedMsg(domain, 60))

	res := c.get(domain, dns.TypeA)
	assert.NotNil(t, res)
	assert.Equal(t, uint32(60), res.Answer[0].Header().Ttl)

	res.Answer[0].Header().Ttl = 1
	assert.Equal(t, uint32(60), c.get(domain, dns.TypeA).Answer[0].Header().Ttl)

	assert.Nil(t, c.get(domain, dns.TypeAAAA))
	assert.Nil(t, c.get("other.local.example.com.", dns.TypeA))
}

func TestCacheKeyIsCaseInsensitive(t *testing.T) {
	c := newCache()

	c.set("SVC1.Local.Example.COM.", dns.TypeA,
		newTestCachedMsg("SVC1.Local.Example.COM.", 60))

	assert.NotNil(t, c.get("svc1.local.example.com.", dns.TypeA))
	assert.NotNil(t, c.get("SVC1.LOCAL.EXAMPLE.COM.", dns.TypeA))
}

func TestCacheRespectsRecordTTL(t *testing.T) {
	c := newCache()

	domain := "svc1.local.example.com."

	c.set(domain, dns.TypeA, newTestCachedMsg(domain, 10))

	time.Sleep(1100 * time.Millisecond)

	res := c.get(domain, dns.TypeA)
	assert.NotNil(t, res)
	assert.True(t, res.Answer[0].Header().Ttl < 10)
	assert.True(t, res.Answer[0].Header().Ttl >= 8)
}

func TestCacheTTLIsClamped(t *testing.T) {
	assert.Equal(t, time.Duration(0), getMsgTTL(newTestCachedMsg("a.", 0)))
	assert.Equal(t, cacheMinTTL, getMsgTTL(newTestCachedMsg("a.", 1)))
	assert.Equal(t, 60*time.Second, getMsgTTL(newTestCachedMsg("a.", 60)))
	assert.Equal(t, cacheMaxTTL, getMsgTTL(newTestCachedMsg("a.", 86400)))
}

func TestCacheSkipsUncacheableResponses(t *testing.T) {
	c := newCache()

	domain := "svc1.local.example.com."

	failure := newTestCachedMsg(domain, 60)
	failure.Rcode = dns.RcodeNameError
	c.set(domain, dns.TypeA, failure)
	assert.Nil(t, c.get(domain, dns.TypeA))

	truncated := newTestCachedMsg(domain, 60)
	truncated.Truncated = true
	c.set(domain, dns.TypeA, truncated)
	assert.Nil(t, c.get(domain, dns.TypeA))

	c.set(domain, dns.TypeMX, newTestCachedMsg(domain, 60))
	assert.Nil(t, c.get(domain, dns.TypeMX))

	c.set(domain, dns.TypeA, nil)
	assert.Nil(t, c.get(domain, dns.TypeA))

	c.set(domain, dns.TypeA, newTestCachedMsg(domain, 0))
	assert.Nil(t, c.get(domain, dns.TypeA))
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

type tstResponseWriter struct {
	msg *dns.Msg
}

func (w *tstResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.100"), Port: 53}
}

func (w *tstResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
}

func (w *tstResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}

func (w *tstResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *tstResponseWriter) Close() error                { return nil }
func (w *tstResponseWriter) TsigStatus() error           { return nil }
func (w *tstResponseWriter) TsigTimersOnly(bool)         {}
func (w *tstResponseWriter) Hijack()                     {}

func TestWriteUpstreamReplyPreservesRcodeAndFlags(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("nope.local.example.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	resp.Authoritative = true
	resp.Id = 4242

	w := &tstResponseWriter{}
	writeUpstreamReply(w, req, resp)

	assert.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeNameError, w.msg.Rcode)
	assert.True(t, w.msg.Authoritative)
	assert.True(t, w.msg.Response)
	assert.True(t, w.msg.RecursionAvailable)
	assert.Equal(t, req.Id, w.msg.Id)
	assert.Equal(t, req.Question, w.msg.Question)
}

func TestWriteUpstreamReplyTruncatesToRequestSize(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("big.local.example.com.", dns.TypeTXT)

	resp := new(dns.Msg)
	resp.SetReply(req)
	for i := range 20 {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name: req.Question[0].Name, Rrtype: dns.TypeTXT,
				Class: dns.ClassINET, Ttl: 60,
			},
			Txt: []string{strings.Repeat("x", 200) + string(rune('a'+i))},
		})
	}
	assert.True(t, resp.Len() > dns.MinMsgSize)

	w := &tstResponseWriter{}
	writeUpstreamReply(w, req, resp)

	assert.NotNil(t, w.msg)
	assert.True(t, w.msg.Truncated)
	assert.True(t, w.msg.Len() <= dns.MinMsgSize)
}

func TestWriteUpstreamReplyHonorsEdns0Size(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("big.local.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)

	assert.Equal(t, 4096, getRequestUDPSize(req))

	resp := new(dns.Msg)
	resp.SetReply(req)
	for i := range 5 {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name: req.Question[0].Name, Rrtype: dns.TypeTXT,
				Class: dns.ClassINET, Ttl: 60,
			},
			Txt: []string{strings.Repeat("x", 200) + string(rune('a'+i))},
		})
	}

	w := &tstResponseWriter{}
	writeUpstreamReply(w, req, resp)

	assert.NotNil(t, w.msg)
	assert.False(t, w.msg.Truncated)
	assert.Equal(t, 5, len(w.msg.Answer))
}

func TestGetRequestUDPSizeDefaultsToMin(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("a.", dns.TypeA)
	assert.Equal(t, dns.MinMsgSize, getRequestUDPSize(req))

	req.SetEdns0(100, false)
	assert.Equal(t, dns.MinMsgSize, getRequestUDPSize(req))
}

func TestGetBootstrapDomains(t *testing.T) {
	assert.Equal(t, []string{"example.com.", "octelium-api.example.com."},
		getBootstrapDomains("example.com"))

	assert.Equal(t, []string{"example.com.", "octelium-api.example.com."},
		getBootstrapDomains("Example.COM."))

	assert.Nil(t, getBootstrapDomains(""))
	assert.Nil(t, getBootstrapDomains("   "))
	assert.Nil(t, getBootstrapDomains("example com"))
}

func TestBootstrapCache(t *testing.T) {
	c := newBootstrapCache()

	domain := "octelium-api.example.com."

	assert.Nil(t, c.get(domain, dns.TypeA))

	c.set(domain, []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("fd00::1")})

	res := c.get(domain, dns.TypeA)
	assert.NotNil(t, res)
	assert.Equal(t, 1, len(res.Answer))
	assert.Equal(t, "1.2.3.4", res.Answer[0].(*dns.A).A.String())
	assert.Equal(t, uint32(bootstrapTTL), res.Answer[0].Header().Ttl)

	res.Answer[0].Header().Ttl = 1
	assert.Equal(t, uint32(bootstrapTTL), c.get(domain, dns.TypeA).Answer[0].Header().Ttl)

	res = c.get(domain, dns.TypeAAAA)
	assert.NotNil(t, res)
	assert.Equal(t, 1, len(res.Answer))
	assert.Equal(t, "fd00::1", res.Answer[0].(*dns.AAAA).AAAA.String())

	assert.NotNil(t, c.get("OCTELIUM-API.Example.COM.", dns.TypeA))
	assert.Nil(t, c.get("example.com.", dns.TypeA))
	assert.Nil(t, c.get(domain, dns.TypeMX))
}

func TestBootstrapCacheWithoutAddrs(t *testing.T) {
	c := newBootstrapCache()

	domain := "octelium-api.example.com."

	c.set(domain, nil)
	assert.Nil(t, c.get(domain, dns.TypeA))

	c.set(domain, []net.IP{net.ParseIP("1.2.3.4")})

	res := c.get(domain, dns.TypeAAAA)
	assert.NotNil(t, res)
	assert.Equal(t, 0, len(res.Answer))
	assert.Equal(t, dns.RcodeSuccess, res.Rcode)
}

func newTestFullDNSServer(t *testing.T, listenAddr string, getter DNSGetter) *Server {
	srv, err := NewDNSServer(&Opts{
		ClusterDomain: "example.com",
		ListenAddr:    listenAddr,
		HasV4:         true,
		HasV6:         true,
		DNSGetter:     getter,
		IsFullDNS:     true,
		LookupIPFn: func(ctx context.Context, host string) ([]net.IP, error) {
			switch host {
			case "octelium-api.example.com":
				return []net.IP{net.ParseIP("1.2.3.4")}, nil
			case "example.com":
				return []net.IP{net.ParseIP("5.6.7.8")}, nil
			default:
				return nil, errors.Errorf("Unknown host: %s", host)
			}
		},
	})
	assert.Nil(t, err)

	return srv
}

func TestServerBootstrapAnswersWithoutClusterDNSServers(t *testing.T) {
	addr := "127.0.0.100:18057"

	srv := newTestFullDNSServer(t, addr, &tstEmptyDNSGetter{})
	assert.Nil(t, srv.Run())

	c := dns.Client{Timeout: 5 * time.Second}

	{
		m := dns.Msg{}
		m.SetQuestion("octelium-api.example.com.", dns.TypeA)

		r, _, err := c.Exchange(&m, addr)
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
		assert.Equal(t, 1, len(r.Answer))
		assert.Equal(t, "1.2.3.4", r.Answer[0].(*dns.A).A.String())
	}

	{
		m := dns.Msg{}
		m.SetQuestion("EXAMPLE.com.", dns.TypeA)

		r, _, err := c.Exchange(&m, addr)
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
		assert.Equal(t, 1, len(r.Answer))
		assert.Equal(t, "5.6.7.8", r.Answer[0].(*dns.A).A.String())
	}

	{
		m := dns.Msg{}
		m.SetQuestion("octelium-api.example.com.", dns.TypeAAAA)

		r, _, err := c.Exchange(&m, addr)
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)
		assert.Equal(t, 0, len(r.Answer))
	}

	{
		m := dns.Msg{}
		m.SetQuestion("google.com.", dns.TypeA)

		r, _, err := c.Exchange(&m, addr)
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeServerFailure, r.Rcode)
	}

	assert.Nil(t, srv.Close())
}

func TestServerBootstrapAnswersOnUpstreamFailure(t *testing.T) {
	srv := newTestFullDNSServer(t, "127.0.0.100:18058", &tstDNSGetter{})
	srv.setBootstrapAnswers(context.Background())

	unreachable := []string{"127.0.0.1:1"}

	{
		ret, err := srv.getExchangeAnswer("octelium-api.example.com.", dns.TypeA, unreachable)
		assert.Nil(t, err)
		assert.NotNil(t, ret)
		assert.Equal(t, "1.2.3.4", ret.Answer[0].(*dns.A).A.String())
	}

	{
		ret, err := srv.getExchangeAnswer("google.com.", dns.TypeA, unreachable)
		assert.NotNil(t, err)
		assert.Nil(t, ret)
	}

	{
		ret, err := srv.getExchangeAnswer("octelium-api.example.com.", dns.TypeA, nil)
		assert.Nil(t, err)
		assert.NotNil(t, ret)
	}
}

func TestServerSkipsBootstrapAnswersInSplitDNSMode(t *testing.T) {
	srv, err := NewDNSServer(&Opts{
		ClusterDomain: "example.com",
		ListenAddr:    "127.0.0.100:18059",
		HasV4:         true,
		DNSGetter:     &tstEmptyDNSGetter{},
		LookupIPFn: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		},
	})
	assert.Nil(t, err)

	srv.setBootstrapAnswers(context.Background())

	assert.Nil(t, srv.getBootstrapAnswer("octelium-api.example.com.", dns.TypeA))

	ret, err := srv.getExchangeAnswer("octelium-api.example.com.", dns.TypeA, nil)
	assert.NotNil(t, err)
	assert.Nil(t, ret)
}

type tstFailingHandler struct {
}

func (h *tstFailingHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetRcode(r, dns.RcodeServerFailure)
	w.WriteMsg(msg)
}

func TestServerBootstrapAnswersOnUnsuccessfulClusterReply(t *testing.T) {
	addr := "127.0.0.100:18060"

	startedCh := make(chan struct{})
	upstream := &dns.Server{
		Addr:              addr,
		Net:               "udp",
		Handler:           &tstFailingHandler{},
		NotifyStartedFunc: func() { close(startedCh) },
	}
	go upstream.ListenAndServe()
	<-startedCh
	defer upstream.Shutdown()

	srv := newTestFullDNSServer(t, "127.0.0.100:18061", &tstDNSGetter{})
	srv.setBootstrapAnswers(context.Background())

	{
		ret, err := srv.getExchangeAnswer("octelium-api.example.com.", dns.TypeA, []string{addr})
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeSuccess, ret.Rcode)
		assert.Equal(t, "1.2.3.4", ret.Answer[0].(*dns.A).A.String())
	}

	{
		ret, err := srv.getExchangeAnswer("google.com.", dns.TypeA, []string{addr})
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeServerFailure, ret.Rcode)
	}
}
