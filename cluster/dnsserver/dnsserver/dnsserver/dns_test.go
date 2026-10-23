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
	"crypto/tls"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
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

	{
		res, err := dnsSrv.getHostname("svc1.ns0.local.example.com.")
		assert.Nil(t, err)
		assert.Equal(t, "svc1.ns0", res)
	}

	{
		res, err := dnsSrv.getHostname("svc1.local.example.com.")
		assert.Nil(t, err)
		assert.Equal(t, "svc1.default", res)
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
		assert.Equal(t, "svc1.default", res)
	}

	{
		res, err := dnsSrv.getHostname("svc1.")
		assert.Nil(t, err)
		assert.Equal(t, "svc1.default", res)
	}

	{
		res, err := dnsSrv.getHostname("svc1.default.local.")
		assert.Nil(t, err)
		assert.Equal(t, "svc1.default", res)
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

type tstDNSResponseWriter struct {
	msg    *dns.Msg
	err    error
	writes int
}

func (w *tstDNSResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (w *tstDNSResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (w *tstDNSResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.writes++
	w.msg = msg.Copy()
	return w.err
}

func (w *tstDNSResponseWriter) Write(data []byte) (int, error) {
	return len(data), w.err
}

func (w *tstDNSResponseWriter) Close() error { return nil }

func (w *tstDNSResponseWriter) TsigStatus() error { return nil }

func (w *tstDNSResponseWriter) TsigTimersOnly(bool) {}

func (w *tstDNSResponseWriter) Hijack() {}

func newTstDNSServer() *DNSServer {
	s := &DNSServer{
		domain:             "example.com",
		cache:              newCache(),
		fallbackZoneCache:  newZoneCache(0),
		reservedNamespaces: wellKnownTLDs,
	}
	s.setDNSConfig(nil)
	return s
}

func newTstDNSService() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{Name: "svc.default"},
		Spec:     &corev1.Service_Spec{},
		Status: &corev1.Service_Status{
			PrimaryHostname:     "svc",
			AdditionalHostnames: []string{"svc.default"},
			Addresses: []*corev1.Service_Status_Address{
				{DualStackIP: &metav1.DualStackIP{Ipv4: "192.0.2.1", Ipv6: "2001:db8::1"}},
			},
		},
	}
}

func newTstDNSUpstream(t *testing.T, handler dns.Handler) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.Nil(t, err)
	started := make(chan struct{})
	done := make(chan error, 1)
	srv := &dns.Server{
		PacketConn:        conn,
		Handler:           handler,
		NotifyStartedFunc: func() { close(started) },
	}
	go func() {
		done <- srv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		assert.Nil(t, srv.Shutdown())
		assert.Nil(t, <-done)
	})
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("The DNS upstream did not start")
	}
	return conn.LocalAddr().String()
}

func tstDNSAnswer(r *dns.Msg) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetReply(r)
	q := r.Question[0]
	hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 300}
	switch q.Qtype {
	case dns.TypeA:
		msg.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("198.51.100.1")}}
	case dns.TypeAAAA:
		msg.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::2")}}
	case dns.TypeTXT:
		msg.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"upstream"}}}
	}
	return msg
}

func TestGetHostnameBoundaries(t *testing.T) {
	s := newTstDNSServer()
	s.Set(newTstDNSService())
	for _, hostname := range []string{"svc.ns1", "svc.com", "svc.octelium", "svc.octelium-api", "svc.cordium"} {
		svc := newTstDNSService()
		svc.Status.PrimaryHostname = hostname
		svc.Status.AdditionalHostnames = nil
		s.Set(svc)
	}
	s.reservedNamespaces = append(append([]string{}, wellKnownTLDs...), wellKnownNamespaces...)

	for _, tc := range []struct {
		arg  string
		want string
	}{
		{arg: "svc.local.example.com.", want: "svc.default"},
		{arg: "svc.example.com.local.", want: "svc.default"},
		{arg: "svc.default.local.", want: "svc.default"},
		{arg: "svc.ns1.local.example.com.", want: "svc.ns1"},
		{arg: "prefix.more.svc.ns1.local.", want: "svc.ns1"},
		{arg: "svc.com.local.", want: "svc.com"},
		{arg: "svc.", want: "svc.default"},
		{arg: "svc", want: "svc.default"},
		{arg: "svc.default.", want: "svc.default"},
		{arg: "svc.ns1.", want: "svc.ns1"},
		{arg: "svc.octelium.", want: "svc.octelium"},
		{arg: "svc.octelium-api.", want: "svc.octelium-api"},
		{arg: "svc.cordium.", want: "svc.cordium"},
		{arg: ".local.", want: "default.default"},
		{arg: ""},
		{arg: "."},
		{arg: strings.Repeat("a", 257)},
		{arg: "missing."},
		{arg: "missing.ns1."},
		{arg: "svc.com."},
		{arg: "svc.notlocal.example.com."},
		{arg: "svc.local.example.com.invalid."},
		{arg: "sub.svc.ns1."},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			got, err := s.getHostname(tc.arg)
			assert.Equal(t, tc.want, got)
			if tc.want == "" {
				assert.ErrorIs(t, err, errNotFound)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestServeDNSLocalAnswers(t *testing.T) {
	s := newTstDNSServer()
	svc := newTstDNSService()
	s.Set(svc)
	for _, name := range []string{
		"svc.local.", "SvC.DeFaUlT.LoCaL.", "svc.local.example.com.",
		"svc.default.example.com.local.", "svc.default.", "svc.",
	} {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			t.Run(fmt.Sprintf("%s/%s", name, dns.TypeToString[qtype]), func(t *testing.T) {
				r := &dns.Msg{}
				r.SetQuestion(name, qtype)
				w := &tstDNSResponseWriter{}
				s.ServeDNS(w, r)
				require.NotNil(t, w.msg)
				assert.Equal(t, 1, w.writes)
				assert.Equal(t, r.Id, w.msg.Id)
				assert.Equal(t, r.Question, w.msg.Question)
				assert.True(t, w.msg.Response)
				assert.True(t, w.msg.Authoritative)
				assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
				require.Equal(t, 1, len(w.msg.Answer))
				hdr := w.msg.Answer[0].Header()
				assert.Equal(t, strings.ToLower(name), hdr.Name)
				assert.Equal(t, qtype, hdr.Rrtype)
				assert.Equal(t, uint16(dns.ClassINET), hdr.Class)
				assert.Equal(t, uint32(60), hdr.Ttl)
				switch rr := w.msg.Answer[0].(type) {
				case *dns.A:
					assert.True(t, rr.A.Equal(net.ParseIP("192.0.2.1")))
				case *dns.AAAA:
					assert.True(t, rr.AAAA.Equal(net.ParseIP("2001:db8::1")))
				default:
					t.Fatalf("Unexpected answer: %T", rr)
				}
			})
		}
	}

	s.Unset(svc)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r := &dns.Msg{}
		r.SetQuestion("svc.default.local.", qtype)
		w := &tstDNSResponseWriter{}
		s.ServeDNS(w, r)
		require.NotNil(t, w.msg)
		assert.Equal(t, dns.RcodeNameError, w.msg.Rcode)
		assert.Empty(t, w.msg.Answer)
	}
}

func TestServeDNSInvalidRequests(t *testing.T) {
	s := newTstDNSServer()
	w := &tstDNSResponseWriter{}
	s.ServeDNS(w, nil)
	assert.Zero(t, w.writes)

	for _, tc := range []struct {
		name string
		r    *dns.Msg
	}{
		{name: "NoQuestions", r: &dns.Msg{MsgHdr: dns.MsgHdr{Id: 123}}},
		{name: "EmptyName", r: &dns.Msg{Question: []dns.Question{{Qtype: dns.TypeA, Qclass: dns.ClassINET}}}},
		{name: "EmptyLabel", r: &dns.Msg{Question: []dns.Question{{Name: "svc..local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}},
		{name: "NUL", r: &dns.Msg{Question: []dns.Question{{Name: "svc\x00.local.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}}},
		{name: "OversizedLabel", r: &dns.Msg{Question: []dns.Question{{Name: strings.Repeat("a", 64) + ".local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}},
		{name: "Space", r: &dns.Msg{Question: []dns.Question{{Name: "bad name.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &tstDNSResponseWriter{}
			s.ServeDNS(w, tc.r)
			require.NotNil(t, w.msg)
			assert.Equal(t, 1, w.writes)
			assert.Equal(t, tc.r.Id, w.msg.Id)
			assert.Equal(t, dns.RcodeRefused, w.msg.Rcode)
			assert.Empty(t, w.msg.Answer)
		})
	}
}

func TestServeDNSProxiedAnswers(t *testing.T) {
	queries := make(chan *dns.Msg, 20)
	addr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries <- r.Copy()
		assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
	}))
	s := newTstDNSServer()
	s.Set(newTstDNSService())
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{addr}}},
	}})
	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{name: "EXTERNAL.EXAMPLE.", qtype: dns.TypeA},
		{name: "external.example.", qtype: dns.TypeAAAA},
		{name: "svc.default.local.", qtype: dns.TypeTXT},
		{name: "svc.default.local.", qtype: dns.TypeMX},
		{name: "_sip._tcp.example.com.", qtype: dns.TypeSRV},
		{name: "_dmarc.example.com.", qtype: dns.TypeTXT},
		{name: "1.2.0.192.in-addr.arpa.", qtype: dns.TypePTR},
		{name: ".", qtype: dns.TypeNS},
		{name: "example.com.", qtype: dns.TypeCAA},
		{name: "example.com.", qtype: dns.TypeSOA},
		{name: "example.com.", qtype: dns.TypeANY},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.name, dns.TypeToString[tc.qtype]), func(t *testing.T) {
			r := &dns.Msg{}
			r.SetQuestion(tc.name, tc.qtype)
			w := &tstDNSResponseWriter{}
			s.ServeDNS(w, r)
			require.NotNil(t, w.msg)
			assert.Equal(t, 1, w.writes)
			assert.Equal(t, r.Id, w.msg.Id)
			assert.Equal(t, r.Question, w.msg.Question)
			assert.True(t, w.msg.Response)
			assert.True(t, w.msg.RecursionAvailable)
			assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
			query := <-queries
			assert.Equal(t, strings.ToLower(tc.name), query.Question[0].Name)
			assert.Equal(t, tc.qtype, query.Question[0].Qtype)
			assert.Equal(t, uint16(dns.ClassINET), query.Question[0].Qclass)
		})
	}
}

func TestServeDNSUpstreamFailure(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.Nil(t, err)
	addr := conn.LocalAddr().String()
	require.Nil(t, conn.Close())
	s := newTstDNSServer()
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{addr}}},
	}})
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
		r := &dns.Msg{}
		r.SetQuestion("external.example.", qtype)
		w := &tstDNSResponseWriter{}
		s.ServeDNS(w, r)
		require.NotNil(t, w.msg)
		assert.Equal(t, 1, w.writes)
		assert.Equal(t, r.Id, w.msg.Id)
		assert.Equal(t, r.Question, w.msg.Question)
		assert.Equal(t, dns.RcodeServerFailure, w.msg.Rcode)
		assert.Empty(t, w.msg.Answer)
		assert.Nil(t, s.fallbackZoneCache.get("external.example.", qtype))
	}
}

func TestGetRequestUDPSize(t *testing.T) {
	r := &dns.Msg{}
	assert.Equal(t, dns.MinMsgSize, getRequestUDPSize(r))
	for _, size := range []uint16{0, 1, 511, 512, 1232, 4096, 65535} {
		r := &dns.Msg{}
		r.SetEdns0(size, false)
		assert.Equal(t, max(dns.MinMsgSize, int(size)), getRequestUDPSize(r))
	}
}

func TestWriteUpstreamReply(t *testing.T) {
	for _, size := range []uint16{0, 128, 512, 1232, 4096} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			r := &dns.Msg{}
			r.SetQuestion("EXAMPLE.COM.", dns.TypeTXT)
			if size != 0 {
				r.SetEdns0(size, false)
			}
			resp := &dns.Msg{}
			resp.SetQuestion("example.com.", dns.TypeTXT)
			resp.Id = r.Id + 1
			for range 10 {
				resp.Answer = append(resp.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 30},
					Txt: []string{strings.Repeat("a", 200)},
				})
			}
			w := &tstDNSResponseWriter{}
			writeUpstreamReply(w, r, resp)
			require.NotNil(t, w.msg)
			assert.Equal(t, 1, w.writes)
			assert.Equal(t, r.Id, w.msg.Id)
			assert.Equal(t, r.Question, w.msg.Question)
			assert.True(t, w.msg.Response)
			assert.True(t, w.msg.RecursionAvailable)
			data, err := w.msg.Pack()
			require.Nil(t, err)
			assert.LessOrEqual(t, len(data), max(dns.MinMsgSize, int(size)))
			assert.Equal(t, size < 4096, w.msg.Truncated)
			if size == 4096 {
				assert.Equal(t, 10, len(w.msg.Answer))
			}
		})
	}

	r := &dns.Msg{}
	r.SetQuestion("example.com.", dns.TypeA)
	resp := tstDNSAnswer(r)
	w := &tstDNSResponseWriter{err: errors.New("write failed")}
	assert.NotPanics(t, func() { writeUpstreamReply(w, r, resp) })
	assert.Equal(t, 1, w.writes)
}

func TestParseZoneUpstreams(t *testing.T) {
	for _, tc := range []struct {
		server string
		want   *upstream
	}{
		{server: "192.0.2.1", want: &upstream{host: "192.0.2.1", port: 53}},
		{server: "2001:db8::1", want: &upstream{host: "2001:db8::1", port: 53}},
		{server: "resolver.example.com", want: &upstream{host: "resolver.example.com", port: 53}},
		{server: "resolver.example.com:5353", want: &upstream{host: "resolver.example.com", port: 5353}},
		{server: "[2001:db8::1]:5353", want: &upstream{host: "2001:db8::1", port: 5353}},
		{server: "dns://192.0.2.1", want: &upstream{host: "192.0.2.1", port: 53}},
		{server: "udp://resolver.example.com:65535", want: &upstream{host: "resolver.example.com", port: 65535}},
		{server: "udp://[2001:db8::1]:1", want: &upstream{host: "2001:db8::1", port: 1}},
		{server: "tls://resolver.example.com", want: &upstream{host: "resolver.example.com", port: 853, typ: "tcp-tls"}},
		{server: "tls://[2001:db8::1]:8853", want: &upstream{host: "2001:db8::1", port: 8853, typ: "tcp-tls"}},
		{server: ""},
		{server: "udp://"},
		{server: "udp://:53"},
		{server: "udp://[invalid"},
		{server: "udp://resolver.example.com:abc"},
		{server: "udp://resolver.example.com:0"},
		{server: "udp://resolver.example.com:65536"},
		{server: "udp://resolver.example.com:-1"},
		{server: "udp://resolver.example.com:9999999999999999999999"},
		{server: "udp://user:password@resolver.example.com"},
		{server: "udp://resolver.example.com/path"},
		{server: "udp://resolver.example.com?query=1"},
		{server: "udp://resolver.example.com#fragment"},
		{server: "udp://bad host"},
		{server: "https://resolver.example.com"},
		{server: "tcp://resolver.example.com"},
	} {
		t.Run(tc.server, func(t *testing.T) {
			got := parseZoneUpstreams([]string{tc.server})
			if tc.want == nil {
				assert.Empty(t, got)
				return
			}
			require.Equal(t, 1, len(got))
			assert.Equal(t, tc.want, got[0])
			assert.Equal(t, net.JoinHostPort(tc.want.host, fmt.Sprintf("%d", tc.want.port)), got[0].getAddr())
		})
	}
	assert.Equal(t, []*upstream{{host: "192.0.2.1", port: 53}}, parseZoneUpstreams([]string{"bad://host", "192.0.2.1", ""}))
}

func TestDNSConfigDefaults(t *testing.T) {
	for _, cc := range []*corev1.ClusterConfig{
		nil,
		{},
		{Spec: &corev1.ClusterConfig_Spec{}},
		{Spec: &corev1.ClusterConfig_Spec{Dns: &corev1.ClusterConfig_Spec_DNS{}}},
		{Spec: &corev1.ClusterConfig_Spec{Dns: &corev1.ClusterConfig_Spec_DNS{
			FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{"invalid://resolver"}},
		}}},
	} {
		s := newTstDNSServer()
		s.setDNSConfig(cc)
		assert.Equal(t, []*upstream{
			{host: "8.8.8.8", port: 853, typ: "tcp-tls"},
			{host: "1.1.1.1", port: 853, typ: "tcp-tls"},
		}, s.upstreams)
		assert.Equal(t, s.upstreams, s.fallbackZone.upstreams)
		assert.Same(t, s.fallbackZoneCache, s.fallbackZone.cache)
		assert.Equal(t, 30*time.Second, s.fallbackZone.cache.duration)
		assert.Empty(t, s.zones)
		assert.Same(t, s.fallbackZone, s.getDNSZone("example.com."))
	}
}

func TestDNSConfigZones(t *testing.T) {
	s := newTstDNSServer()
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{
			FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
				Servers:       []string{"192.0.2.1"},
				CacheDuration: &metav1.Duration{Type: &metav1.Duration_Seconds{Seconds: 5}},
			},
			Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
				nil,
				{},
				{Domains: []string{"empty.example"}},
				{Domains: []string{"invalid.example"}, Servers: []string{"invalid://resolver"}},
				{Domains: []string{"", "."}, Servers: []string{"192.0.2.2"}},
				{Domains: []string{"EXAMPLE.COM", "example.net.", "."}, Servers: []string{"192.0.2.3"}},
				{Domains: []string{"api.example.com."}, Servers: []string{"192.0.2.4"}},
			},
		},
	}})
	assert.Equal(t, 5*time.Second, s.fallbackZoneCache.duration)
	require.Equal(t, 2, len(s.zones))
	assert.Equal(t, []string{"example.com.", "example.net."}, s.zones[0].domains)
	assert.Same(t, s.zones[0], s.getDNSZone("EXAMPLE.COM"))
	assert.Same(t, s.zones[0], s.getDNSZone("www.example.net."))
	assert.Same(t, s.zones[1], s.getDNSZone("a.api.example.com."))
	assert.Same(t, s.zones[0], s.getDNSZone("notapi.example.com."))
	assert.Same(t, s.fallbackZone, s.getDNSZone("notexample.com."))
	assert.Same(t, s.fallbackZone, s.getDNSZone("example.com.invalid."))
	assert.Same(t, s.fallbackZone, s.getDNSZone("."))

	s.zones[0], s.zones[1] = s.zones[1], s.zones[0]
	assert.Equal(t, "192.0.2.4", s.getDNSZone("api.example.com.").upstreams[0].host)
	s.setDNSConfig(nil)
	assert.Empty(t, s.zones)
	assert.Equal(t, 30*time.Second, s.fallbackZoneCache.duration)
	assert.Same(t, s.fallbackZone, s.getDNSZone("api.example.com."))
}

func TestChooseUpstream(t *testing.T) {
	zone := &dnsZone{upstreams: []*upstream{
		{host: "192.0.2.1", port: 53},
		{host: "192.0.2.2", port: 853, typ: "tcp-tls"},
	}}
	for range 100 {
		got := chooseUpstream(zone)
		assert.True(t, got == zone.upstreams[0] || got == zone.upstreams[1])
	}
	zone.upstreams = zone.upstreams[:1]
	assert.Same(t, zone.upstreams[0], chooseUpstream(zone))
}

func TestGetProxiedAnswerCaching(t *testing.T) {
	var queries atomic.Int64
	addr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		msg := tstDNSAnswer(r)
		switch r.Question[0].Name {
		case "missing.example.":
			msg.SetRcode(r, dns.RcodeNameError)
		case "failed.example.":
			msg.SetRcode(r, dns.RcodeServerFailure)
		}
		assert.Nil(t, w.WriteMsg(msg))
	}))
	s := newTstDNSServer()
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{addr}}},
	}})
	for _, tc := range []struct {
		name   string
		qtype  uint16
		rcode  int
		cached bool
	}{
		{name: "external.example.", qtype: dns.TypeA, cached: true},
		{name: "external.example.", qtype: dns.TypeAAAA, cached: true},
		{name: "external.example.", qtype: dns.TypeTXT},
		{name: "missing.example.", qtype: dns.TypeA, rcode: dns.RcodeNameError},
		{name: "failed.example.", qtype: dns.TypeA, rcode: dns.RcodeServerFailure},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.name, dns.TypeToString[tc.qtype]), func(t *testing.T) {
			before := queries.Load()
			first, err := s.getProxiedAnswer(tc.name, tc.qtype)
			require.Nil(t, err)
			require.NotNil(t, first)
			want := first.Copy()
			first.Id++
			first.Answer = nil
			second, err := s.getProxiedAnswer(tc.name, tc.qtype)
			require.Nil(t, err)
			require.NotNil(t, second)
			assert.Equal(t, tc.rcode, second.Rcode)
			if tc.cached {
				assert.Equal(t, int64(1), queries.Load()-before)
				assert.Equal(t, want, second)
			} else {
				assert.Equal(t, int64(2), queries.Load()-before)
				assert.Nil(t, s.fallbackZoneCache.get(tc.name, tc.qtype))
			}
		})
	}
}

func TestGetProxiedAnswerZones(t *testing.T) {
	var fallbackQueries atomic.Int64
	var zoneQueries atomic.Int64
	upstream := func(counter *atomic.Int64, ip string) string {
		return newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			counter.Add(1)
			msg := tstDNSAnswer(r)
			msg.Answer[0].(*dns.A).A = net.ParseIP(ip)
			assert.Nil(t, w.WriteMsg(msg))
		}))
	}
	fallbackAddr := upstream(&fallbackQueries, "198.51.100.1")
	zoneAddr := upstream(&zoneQueries, "198.51.100.2")
	s := newTstDNSServer()
	cc := &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{
			FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{fallbackAddr}},
			Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
				{Domains: []string{"example.com"}, Servers: []string{zoneAddr}},
			},
		},
	}}
	s.setDNSConfig(cc)

	for range 2 {
		for _, tc := range []struct{ name, ip string }{
			{name: "www.example.com.", ip: "198.51.100.2"},
			{name: "example.net.", ip: "198.51.100.1"},
		} {
			msg, err := s.getProxiedAnswer(tc.name, dns.TypeA)
			require.Nil(t, err)
			require.Equal(t, 1, len(msg.Answer))
			assert.Equal(t, tc.ip, msg.Answer[0].(*dns.A).A.String())
		}
	}
	assert.Equal(t, int64(1), fallbackQueries.Load())
	assert.Equal(t, int64(1), zoneQueries.Load())
	assert.Nil(t, s.fallbackZoneCache.get("www.example.com.", dns.TypeA))
	assert.Nil(t, s.zones[0].cache.get("example.net.", dns.TypeA))

	cc.Spec.Dns.Zones[0].Servers = []string{fallbackAddr}
	s.setDNSConfig(cc)
	msg, err := s.getProxiedAnswer("www.example.com.", dns.TypeA)
	require.Nil(t, err)
	assert.Equal(t, "198.51.100.1", msg.Answer[0].(*dns.A).A.String())
	assert.Equal(t, int64(2), fallbackQueries.Load())
	assert.Equal(t, int64(1), zoneQueries.Load())
}

func TestDNSConfigConcurrentAccess(t *testing.T) {
	s := newTstDNSServer()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				for _, name := range []string{"example.com.", "sub.example.com.", "example.net."} {
					zone := s.getDNSZone(name)
					assert.NotNil(t, zone)
					assert.NotEmpty(t, zone.upstreams)
					assert.NotNil(t, zone.cache)
					zone.cache.get(name, dns.TypeA)
				}
			}
		}()
	}
	for i := range 100 {
		if i%2 == 0 {
			s.setDNSConfig(nil)
			continue
		}
		s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
			Dns: &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{"192.0.2.1"}},
				Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
					{Domains: []string{"example.com"}, Servers: []string{"192.0.2.2"}},
					{Domains: []string{"sub.example.com"}, Servers: []string{"192.0.2.3"}},
				},
			},
		}})
	}
	wg.Wait()
}

func TestDNSZoneCacheCleanupLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTstDNSServer()
		s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
			Dns: &corev1.ClusterConfig_Spec_DNS{Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
				{Domains: []string{"example.com"}, Servers: []string{"192.0.2.1"}},
				{Domains: []string{"example.net"}, Servers: []string{"192.0.2.2"}},
			}},
		}})
		msg := &dns.Msg{}
		msg.SetQuestion("www.example.com.", dns.TypeA)
		msg.SetReply(msg)
		for _, cache := range []*zoneCache{s.fallbackZoneCache, s.zones[0].cache, s.zones[1].cache} {
			cache.set("expired.example.", dns.TypeA, msg)
			cache.setDuration(time.Hour)
			cache.set("live.example.", dns.TypeA, msg)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			s.startZoneCacheCleanupLoop(ctx)
			close(done)
		}()
		synctest.Wait()
		time.Sleep(6 * time.Minute)
		synctest.Wait()
		for _, cache := range []*zoneCache{s.fallbackZoneCache, s.zones[0].cache, s.zones[1].cache} {
			cache.RLock()
			assert.Equal(t, 1, len(cache.cMap))
			cache.RUnlock()
			assert.NotNil(t, cache.get("live.example.", dns.TypeA))
			assert.Nil(t, cache.get("expired.example.", dns.TypeA))
		}
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("The DNS zone cache cleanup loop did not stop")
		}
	})
}

func TestReservedNamespacesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s := &DNSServer{}
	s.setReservedNamespaces(ctx)
	assert.Equal(t, wellKnownTLDs, s.reservedNamespaces)
}

type tstDNSClusterClient struct {
	octeliumc.ClientInterface
	cc  *corev1.ClusterConfig
	err error
}

func (c *tstDNSClusterClient) CoreV1Utils() octeliumc.CoreV1Utils { return c }

func (c *tstDNSClusterClient) GetClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error) {
	return c.cc, c.err
}

func TestInitialize(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cc := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{Name: "default"},
		Spec: &corev1.ClusterConfig_Spec{
			Dns: &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{"192.0.2.1"}},
				Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
					{Domains: []string{"example.net"}, Servers: []string{"192.0.2.2"}},
				},
			},
		},
		Status: &corev1.ClusterConfig_Status{Domain: "example.com"},
	}
	s, err := Initialize(ctx, &tstDNSClusterClient{cc: cc})
	require.Nil(t, err)
	require.NotNil(t, s)
	assert.Equal(t, "example.com", s.domain)
	assert.NotNil(t, s.cache)
	assert.NotNil(t, s.ccCtl)
	assert.Equal(t, wellKnownTLDs, s.reservedNamespaces)
	assert.Equal(t, "192.0.2.1", s.fallbackZone.upstreams[0].host)
	assert.Equal(t, "192.0.2.2", s.getDNSZone("www.example.net.").upstreams[0].host)

	wantErr := errors.New("config unavailable")
	s, err = Initialize(ctx, &tstDNSClusterClient{err: wantErr})
	assert.Nil(t, s)
	assert.ErrorIs(t, err, wantErr)
}

func TestDNSConfigWatch(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	require.Nil(t, err)
	initCtx, initCancel := context.WithCancel(ctx)
	initCancel()
	s, err := Initialize(initCtx, &tstDNSClusterClient{ClientInterface: tst.C.OcteliumC, cc: cc})
	require.Nil(t, err)
	require.Nil(t, s.ccCtl.Run(ctx))

	cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
		FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{"192.0.2.1"}},
		Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
			{Domains: []string{"example.net"}, Servers: []string{"192.0.2.2"}},
		},
	}
	cc, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	require.Nil(t, err)
	require.Eventually(t, func() bool {
		zone := s.getDNSZone("www.example.net.")
		return zone.upstreams[0].host == "192.0.2.2"
	}, 10*time.Second, 10*time.Millisecond)
	assert.Equal(t, "192.0.2.1", s.getDNSZone("www.example.org.").upstreams[0].host)

	zone := s.getDNSZone("example.net.")
	cc.Metadata.DisplayName = "unrelated update"
	cc, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	require.Nil(t, err)
	require.Eventually(t, func() bool {
		return s.ccCtl.Get().Metadata.ResourceVersion == cc.Metadata.ResourceVersion
	}, 10*time.Second, 10*time.Millisecond)
	assert.Never(t, func() bool {
		return zone != s.getDNSZone("example.net.")
	}, 100*time.Millisecond, 10*time.Millisecond)

	cc.Spec.Dns = nil
	_, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	require.Nil(t, err)
	require.Eventually(t, func() bool {
		return s.getDNSZone("example.net.").upstreams[0].host == "8.8.8.8"
	}, 10*time.Second, 10*time.Millisecond)
}

func TestServeDNSWireValidation(t *testing.T) {
	s := newTstDNSServer()
	s.Set(newTstDNSService())
	addr := newTstDNSUpstream(t, s)
	c := &dns.Client{Timeout: time.Second}
	for _, tc := range []struct {
		name  string
		msg   *dns.Msg
		rcode int
	}{
		{name: "NoQuestions", msg: &dns.Msg{}, rcode: dns.RcodeFormatError},
		{name: "MultipleQuestions", msg: &dns.Msg{Question: []dns.Question{
			{Name: "svc.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			{Name: "other.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		}}, rcode: dns.RcodeFormatError},
		{name: "DynamicUpdate", msg: &dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeUpdate}, Question: []dns.Question{
			{Name: "svc.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		}}, rcode: dns.RcodeNotImplemented},
		{name: "NUL", msg: &dns.Msg{Question: []dns.Question{
			{Name: "bad\x00.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		}}, rcode: dns.RcodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.msg.Copy()
			msg.Id = dns.Id()
			resp, _, err := c.ExchangeContext(t.Context(), msg, addr)
			require.Nil(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, msg.Id, resp.Id)
			assert.Equal(t, tc.rcode, resp.Rcode)
			assert.Empty(t, resp.Answer)
		})
	}
	r := &dns.Msg{}
	r.SetQuestion("svc.local.", dns.TypeA)
	resp, _, err := c.ExchangeContext(t.Context(), r, addr)
	require.Nil(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Equal(t, 1, len(resp.Answer))
}

func TestServeDNSConcurrentRequests(t *testing.T) {
	s := newTstDNSServer()
	s.Set(newTstDNSService())
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r := &dns.Msg{}
		r.SetQuestion("external.example.", qtype)
		s.fallbackZoneCache.set("external.example.", qtype, tstDNSAnswer(r))
	}
	addr := newTstDNSUpstream(t, s)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var updates atomic.Int64
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				svc := newTstDNSService()
				if updates.Add(1)%2 == 0 {
					svc.Status.Addresses[0].DualStackIP.Ipv4 = "192.0.2.2"
				}
				s.Set(svc)
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &dns.Client{Timeout: 2 * time.Second}
			for i := range 40 {
				qtype := uint16(dns.TypeA)
				if i%2 == 1 {
					qtype = dns.TypeAAAA
				}
				name := "SvC.DeFaUlT.LoCaL."
				if i%3 == 0 {
					name = "ExTeRnAl.ExAmPlE."
				}
				r := &dns.Msg{}
				r.SetQuestion(name, qtype)
				r.Id = uint16(worker*40 + i)
				resp, _, err := c.ExchangeContext(ctx, r, addr)
				if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
					return
				}
				assert.Equal(t, r.Id, resp.Id)
				assert.Equal(t, r.Question, resp.Question)
				assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
				if !assert.Equal(t, 1, len(resp.Answer)) {
					return
				}
				if qtype == dns.TypeA {
					ip := resp.Answer[0].(*dns.A).A.String()
					if i%3 == 0 {
						assert.Equal(t, "198.51.100.1", ip)
					} else {
						assert.Contains(t, []string{"192.0.2.1", "192.0.2.2"}, ip)
					}
				} else {
					ip := resp.Answer[0].(*dns.AAAA).AAAA.String()
					if i%3 == 0 {
						assert.Equal(t, "2001:db8::2", ip)
					} else {
						assert.Equal(t, "2001:db8::1", ip)
					}
				}
			}
		}()
	}
	wg.Wait()
	cancel()
	<-done
	assert.Positive(t, updates.Load())
}

func TestServeDNSMalformedPackets(t *testing.T) {
	s := newTstDNSServer()
	s.Set(newTstDNSService())
	addr := newTstDNSUpstream(t, s)
	header := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "TruncatedLabel", data: []byte{3, 'a'}},
		{name: "CompressionLoop", data: []byte{0xc0, 0x0c, 0, 1, 0, 1}},
		{name: "InvalidLabelType", data: []byte{0x80, 0, 0, 1, 0, 1}},
		{name: "MissingQuestionType", data: []byte{1, 'a', 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("udp", addr, time.Second)
			require.Nil(t, err)
			defer conn.Close()
			require.Nil(t, conn.SetDeadline(time.Now().Add(time.Second)))
			_, err = conn.Write(append(append([]byte{}, header...), tc.data...))
			require.Nil(t, err)
			data := make([]byte, 512)
			n, err := conn.Read(data)
			require.Nil(t, err)
			msg := &dns.Msg{}
			require.Nil(t, msg.Unpack(data[:n]))
			assert.Equal(t, uint16(0x1234), msg.Id)
			assert.Equal(t, dns.RcodeFormatError, msg.Rcode)
			assert.Empty(t, msg.Answer)
		})
	}
	r := &dns.Msg{}
	r.SetQuestion("svc.default.local.", dns.TypeA)
	c := &dns.Client{Timeout: time.Second}
	resp, _, err := c.ExchangeContext(t.Context(), r, addr)
	require.Nil(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
}

func TestServeDNSIgnoredPackets(t *testing.T) {
	s := newTstDNSServer()
	addr := newTstDNSUpstream(t, s)
	response := &dns.Msg{}
	response.SetQuestion("svc.local.", dns.TypeA)
	response.Response = true
	data, err := response.Pack()
	require.Nil(t, err)
	for _, packet := range [][]byte{{0x12, 0x34, 0x01}, data} {
		conn, err := net.DialTimeout("udp", addr, time.Second)
		require.Nil(t, err)
		defer conn.Close()
		require.Nil(t, conn.SetDeadline(time.Now().Add(100*time.Millisecond)))
		_, err = conn.Write(packet)
		require.Nil(t, err)
		_, err = conn.Read(make([]byte, 512))
		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
		assert.True(t, netErr.Timeout())
	}
}

func TestGetProxiedAnswerTLSVerification(t *testing.T) {
	upstream := httptest.NewTLSServer(nil)
	defer upstream.Close()
	s := newTstDNSServer()
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
			Servers: []string{"tls://" + upstream.Listener.Addr().String()},
		}},
	}})
	msg, err := s.getProxiedAnswer("external.example.", dns.TypeA)
	assert.Nil(t, msg)
	var certErr *tls.CertificateVerificationError
	assert.ErrorAs(t, err, &certErr)
	assert.Nil(t, s.fallbackZoneCache.get("external.example.", dns.TypeA))
}

func TestServeDNSUpstreamRcodes(t *testing.T) {
	rcodes := []int{dns.RcodeNameError, dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented}
	names := make(map[string]int)
	for _, rcode := range rcodes {
		names[fmt.Sprintf("rcode%d.external.example.", rcode)] = rcode
	}
	addr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := &dns.Msg{}
		msg.SetRcode(r, names[r.Question[0].Name])
		msg.Authoritative = true
		msg.Ns = []dns.RR{&dns.SOA{
			Hdr: dns.RR_Header{Name: "external.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns.external.example.", Mbox: "hostmaster.external.example.", Serial: 1, Minttl: 60,
		}}
		assert.Nil(t, w.WriteMsg(msg))
	}))
	s := newTstDNSServer()
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{addr}}},
	}})
	for _, rcode := range rcodes {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeTXT} {
			r := &dns.Msg{}
			r.SetQuestion(fmt.Sprintf("RCODE%d.EXTERNAL.EXAMPLE.", rcode), qtype)
			w := &tstDNSResponseWriter{}
			s.ServeDNS(w, r)
			require.NotNil(t, w.msg)
			assert.Equal(t, 1, w.writes)
			assert.Equal(t, rcode, w.msg.Rcode)
			assert.Equal(t, r.Id, w.msg.Id)
			assert.Equal(t, r.Question, w.msg.Question)
			assert.True(t, w.msg.Authoritative)
			assert.True(t, w.msg.RecursionAvailable)
			assert.Empty(t, w.msg.Answer)
			require.Equal(t, 1, len(w.msg.Ns))
			assert.Equal(t, "ns.external.example.", w.msg.Ns[0].(*dns.SOA).Ns)
			assert.Nil(t, s.fallbackZoneCache.get(strings.ToLower(r.Question[0].Name), qtype))
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

func TestDNSZoneSelection(t *testing.T) {
	dnsSrv := &DNSServer{
		fallbackZoneCache: newZoneCache(0),
	}

	dnsSrv.setDNSConfig(&corev1.ClusterConfig{
		Spec: &corev1.ClusterConfig_Spec{
			Dns: &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
					Servers: []string{"9.9.9.9"},
				},
				Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
					{
						Domains: []string{"example.com", "example.net."},
						Servers: []string{"udp://10.0.0.1:5353"},
						CacheDuration: &metav1.Duration{
							Type: &metav1.Duration_Minutes{Minutes: 1},
						},
					},
					{
						Domains: []string{"sub.example.com"},
						Servers: []string{"tls://dns.internal.example:8853"},
					},
				},
			},
		},
	})

	fallback := dnsSrv.getDNSZone("unmatched.example.org.")
	assert.Equal(t, "9.9.9.9", fallback.upstreams[0].host)
	assert.Equal(t, 53, fallback.upstreams[0].port)
	assert.Same(t, dnsSrv.fallbackZoneCache, fallback.cache)

	zone := dnsSrv.getDNSZone("EXAMPLE.COM")
	assert.Equal(t, "10.0.0.1", zone.upstreams[0].host)
	assert.Equal(t, 5353, zone.upstreams[0].port)
	assert.Equal(t, time.Minute, zone.cache.duration)
	assert.Same(t, zone, dnsSrv.getDNSZone("www.example.net."))
	assert.NotSame(t, zone, fallback)

	subZone := dnsSrv.getDNSZone("api.sub.example.com.")
	assert.Equal(t, "dns.internal.example", subZone.upstreams[0].host)
	assert.Equal(t, 8853, subZone.upstreams[0].port)
	assert.Equal(t, "tcp-tls", subZone.upstreams[0].typ)
	assert.NotSame(t, zone, subZone)

	assert.Same(t, fallback, dnsSrv.getDNSZone("notexample.com."))
	assert.Same(t, fallback, dnsSrv.getDNSZone("example.com.invalid."))
}
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
			m.SetQuestion("svc1.local.", dns.TypeA)
			r, _, err := c.ExchangeContext(context.Background(), m, addr)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode)
			assert.Equal(t, "1.2.3.4", (r.Answer[0].(*dns.A)).A.String())
		}
		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("svc1.default.", dns.TypeA)
			r, _, err := c.ExchangeContext(context.Background(), m, addr)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode)
			assert.Equal(t, "1.2.3.4", (r.Answer[0].(*dns.A)).A.String())
		}
		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("svc1.default.local.", dns.TypeA)
			r, _, err := c.ExchangeContext(context.Background(), m, addr)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode)
			assert.Equal(t, "1.2.3.4", (r.Answer[0].(*dns.A)).A.String())
		}
		{
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion("svc1.", dns.TypeA)
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

func TestServeDNSCachedTTLAging(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTstDNSServer()
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r := &dns.Msg{}
			r.SetQuestion("external.example.", qtype)
			msg := tstDNSAnswer(r)
			msg.Answer[0].Header().Ttl = 20
			s.fallbackZoneCache.set("external.example.", qtype, msg)
		}
		time.Sleep(5 * time.Second)
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r := &dns.Msg{}
			r.SetQuestion("EXTERNAL.EXAMPLE.", qtype)
			r.SetEdns0(1232, false)
			w := &tstDNSResponseWriter{}
			s.ServeDNS(w, r)
			require.NotNil(t, w.msg)
			assert.Equal(t, r.Id, w.msg.Id)
			assert.Equal(t, r.Question, w.msg.Question)
			assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
			require.Equal(t, 1, len(w.msg.Answer))
			assert.Equal(t, uint32(15), w.msg.Answer[0].Header().Ttl)
			assert.Equal(t, qtype, w.msg.Answer[0].Header().Rrtype)
			assert.Equal(t, uint32(15), s.fallbackZoneCache.get("external.example.", qtype).Answer[0].Header().Ttl)
		}
	})
}

func TestServeDNSZeroTTLUpstream(t *testing.T) {
	var queries atomic.Int64
	addr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		n := queries.Add(1)
		msg := tstDNSAnswer(r)
		msg.Answer[0].Header().Ttl = 0
		switch rr := msg.Answer[0].(type) {
		case *dns.A:
			rr.A = net.ParseIP(fmt.Sprintf("198.51.100.%d", n))
		case *dns.AAAA:
			rr.AAAA = net.ParseIP(fmt.Sprintf("2001:db8::%x", n))
		}
		assert.Nil(t, w.WriteMsg(msg))
	}))
	s := newTstDNSServer()
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{addr}}},
	}})
	serverAddr := newTstDNSUpstream(t, s)
	c := &dns.Client{Timeout: 2 * time.Second}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for range 3 {
			before := queries.Load()
			r := &dns.Msg{}
			r.SetQuestion("external.example.", qtype)
			msg, _, err := c.ExchangeContext(t.Context(), r, serverAddr)
			require.Nil(t, err)
			require.NotNil(t, msg)
			assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
			assert.Equal(t, r.Id, msg.Id)
			assert.Equal(t, r.Question, msg.Question)
			require.Equal(t, 1, len(msg.Answer))
			assert.Zero(t, msg.Answer[0].Header().Ttl)
			assert.Equal(t, before+1, queries.Load())
			assert.Nil(t, s.fallbackZoneCache.get("external.example.", qtype))
		}
	}
}

func TestGetProxiedAnswerTTLRefresh(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			var queries atomic.Int64
			addr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				n := queries.Add(1)
				msg := tstDNSAnswer(r)
				msg.Answer[0].Header().Ttl = 1
				switch rr := msg.Answer[0].(type) {
				case *dns.A:
					rr.A = net.ParseIP(fmt.Sprintf("198.51.100.%d", n))
				case *dns.AAAA:
					rr.AAAA = net.ParseIP(fmt.Sprintf("2001:db8::%x", n))
				}
				assert.Nil(t, w.WriteMsg(msg))
			}))
			s := newTstDNSServer()
			s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
				Dns: &corev1.ClusterConfig_Spec_DNS{Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
					{Domains: []string{"example.com"}, Servers: []string{addr},
						CacheDuration: &metav1.Duration{Type: &metav1.Duration_Minutes{Minutes: 1}}},
				}},
			}})
			first, err := s.getProxiedAnswer("www.example.com.", qtype)
			require.Nil(t, err)
			require.NotNil(t, first)
			assert.Equal(t, int64(1), queries.Load())
			require.Eventually(t, func() bool {
				msg, err := s.getProxiedAnswer("www.example.com.", qtype)
				return err == nil && queries.Load() > 1 && msg != nil &&
					len(msg.Answer) == 1 && msg.Answer[0].String() != first.Answer[0].String()
			}, 3*time.Second, 20*time.Millisecond)
			assert.Equal(t, int64(2), queries.Load())
			assert.Equal(t, uint32(1), first.Answer[0].Header().Ttl)
		})
	}
}

func TestGetProxiedAnswerFailover(t *testing.T) {
	for _, namedZone := range []bool{false, true} {
		t.Run(fmt.Sprintf("NamedZone%t", namedZone), func(t *testing.T) {
			var queries atomic.Int64
			addr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				queries.Add(1)
				assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
			}))
			conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
			require.Nil(t, err)
			badAddr := conn.LocalAddr().String()
			require.Nil(t, conn.Close())
			s := newTstDNSServer()
			zone := &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{badAddr, addr}}
			config := &corev1.ClusterConfig_Spec_DNS{FallbackZone: zone}
			if namedZone {
				zone.Domains = []string{"example.com"}
				config.FallbackZone = &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{badAddr}}
				config.Zones = []*corev1.ClusterConfig_Spec_DNS_Zone{zone}
			}
			s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{Dns: config}})
			for i := range 16 {
				name := fmt.Sprintf("query%d.example.com.", i)
				for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
					before := queries.Load()
					for range 2 {
						msg, err := s.getProxiedAnswer(name, qtype)
						require.Nil(t, err)
						require.NotNil(t, msg)
						assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
						require.Equal(t, 1, len(msg.Answer))
						assert.Equal(t, qtype, msg.Answer[0].Header().Rrtype)
					}
					want := int64(1)
					if qtype == dns.TypeTXT {
						want = 2
					}
					assert.Equal(t, before+want, queries.Load())
				}
			}
			if namedZone {
				assert.Nil(t, s.fallbackZoneCache.get("query0.example.com.", dns.TypeA))
			}
		})
	}
}

func TestGetProxiedAnswerFailoverRetries(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("Malformed%t", malformed), func(t *testing.T) {
			var queries atomic.Int64
			var attempts [3]atomic.Int64
			var servers []string
			for i := range attempts {
				servers = append(servers, newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
					attempts[i].Add(1)
					assert.Equal(t, []dns.Question{{Name: "external.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}, r.Question)
					if queries.Add(1) < 3 {
						if malformed {
							_, err := w.Write([]byte{0})
							assert.Nil(t, err)
						} else {
							msg := &dns.Msg{}
							msg.SetRcode(r, dns.RcodeServerFailure)
							assert.Nil(t, w.WriteMsg(msg))
						}
						return
					}
					assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
				})))
			}
			s := newTstDNSServer()
			s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
				Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: servers}},
			}})
			for range 2 {
				msg, err := s.getProxiedAnswer("external.example.", dns.TypeA)
				require.Nil(t, err)
				require.NotNil(t, msg)
				assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
				require.Equal(t, 1, len(msg.Answer))
				assert.Equal(t, "198.51.100.1", msg.Answer[0].(*dns.A).A.String())
			}
			assert.Equal(t, int64(3), queries.Load())
			for i := range attempts {
				assert.Equal(t, int64(1), attempts[i].Load())
			}
		})
	}
}

func TestGetProxiedAnswerFailoverRcodes(t *testing.T) {
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			var queries atomic.Int64
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				queries.Add(1)
				msg := &dns.Msg{}
				msg.SetRcode(r, rcode)
				msg.Authoritative = true
				msg.Ns = []dns.RR{&dns.SOA{
					Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
					Ns:  "ns.example.", Mbox: "hostmaster.example.", Serial: 1, Minttl: 30,
				}}
				assert.Nil(t, w.WriteMsg(msg))
			})
			s := newTstDNSServer()
			s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
				Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
					Servers: []string{newTstDNSUpstream(t, handler), newTstDNSUpstream(t, handler)},
				}},
			}})
			msg, err := s.getProxiedAnswer("external.example.", dns.TypeA)
			require.Nil(t, err)
			require.NotNil(t, msg)
			assert.Equal(t, rcode, msg.Rcode)
			assert.True(t, msg.Authoritative)
			assert.Empty(t, msg.Answer)
			require.Equal(t, 1, len(msg.Ns))
			assert.Equal(t, "ns.example.", msg.Ns[0].(*dns.SOA).Ns)
			assert.Equal(t, int64(1), queries.Load())
			if rcode != dns.RcodeSuccess {
				assert.Nil(t, s.fallbackZoneCache.get("external.example.", dns.TypeA))
			}
		})
	}
}

func TestGetProxiedAnswerFailoverErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		firstError bool
		lastError  bool
	}{
		{name: "ServerFailure"},
		{name: "ServerFailureThenError", lastError: true},
		{name: "ErrorThenServerFailure", firstError: true},
		{name: "Errors", firstError: true, lastError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var queries atomic.Int64
			var attempts [2]atomic.Int64
			var servers []string
			for i := range attempts {
				servers = append(servers, newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
					attempts[i].Add(1)
					n := queries.Add(1)
					if n == 1 && tc.firstError || n == 2 && tc.lastError {
						_, err := w.Write([]byte{0})
						assert.Nil(t, err)
						return
					}
					msg := &dns.Msg{}
					msg.SetRcode(r, dns.RcodeServerFailure)
					msg.Ns = []dns.RR{&dns.NS{
						Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
						Ns:  "ns.example.",
					}}
					assert.Nil(t, w.WriteMsg(msg))
				})))
			}
			s := newTstDNSServer()
			s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
				Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: servers}},
			}})
			msg, err := s.getProxiedAnswer("external.example.", dns.TypeA)
			if tc.firstError && tc.lastError {
				assert.NotNil(t, err)
				assert.Nil(t, msg)
			} else {
				require.Nil(t, err)
				require.NotNil(t, msg)
				assert.Equal(t, dns.RcodeServerFailure, msg.Rcode)
				require.Equal(t, 1, len(msg.Ns))
				assert.Equal(t, "ns.example.", msg.Ns[0].(*dns.NS).Ns)
			}
			assert.Equal(t, int64(2), queries.Load())
			for i := range attempts {
				assert.Equal(t, int64(1), attempts[i].Load())
			}
			assert.Nil(t, s.fallbackZoneCache.get("external.example.", dns.TypeA))
		})
	}
}

func TestGetProxiedAnswerFailoverTLS(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	t.Cleanup(srv.Close)
	var queries atomic.Int64
	addr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
	}))
	s := newTstDNSServer()
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
			Servers: []string{"tls://" + srv.Listener.Addr().String(), addr},
		}},
	}})
	for i := range 16 {
		msg, err := s.getProxiedAnswer(fmt.Sprintf("query%d.example.", i), dns.TypeTXT)
		require.Nil(t, err)
		require.NotNil(t, msg)
		assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
		require.Equal(t, 1, len(msg.Answer))
		assert.Equal(t, []string{"upstream"}, msg.Answer[0].(*dns.TXT).Txt)
	}
	assert.Equal(t, int64(16), queries.Load())
}

func TestServeDNSFailoverTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		servers int
		recover bool
	}{
		{name: "Recovery", servers: 2, recover: true},
		{name: "Unavailable", servers: 3},
		{name: "ManyResolvers", servers: 32, recover: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var queries atomic.Int64
			var fallbackQueries atomic.Int64
			fallback := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				fallbackQueries.Add(1)
				assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
			}))
			attempts := make([]atomic.Int64, tc.servers)
			var servers []string
			for i := range attempts {
				servers = append(servers, newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
					attempts[i].Add(1)
					if queries.Add(1) == int64(tc.servers) && tc.recover {
						assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
					}
				})))
			}
			s := newTstDNSServer()
			s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
				Dns: &corev1.ClusterConfig_Spec_DNS{
					FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{fallback}},
					Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
						{Domains: []string{"example.com"}, Servers: servers},
					},
				},
			}})
			r := &dns.Msg{}
			r.SetQuestion("www.example.com.", dns.TypeA)
			w := &tstDNSResponseWriter{}
			start := time.Now()
			s.ServeDNS(w, r)
			elapsed := time.Since(start)
			require.NotNil(t, w.msg)
			assert.Equal(t, r.Id, w.msg.Id)
			assert.Equal(t, r.Question, w.msg.Question)
			if tc.recover {
				assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
				require.Equal(t, 1, len(w.msg.Answer))
				assert.Equal(t, "198.51.100.1", w.msg.Answer[0].(*dns.A).A.String())
				assert.NotNil(t, s.zones[0].cache.get("www.example.com.", dns.TypeA))
			} else {
				assert.Equal(t, dns.RcodeServerFailure, w.msg.Rcode)
				assert.Empty(t, w.msg.Answer)
				assert.Nil(t, s.zones[0].cache.get("www.example.com.", dns.TypeA))
			}
			assert.Less(t, elapsed, 5*time.Second)
			assert.Equal(t, int64(tc.servers), queries.Load())
			for i := range attempts {
				assert.Equal(t, int64(1), attempts[i].Load())
			}
			assert.Zero(t, fallbackQueries.Load())
		})
	}
}

func TestServeDNSFailoverRecovery(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			var healthy atomic.Bool
			var queries atomic.Int64
			var fallbackQueries atomic.Int64
			fallback := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				fallbackQueries.Add(1)
				assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
			}))
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				queries.Add(1)
				if !healthy.Load() {
					_, err := w.Write([]byte{0})
					assert.Nil(t, err)
					return
				}
				assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
			})
			s := newTstDNSServer()
			s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
				Dns: &corev1.ClusterConfig_Spec_DNS{
					FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{Servers: []string{fallback}},
					Zones: []*corev1.ClusterConfig_Spec_DNS_Zone{
						{Domains: []string{"example.com"}, Servers: []string{newTstDNSUpstream(t, handler), newTstDNSUpstream(t, handler)}},
					},
				},
			}})
			r := &dns.Msg{}
			r.SetQuestion("www.example.com.", qtype)
			w := &tstDNSResponseWriter{}
			s.ServeDNS(w, r)
			require.NotNil(t, w.msg)
			assert.Equal(t, dns.RcodeServerFailure, w.msg.Rcode)
			assert.Equal(t, r.Id, w.msg.Id)
			assert.Equal(t, r.Question, w.msg.Question)
			assert.Equal(t, int64(2), queries.Load())
			assert.Nil(t, s.zones[0].cache.get("www.example.com.", qtype))
			healthy.Store(true)
			s.ServeDNS(w, r)
			require.NotNil(t, w.msg)
			assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
			assert.Equal(t, r.Id, w.msg.Id)
			assert.Equal(t, r.Question, w.msg.Question)
			require.Equal(t, 1, len(w.msg.Answer))
			assert.Equal(t, qtype, w.msg.Answer[0].Header().Rrtype)
			assert.Equal(t, int64(3), queries.Load())
			assert.Zero(t, fallbackQueries.Load())
		})
	}
}

func TestServeDNSFailoverConcurrentRequests(t *testing.T) {
	var queries atomic.Int64
	addr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		assert.Nil(t, w.WriteMsg(tstDNSAnswer(r)))
	}))
	badAddr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_, err := w.Write([]byte{0})
		assert.Nil(t, err)
	}))
	failedAddr := newTstDNSUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := &dns.Msg{}
		msg.SetRcode(r, dns.RcodeServerFailure)
		assert.Nil(t, w.WriteMsg(msg))
	}))
	s := newTstDNSServer()
	s.setDNSConfig(&corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{
		Dns: &corev1.ClusterConfig_Spec_DNS{FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
			Servers: []string{badAddr, addr, failedAddr},
		}},
	}})
	serverAddr := newTstDNSUpstream(t, s)
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &dns.Client{Timeout: 3 * time.Second}
			for i := range 16 {
				qtype := dns.TypeA
				if i%2 == 1 {
					qtype = dns.TypeAAAA
				}
				for range 2 {
					r := &dns.Msg{}
					r.SetQuestion(fmt.Sprintf("query%d-%d.example.", worker, i), qtype)
					msg, _, err := c.ExchangeContext(t.Context(), r, serverAddr)
					if !assert.Nil(t, err) || !assert.NotNil(t, msg) {
						return
					}
					assert.Equal(t, r.Id, msg.Id)
					assert.Equal(t, r.Question, msg.Question)
					assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
					if assert.Equal(t, 1, len(msg.Answer)) {
						assert.Equal(t, qtype, msg.Answer[0].Header().Rrtype)
					}
				}
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(16*16), queries.Load())
}
