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

package harness

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const dnsUpstreamTTL = 5

type TestSrvDNS struct {
	Port int
	Host string

	AddrV4 string
	AddrV6 string

	srv     *dns.Server
	queries atomic.Int64
}

func (s *TestSrvDNS) Queries() int64 {
	return s.queries.Load()
}

func (s *TestSrvDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.queries.Add(1)

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		msg.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(msg)
		return
	}

	q := r.Question[0]

	zap.L().Debug("TestSrvDNS received a query",
		zap.String("name", q.Name), zap.Uint16("qtype", q.Qtype))

	hdr := dns.RR_Header{
		Name:   q.Name,
		Rrtype: q.Qtype,
		Class:  dns.ClassINET,
		Ttl:    dnsUpstreamTTL,
	}

	switch q.Qtype {
	case dns.TypeA:
		if s.AddrV4 != "" {
			msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr, A: net.ParseIP(s.AddrV4)})
		}
	case dns.TypeAAAA:
		if s.AddrV6 != "" {
			msg.Answer = append(msg.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(s.AddrV6)})
		}
	case dns.TypeTXT:
		msg.Answer = append(msg.Answer, &dns.TXT{Hdr: hdr, Txt: []string{q.Name}})
	}

	w.WriteMsg(msg)
}

func (s *TestSrvDNS) Run() error {
	startedCh := make(chan struct{})

	s.srv = &dns.Server{
		Addr:              net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port)),
		Net:               "udp",
		Handler:           s,
		NotifyStartedFunc: func() { close(startedCh) },
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-startedCh:
		return nil
	case err := <-errCh:
		return errors.Errorf("Could not run the local DNS upstream: %+v", err)
	case <-time.After(30 * time.Second):
		return errors.Errorf("The local DNS upstream did not start listening on %s",
			s.srv.Addr)
	}
}

func (s *TestSrvDNS) Close() {
	if s.srv != nil {
		s.srv.Shutdown()
	}
}

func (h *H) StartDNSUpstream(t *testing.T, srv *TestSrvDNS) *TestSrvDNS {
	t.Helper()

	if srv == nil {
		srv = &TestSrvDNS{}
	}
	if srv.Port == 0 {
		srv.Port = h.Port()
	}
	if srv.Host == "" {
		srv.Host = "127.0.0.1"
	}
	if srv.AddrV4 == "" {
		srv.AddrV4 = "198.51.100.7"
	}
	if srv.AddrV6 == "" {
		srv.AddrV6 = "2001:db8::7"
	}

	if err := srv.Run(); err != nil {
		t.Fatalf("%+v", err)
	}

	t.Cleanup(srv.Close)
	return srv
}
