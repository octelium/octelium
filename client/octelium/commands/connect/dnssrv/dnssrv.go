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
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Opts struct {
	ClusterDomain string
	HasV4         bool
	HasV6         bool
	DNSGetter     DNSGetter
	ListenAddr    string
	// FallbackServers []string
	// UseFallback     bool
}

type Server struct {
	domain    string
	hasV4     bool
	hasV6     bool
	dnsGetter DNSGetter

	srv      *dns.Server
	mu       sync.Mutex
	isClosed bool
	// fallbackServerAddrs []string
	cache       *cache
	cacheCancel context.CancelFunc
	listenAddr  string
	// useFallback         bool
}

type DNSGetter interface {
	GetClusterDNSServers() []string
}

func NewDNSServer(opts *Opts) (*Server, error) {

	listenAddr := func() string {
		if opts.ListenAddr != "" {
			if _, _, err := net.SplitHostPort(opts.ListenAddr); err == nil {
				return opts.ListenAddr
			}
			if govalidator.IsIP(opts.ListenAddr) {
				return net.JoinHostPort(opts.ListenAddr, "53")
			}
			return ""
		}
		return "127.0.0.100:53"
	}()
	if listenAddr == "" {
		return nil, errors.Errorf("Local DNS: invalid listen address: %s", opts.ListenAddr)
	}
	return &Server{
		domain:    opts.ClusterDomain,
		hasV4:     opts.HasV4,
		hasV6:     opts.HasV6,
		dnsGetter: opts.DNSGetter,

		/*
			useFallback: opts.UseFallback,
			fallbackServerAddrs: func() []string {

				if len(opts.FallbackServers) == 0 {
					return []string{"8.8.8.8:53"}
				}

				var ret []string
				for _, addr := range opts.FallbackServers {
					if govalidator.IsIP(addr) {
						ret = append(ret, net.JoinHostPort(addr, "53"))
					}
					if _, _, err := net.SplitHostPort(addr); err == nil {
						ret = append(ret, addr)
					}

					zap.L().Warn("Skipping invalid fallback DNS server", zap.String("addr", addr))
				}

				if len(ret) == 0 {
					return []string{"8.8.8.8:53"}
				}

				return ret
			}(),
		*/
		cache:      newCache(),
		listenAddr: listenAddr,
	}, nil
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	if r == nil || len(r.Question) == 0 {
		msg := dns.Msg{}
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
		return
	}

	msg := dns.Msg{}
	msg.SetReply(r)

	q := msg.Question[0]
	domain := q.Name

	if !s.isClusterDomain(domain) {

		ret, err := s.getExchangeAnswer(&msg, domain, q.Qtype,
			net.JoinHostPort(s.dnsGetter.GetClusterDNSServers()[0], "53"))
		if err != nil {
			zap.L().Debug("Local DNS: Could not exchange answer for Cluster zone", zap.Error(err))
			msg.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(&msg)
			return
		}
		msg.Answer = ret.Answer
		msg.Extra = ret.Extra
		msg.Ns = ret.Ns
		w.WriteMsg(&msg)
		return
		/*
			if !s.useFallback {
				msg.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(&msg)
				return
			}
			ret, err := s.getExchangeAnswer(&msg, domain, q.Qtype, s.fallbackServerAddrs[0])
			if err != nil {
				zap.L().Debug("Local DNS: Could not exchange answer for external zone", zap.Error(err))
				msg.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(&msg)
				return
			}
			msg.Answer = ret.Answer
			msg.Extra = ret.Extra
			msg.Ns = ret.Ns
			w.WriteMsg(&msg)
			return
		*/
	}

	switch {
	case q.Qtype == dns.TypeA && !s.hasV4:
		// zap.L().Debug("Local DNS: IPv4 is not supported", zap.String("domain", domain))
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
		return
	case q.Qtype == dns.TypeAAAA && !s.hasV6:
		// zap.L().Debug("Local DNS: IPv6 is not supported", zap.String("domain", domain))
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
		return
	}

	ret, err := s.getExchangeAnswer(&msg, domain, q.Qtype,
		net.JoinHostPort(s.dnsGetter.GetClusterDNSServers()[0], "53"))
	if err != nil {
		zap.L().Debug("Local DNS: Could not exchange answer for Cluster zone", zap.Error(err))
		msg.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(&msg)
		return
	}
	msg.Answer = ret.Answer
	msg.Extra = ret.Extra
	msg.Ns = ret.Ns
	w.WriteMsg(&msg)
}

func (s *Server) ListenHost() string {
	host, _, _ := net.SplitHostPort(s.listenAddr)
	return host
}

func (s *Server) getExchangeAnswer(msg *dns.Msg, domain string, typ uint16, srvAddr string) (*dns.Msg, error) {

	if cached := s.cache.get(domain, typ); cached != nil {
		return cached, nil
	}

	c := dns.Client{}
	m := dns.Msg{}

	m.SetQuestion(domain, typ)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r, _, err := c.ExchangeContext(ctx, &m, srvAddr)
	if err != nil {
		return nil, err
	}

	s.cache.set(domain, typ, r)

	return r, nil
}

func (s *Server) isClusterDomain(domain string) bool {
	suffixList := []string{
		".local.",
		fmt.Sprintf(".local.%s.", s.domain),
		fmt.Sprintf(".%s.local.", s.domain),
		fmt.Sprintf(".%s.", s.domain),
	}

	for _, suffix := range suffixList {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	return false
}

func (s *Server) Run() error {
	zap.L().Debug("Starting running local DNS server")
	go func() {
		if err := s.doRun(); err != nil {
			zap.L().Warn("Could not run local DNS server", zap.Error(err))
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	s.cacheCancel = cancel
	go s.cache.startCleanupLoop(ctx)
	return nil
}

func (s *Server) doRun() error {
	s.srv = &dns.Server{Addr: s.listenAddr, Net: "udp"}
	s.srv.Handler = s
	if err := s.srv.ListenAndServe(); err != nil {
		zap.L().Warn("Failed to serve local DNS", zap.Error(err))
		return err
	}

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosed || s.srv == nil {
		return nil
	}

	s.isClosed = true
	zap.L().Debug("Closing local DNS server...")
	s.cacheCancel()

	return s.srv.Shutdown()
}

type cache struct {
	sync.RWMutex
	cMap     map[string]*cacheVal
	duration time.Duration
}

type cacheVal struct {
	r   *dns.Msg
	exp time.Time
}

func newCache() *cache {
	return &cache{
		cMap:     make(map[string]*cacheVal),
		duration: 30 * time.Second,
	}
}

func getCacheKey(domain string, typ uint16) string {
	return fmt.Sprintf("%s:%d", domain, typ)
}

func (c *cache) get(domain string, typ uint16) *dns.Msg {
	c.RLock()
	defer c.RUnlock()
	val, ok := c.cMap[getCacheKey(domain, typ)]
	if !ok {
		return nil
	}

	if time.Now().After(val.exp) {
		return nil
	}

	return val.r
}

func (c *cache) set(domain string, typ uint16, r *dns.Msg) {
	if r.Rcode != dns.RcodeSuccess {
		return
	}

	switch typ {
	case dns.TypeA, dns.TypeAAAA:
	default:
		return
	}

	c.Lock()
	c.cMap[getCacheKey(domain, typ)] = &cacheVal{
		r:   r,
		exp: time.Now().Add(c.duration),
	}
	c.Unlock()
}

func (c *cache) startCleanupLoop(ctx context.Context) {
	tickerCh := time.NewTicker(6 * time.Minute)
	defer tickerCh.Stop()

	cleanAllCh := time.NewTicker(60 * time.Minute)
	defer cleanAllCh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			c.doCleanup()
		case <-cleanAllCh.C:
			c.Lock()
			c.cMap = make(map[string]*cacheVal)
			c.Unlock()
		}
	}
}

func (c *cache) doCleanup() {
	c.Lock()
	defer c.Unlock()
	for k, v := range c.cMap {
		if time.Now().After(v.exp) {
			delete(c.cMap, k)
		}
	}
}
