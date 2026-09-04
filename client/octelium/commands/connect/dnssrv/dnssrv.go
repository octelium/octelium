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
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	listenTimeout   = 5 * time.Second
	upstreamTimeout = 2 * time.Second
	upstreamUDPSize = 1232
)

type Opts struct {
	ClusterDomain string
	HasV4         bool
	HasV6         bool
	DNSGetter     DNSGetter
	ListenAddr    string
	IsFullDNS     bool
	LookupIPFn    func(ctx context.Context, host string) ([]net.IP, error)
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
	isFullDNS   bool
	lookupIPFn  func(ctx context.Context, host string) ([]net.IP, error)
	bootstrap   *bootstrapCache
	// useFallback         bool
}

type DNSGetter interface {
	GetClusterDNSServers() []string
}

func NewDNSServer(opts *Opts) (*Server, error) {
	if opts == nil {
		return nil, errors.Errorf("Local DNS: nil opts")
	}
	if opts.DNSGetter == nil {
		return nil, errors.Errorf("Local DNS: nil DNSGetter")
	}

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
		if cliutils.IsDarwin() || cliutils.IsWindows() {
			return "127.0.0.1:53"
		}

		return "127.0.0.100:53"
	}()
	if listenAddr == "" {
		return nil, errors.Errorf("Local DNS: invalid listen address: %s", opts.ListenAddr)
	}

	lookupIPFn := opts.LookupIPFn
	if lookupIPFn == nil {
		lookupIPFn = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}

	return &Server{
		domain:     opts.ClusterDomain,
		hasV4:      opts.HasV4,
		hasV6:      opts.HasV6,
		dnsGetter:  opts.DNSGetter,
		cache:      newCache(),
		listenAddr: listenAddr,
		isFullDNS:  opts.IsFullDNS,
		lookupIPFn: lookupIPFn,
		bootstrap:  newBootstrapCache(),
	}, nil
}

func getRequestUDPSize(r *dns.Msg) int {
	if opt := r.IsEdns0(); opt != nil {
		if size := int(opt.UDPSize()); size >= dns.MinMsgSize {
			return size
		}
	}

	return dns.MinMsgSize
}

func writeRcode(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	msg := new(dns.Msg)
	msg.SetRcode(r, rcode)
	if err := w.WriteMsg(msg); err != nil {
		zap.L().Debug("Local DNS: Could not write the response", zap.Error(err))
	}
}

func writeUpstreamReply(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg) {
	resp.Id = r.Id
	resp.Question = r.Question
	resp.Response = true
	resp.RecursionAvailable = true

	resp.Truncate(getRequestUDPSize(r))

	if err := w.WriteMsg(resp); err != nil {
		zap.L().Debug("Local DNS: Could not write the response", zap.Error(err))
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	if r == nil {
		msg := new(dns.Msg)
		msg.MsgHdr.Response = true
		msg.Rcode = dns.RcodeRefused
		w.WriteMsg(msg)
		return
	}

	if len(r.Question) == 0 {
		writeRcode(w, r, dns.RcodeRefused)
		return
	}

	q := r.Question[0]
	domain := q.Name

	upstreamAddrs := s.getUpstreamAddrs()
	if len(upstreamAddrs) == 0 {
		if ret := s.getBootstrapAnswer(domain, q.Qtype); ret != nil {
			writeUpstreamReply(w, r, ret)
			return
		}

		zap.L().Debug("Local DNS: no Cluster DNS servers available")
		writeRcode(w, r, dns.RcodeServerFailure)
		return
	}

	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		if s.isClusterName(domain) {
			switch {
			case q.Qtype == dns.TypeA && !s.hasV4,
				q.Qtype == dns.TypeAAAA && !s.hasV6:
				msg := new(dns.Msg)
				msg.SetReply(r)
				msg.RecursionAvailable = true
				if err := w.WriteMsg(msg); err != nil {
					zap.L().Debug("Local DNS: Could not write the response", zap.Error(err))
				}
				return
			}
		}
	}

	ret, err := s.getExchangeAnswer(domain, q.Qtype, upstreamAddrs)
	if err != nil {
		zap.L().Debug("Local DNS: Could not exchange answer with the Cluster DNS", zap.Error(err))
		writeRcode(w, r, dns.RcodeServerFailure)
		return
	}

	writeUpstreamReply(w, r, ret)
}

func (s *Server) getUpstreamAddrs() []string {
	var ret []string
	for _, server := range s.dnsGetter.GetClusterDNSServers() {
		if govalidator.IsIP(server) {
			ret = append(ret, net.JoinHostPort(server, "53"))
		}
	}

	return ret
}

func (s *Server) ListenHost() string {
	host, _, _ := net.SplitHostPort(s.listenAddr)
	return host
}

func (s *Server) getExchangeAnswer(domain string, typ uint16,
	srvAddrs []string) (*dns.Msg, error) {

	if cached := s.cache.get(domain, typ); cached != nil {
		return cached, nil
	}

	var ret *dns.Msg
	var retErr error

	for _, srvAddr := range srvAddrs {
		r, err := s.doExchange(domain, typ, srvAddr)
		if err != nil {
			zap.L().Debug("Local DNS: Could not exchange with the Cluster DNS server",
				zap.String("addr", srvAddr), zap.Error(err))
			retErr = err
			continue
		}

		s.cache.set(domain, typ, r)

		ret = r
		break
	}

	if ret == nil || ret.Rcode != dns.RcodeSuccess {
		if bootstrapRet := s.getBootstrapAnswer(domain, typ); bootstrapRet != nil {
			zap.L().Debug("Local DNS: Serving a bootstrap answer",
				zap.String("domain", domain))
			return bootstrapRet, nil
		}
	}

	if ret != nil {
		return ret, nil
	}

	if retErr == nil {
		retErr = errors.Errorf("No Cluster DNS servers available")
	}

	return nil, retErr
}

func (s *Server) doExchange(domain string, typ uint16, srvAddr string) (*dns.Msg, error) {
	m := dns.Msg{}
	m.SetQuestion(domain, typ)
	m.SetEdns0(upstreamUDPSize, false)

	ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
	defer cancel()

	c := dns.Client{UDPSize: upstreamUDPSize}

	r, _, err := c.ExchangeContext(ctx, &m, srvAddr)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (s *Server) isClusterName(domain string) bool {
	domain = strings.ToLower(domain)

	suffixList := []string{
		fmt.Sprintf(".local.%s.", s.domain),
		fmt.Sprintf(".%s.local.", s.domain),
		".local.",
	}

	for _, suffix := range suffixList {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	return len(strings.Split(strings.TrimSuffix(domain, "."), ".")) == 1
}

const (
	bootstrapLookupTimeout = 2 * time.Second
	bootstrapTTL           = 60
)

func getBootstrapDomains(clusterDomain string) []string {
	clusterDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(clusterDomain), "."))
	if clusterDomain == "" || !govalidator.IsDNSName(clusterDomain) {
		return nil
	}

	return []string{
		dns.Fqdn(clusterDomain),
		dns.Fqdn(fmt.Sprintf("octelium-api.%s", clusterDomain)),
	}
}

func (s *Server) setBootstrapAnswers(ctx context.Context) {
	if !s.isFullDNS {
		return
	}

	domains := getBootstrapDomains(s.domain)
	if len(domains) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, bootstrapLookupTimeout)
	defer cancel()

	for _, domain := range domains {
		ips, err := s.lookupIPFn(ctx, strings.TrimSuffix(domain, "."))
		if err != nil {
			zap.L().Debug("Local DNS: Could not resolve the bootstrap domain",
				zap.String("domain", domain), zap.Error(err))
			continue
		}

		zap.L().Debug("Local DNS: Setting the bootstrap answers of the domain",
			zap.String("domain", domain), zap.Any("addrs", ips))

		s.bootstrap.set(domain, ips)
	}
}

func (s *Server) getBootstrapAnswer(domain string, typ uint16) *dns.Msg {
	if !s.isFullDNS {
		return nil
	}

	return s.bootstrap.get(domain, typ)
}

type bootstrapCache struct {
	sync.RWMutex
	cMap map[string]*dns.Msg
}

func newBootstrapCache() *bootstrapCache {
	return &bootstrapCache{
		cMap: make(map[string]*dns.Msg),
	}
}

func getBootstrapMsg(domain string, typ uint16, ips []net.IP) *dns.Msg {
	ret := new(dns.Msg)

	for _, ip := range ips {
		hdr := dns.RR_Header{
			Name: domain, Rrtype: typ, Class: dns.ClassINET, Ttl: bootstrapTTL,
		}

		switch typ {
		case dns.TypeA:
			if ip4 := ip.To4(); ip4 != nil {
				ret.Answer = append(ret.Answer, &dns.A{Hdr: hdr, A: ip4})
			}
		case dns.TypeAAAA:
			if ip.To4() == nil && ip.To16() != nil {
				ret.Answer = append(ret.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip.To16()})
			}
		}
	}

	return ret
}

func (c *bootstrapCache) set(domain string, ips []net.IP) {
	if len(ips) == 0 {
		return
	}

	c.Lock()
	defer c.Unlock()

	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		c.cMap[getCacheKey(domain, typ)] = getBootstrapMsg(domain, typ, ips)
	}
}

func (c *bootstrapCache) get(domain string, typ uint16) *dns.Msg {
	c.RLock()
	defer c.RUnlock()

	ret, ok := c.cMap[getCacheKey(domain, typ)]
	if !ok {
		return nil
	}

	return ret.Copy()
}

func (s *Server) Run() error {
	zap.L().Debug("Starting running local DNS server", zap.String("addr", s.listenAddr))

	s.setBootstrapAnswers(context.Background())

	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}

	startedCh := make(chan struct{})

	s.srv = &dns.Server{
		Addr:              s.listenAddr,
		Net:               "udp",
		Handler:           s,
		NotifyStartedFunc: func() { close(startedCh) },
	}
	srv := s.srv

	ctx, cancel := context.WithCancel(context.Background())
	s.cacheCancel = cancel
	s.mu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			zap.L().Warn("Failed to serve local DNS", zap.Error(err))
			errCh <- err
		}
	}()

	select {
	case <-startedCh:
	case err := <-errCh:
		return errors.Errorf("Could not listen on the local DNS address %s: %+v", s.listenAddr, err)
	case <-time.After(listenTimeout):
		return errors.Errorf("Timed out waiting for the local DNS server to listen on %s",
			s.listenAddr)
	}

	zap.L().Debug("Local DNS server is now listening", zap.String("addr", s.listenAddr))

	go s.cache.startCleanupLoop(ctx)

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosed {
		return nil
	}

	s.isClosed = true
	zap.L().Debug("Closing local DNS server...")

	if s.cacheCancel != nil {
		s.cacheCancel()
	}

	if s.srv == nil {
		return nil
	}

	if err := s.srv.Shutdown(); err != nil {
		zap.L().Debug("Could not shut down the local DNS server", zap.Error(err))
	}

	return nil
}

const (
	cacheMinTTL     = 5 * time.Second
	cacheMaxTTL     = 300 * time.Second
	cacheMaxEntries = 4096
)

type cache struct {
	sync.RWMutex
	cMap map[string]*cacheVal
}

type cacheVal struct {
	r        *dns.Msg
	cachedAt time.Time
	exp      time.Time
}

func newCache() *cache {
	return &cache{
		cMap: make(map[string]*cacheVal),
	}
}

func getCacheKey(domain string, typ uint16) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(domain), typ)
}

func getMsgTTL(r *dns.Msg) time.Duration {
	ttl := cacheMaxTTL
	var hasRR bool

	for _, rrs := range [][]dns.RR{r.Answer, r.Ns, r.Extra} {
		for _, rr := range rrs {
			if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			hasRR = true
			if cur := time.Duration(rr.Header().Ttl) * time.Second; cur < ttl {
				ttl = cur
			}
		}
	}

	if !hasRR {
		return 0
	}
	if ttl <= 0 {
		return 0
	}

	return min(max(ttl, cacheMinTTL), cacheMaxTTL)
}

func (c *cache) get(domain string, typ uint16) *dns.Msg {
	c.RLock()
	val, ok := c.cMap[getCacheKey(domain, typ)]
	c.RUnlock()
	if !ok {
		return nil
	}

	now := time.Now()
	if now.After(val.exp) {
		return nil
	}

	elapsed := uint32(now.Sub(val.cachedAt) / time.Second)

	ret := val.r.Copy()
	for _, rrs := range [][]dns.RR{ret.Answer, ret.Ns, ret.Extra} {
		for _, rr := range rrs {
			if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if rr.Header().Ttl <= elapsed {
				rr.Header().Ttl = 1
				continue
			}
			rr.Header().Ttl -= elapsed
		}
	}

	return ret
}

func (c *cache) set(domain string, typ uint16, r *dns.Msg) {
	if r == nil || r.Rcode != dns.RcodeSuccess || r.Truncated {
		return
	}

	switch typ {
	case dns.TypeA, dns.TypeAAAA:
	default:
		return
	}

	ttl := getMsgTTL(r)
	if ttl <= 0 {
		return
	}

	now := time.Now()

	c.Lock()
	if len(c.cMap) >= cacheMaxEntries {
		c.doCleanupLocked()
	}
	if len(c.cMap) >= cacheMaxEntries {
		c.Unlock()
		return
	}
	c.cMap[getCacheKey(domain, typ)] = &cacheVal{
		r:        r.Copy(),
		cachedAt: now,
		exp:      now.Add(ttl),
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
	c.doCleanupLocked()
}

func (c *cache) doCleanupLocked() {
	for k, v := range c.cMap {
		if time.Now().After(v.exp) {
			delete(c.cMap, k)
		}
	}
}
