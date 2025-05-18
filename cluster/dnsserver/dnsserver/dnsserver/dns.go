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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/ccctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type DNSServer struct {
	domain            string
	cache             *cache
	upstreams         []*upstream
	ccCtl             *ccctl.Controller
	mu                sync.RWMutex
	fallbackZoneCache *zoneCache
}

func Initialize(ctx context.Context, octeliumC octeliumc.ClientInterface) (*DNSServer, error) {

	ret := &DNSServer{
		cache: newCache(),
	}

	getDuration := func(cc *corev1.ClusterConfig) time.Duration {
		if cc.Spec.Dns == nil || cc.Spec.Dns.FallbackZone == nil || cc.Spec.Dns.FallbackZone.CacheDuration == nil {
			return 0
		}
		return umetav1.ToDuration(cc.Spec.Dns.FallbackZone.CacheDuration).ToGo()
	}

	ccCtl, err := ccctl.New(ctx, octeliumC, &ccctl.Opts{
		OnUpdate: func(ctx context.Context, new, old *corev1.ClusterConfig) error {
			if !pbutils.IsEqual(new.Spec.Dns, old.Spec.Dns) {
				zap.L().Debug("Updating fallback upstreams", zap.Any("dnsConfig", new.Spec.Dns))
				ret.setDefaultUpstreams(new)
				ret.fallbackZoneCache.setDuration(getDuration(new))
			}

			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	ret.ccCtl = ccCtl
	ret.domain = ccCtl.Get().Status.Domain
	ret.setDefaultUpstreams(ccCtl.Get())

	ret.fallbackZoneCache = newZoneCache(getDuration(ret.ccCtl.Get()))

	return ret, nil
}

type upstream struct {
	host string
	port int
	typ  string
}

func (u *upstream) getAddr() string {
	return net.JoinHostPort(u.host, fmt.Sprintf("%d", u.port))
}

/*
func (s *DNSServer) Resolve(arg string, isIPv6 bool) net.IP {
	zap.S().Debugf("resolving dns for svc: %s", arg)
	res, found := s.cache.Get(fmt.Sprintf("svc:%s", arg))
	if !found {
		return nil
	}

	svcInfo := res.(SvcInfo)
	if len(svcInfo.Addresses) == 0 {
		return nil
	}

	addr := svcInfo.Addresses[svcInfo.CurIdx]

	var ret net.IP
	if isIPv6 {
		ret = net.ParseIP(addr.DualStackIP.Ipv6)
	} else {
		ret = net.ParseIP(addr.DualStackIP.Ipv4)
	}

	svcInfo.CurIdx = uint32((int(svcInfo.CurIdx) + 1) % len(svcInfo.Addresses))

	s.cache.Set(fmt.Sprintf("svc:%s", arg), svcInfo, 0)

	return ret
}
*/

type SvcInfo struct {
	Addresses []*corev1.Service_Status_Address
	CurIdx    uint32
}

func getKey(svc *corev1.Service) string {
	return fmt.Sprintf("svc:%s", svc.Metadata.Name)
}

func (s *DNSServer) Set(svc *corev1.Service) {

	zap.S().Debugf("Setting Service %s: %+v", svc.Metadata.Name, svc.Status.Addresses)

	s.cache.set(svc)

}

func (s *DNSServer) Unset(svc *corev1.Service) {
	// s.cache.Delete(getKey(svc))
	s.cache.delete(svc)
}

func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		msg := dns.Msg{}
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
		return
	}

	msg := dns.Msg{}
	msg.SetReply(r)

	domain := msg.Question[0].Name

	if !govalidator.IsDNSName(domain) {
		msg := dns.Msg{}
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
		return
	}

	hostname, err := s.getHostname(domain)
	if err != nil {
		ret, err := s.getProxiedAnswer(domain, r.Question[0].Qtype)
		if err != nil {
			msg.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(&msg)
			zap.S().Debugf("Could not find svcNs for domain: %s", domain)
			return
		}

		msg.Answer = ret.Answer
		msg.Extra = ret.Extra
		msg.Ns = ret.Ns
		w.WriteMsg(&msg)
		return
	}

	doResolve := func(typ uint16) {

		address := s.cache.get(hostname, typ)
		if address == nil {
			msg.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(&msg)
			return
		}

		msg.Authoritative = true

		switch typ {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: typ, Class: dns.ClassINET, Ttl: 60},
				A:   address,
			})
		case dns.TypeAAAA:
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: typ, Class: dns.ClassINET, Ttl: 60},
				AAAA: address,
			})
		}

		w.WriteMsg(&msg)
		zap.S().Debugf("Successfully resolved for domain: %s | hostname: %s to address: %s",
			domain, hostname, address.String())
	}

	switch r.Question[0].Qtype {
	case dns.TypeA:
		doResolve(dns.TypeA)
		return
	case dns.TypeAAAA:
		doResolve(dns.TypeAAAA)
		return
	default:
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
	}
}

/*
	type svcNs struct {
		svc       string
		namespace string
	}

var rgx = regexp.MustCompile(`^(((?P<svc>[a-z][a-z0-9-]{0,62}[a-z0-9])(\.|_)(?P<ns>[a-z][a-z0-9-]{0,62}[a-z0-9]))|(?P<svc_default>[a-z][a-z0-9-]{0,62}[a-z0-9]))$`)
*/
func (s *DNSServer) getHostname(arg string) (string, error) {

	suffixList := []string{
		fmt.Sprintf(".%s.local.", s.domain),
		fmt.Sprintf(".local.%s.", s.domain),
		fmt.Sprintf(".%s.", s.domain),
		".local.",
	}

	idx := slices.IndexFunc(suffixList, func(suffix string) bool {
		return strings.HasSuffix(arg, suffix)
	})
	if idx < 0 {
		if slices.ContainsFunc(suffixList, func(suffix string) bool {
			return arg == suffix[1:]
		}) {
			return "default.default", nil
		}

		return "", errors.Errorf("not found")
	}
	ret := strings.TrimSuffix(arg, suffixList[idx])

	if ret == "" {
		return "default.default", nil
	}

	return ret, nil
}

/*
func (s *DNSServer) parseSvcNs(arg string) *svcNs {

	if !govalidator.IsASCII(arg) {
		return nil
	}

	suffixList := []string{
		".local.",
		fmt.Sprintf(".local.%s.", s.domain),
		fmt.Sprintf(".%s.local.", s.domain),
		fmt.Sprintf(".%s.", s.domain),
	}

	idx := slices.IndexFunc(suffixList, func(suffix string) bool {
		return strings.HasSuffix(arg, suffix)
	})
	if idx < 0 {
		return nil
	}
	arg = suffixList[idx]
	if arg == "" {
		return &svcNs{
			svc:       "default",
			namespace: "default",
		}
	}

	for _, suffix := range suffixList {
		if strings.HasSuffix(arg, suffix) {
			str := strings.TrimSuffix(arg, suffix)

			match := rgx.FindStringSubmatch(str)

			if len(match) == 0 {
				continue
			}

			var svc, ns, svcDefault string

			for i, name := range rgx.SubexpNames() {
				switch name {
				case "svc":
					svc = match[i]
				case "ns":
					ns = match[i]
				case "svc_default":
					svcDefault = match[i]
				}
			}

			if svcDefault != "" {
				return &svcNs{
					svc:       svcDefault,
					namespace: "default",
				}
			} else if svc != "" && ns != "" {
				return &svcNs{
					svc:       svc,
					namespace: ns,
				}
			}

		}
	}

	return nil
}
*/

func (s *DNSServer) Run(ctx context.Context) error {

	if err := s.ccCtl.Run(ctx); err != nil {
		return err
	}

	if len(s.upstreams) == 0 {
		s.setDefaultUpstreams(s.ccCtl.Get())
	}

	go s.fallbackZoneCache.startCleanupLoop(ctx)

	{
		srv := &dns.Server{Addr: fmt.Sprintf("[::1]:%d", vutils.ManagedServicePort), Net: "udp"}
		srv.Handler = s

		go func() {
			if err := srv.ListenAndServe(); err != nil {
				zap.S().Debugf("Failed to set udp listener %s\n", err.Error())
			}
		}()
	}

	{
		srv := &dns.Server{Addr: fmt.Sprintf("127.0.0.1:%d", vutils.ManagedServicePort), Net: "udp"}
		srv.Handler = s

		go func() {
			if err := srv.ListenAndServe(); err != nil {
				zap.S().Debugf("Failed to set udp listener %s\n", err.Error())
			}
			zap.L().Debug("DNS server existed...")
		}()
	}

	return nil
}

func (s *DNSServer) getProxiedAnswer(domain string, typ uint16) (*dns.Msg, error) {

	zap.L().Debug("Getting proxied answer", zap.String("domain", domain), zap.Uint16("type", typ))
	if cached := s.fallbackZoneCache.get(domain, typ); cached != nil {
		zap.L().Debug("Found cached proxied answer", zap.String("domain", domain), zap.Any("answer", cached))
		return cached, nil
	}

	upstream := s.chooseUpstream()
	c := dns.Client{
		Net:     upstream.typ,
		Timeout: 6 * time.Second,
	}
	m := dns.Msg{}

	m.SetQuestion(domain, typ)

	r, _, err := c.Exchange(&m, upstream.getAddr())
	if err != nil {
		return nil, err
	}

	s.fallbackZoneCache.set(domain, typ, r)

	zap.L().Debug("Found cached proxied answer", zap.String("domain", domain), zap.Any("answer", r))
	return r, nil
}

func (s *DNSServer) chooseUpstream() *upstream {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.upstreams[utilrand.GetRandomRangeMath(0, len(s.upstreams)-1)]
}

func (s *DNSServer) setDefaultUpstreams(cc *corev1.ClusterConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	getPort := func(u *url.URL) int {
		if u.Port() != "" {
			if port, err := strconv.Atoi(u.Port()); err == nil && port > 0 && port <= 65535 {
				return port
			}
		}
		return 0
	}

	s.upstreams = nil
	if cc != nil && cc.Spec.Dns != nil && cc.Spec.Dns.FallbackZone != nil &&
		len(cc.Spec.Dns.FallbackZone.Servers) > 0 {
		for _, server := range cc.Spec.Dns.FallbackZone.Servers {
			u, err := url.Parse(server)
			if err != nil {
				zap.L().Warn("Could not parse fallback server. Skipping...",
					zap.Error(err), zap.String("server", server))
				continue
			}

			switch u.Scheme {
			case "dns", "", "udp":
				upstream := &upstream{
					host: u.Host,
					port: getPort(u),
				}
				if upstream.port == 0 {
					upstream.port = 53
				}
				s.upstreams = append(s.upstreams, upstream)
			case "tls":
				upstream := &upstream{
					host: u.Host,
					port: getPort(u),
					typ:  "tcp-tls",
				}
				if upstream.port == 0 {
					upstream.port = 853
				}
				s.upstreams = append(s.upstreams, upstream)
			default:
				continue
			}

		}
	}

	if len(s.upstreams) > 0 {
		return
	}

	zap.L().Debug("Fallbacking to default fallback servers...")

	s.upstreams = []*upstream{
		{
			host: "8.8.8.8",
			port: 853,
			typ:  "tcp-tls",
		},
		{
			host: "1.1.1.1",
			port: 853,
			typ:  "tcp-tls",
		},
	}

}
