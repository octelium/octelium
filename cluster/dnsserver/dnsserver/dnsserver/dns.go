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
	"bufio"
	"bytes"
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
	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/ccctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
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
	fallbackZone      *dnsZone
	zones             []*dnsZone

	reservedNamespaces []string
}

type dnsZone struct {
	domains   []string
	upstreams []*upstream
	cache     *zoneCache
}

func Initialize(ctx context.Context, octeliumC octeliumc.ClientInterface) (*DNSServer, error) {

	ret := &DNSServer{
		cache:             newCache(),
		fallbackZoneCache: newZoneCache(0),
	}

	ret.setReservedNamespaces(ctx)

	ccCtl, err := ccctl.New(ctx, octeliumC, &ccctl.Opts{
		OnUpdate: func(ctx context.Context, new, old *corev1.ClusterConfig) error {
			if !pbutils.IsEqual(new.Spec.Dns, old.Spec.Dns) {
				zap.L().Debug("Updating DNS upstreams", zap.Any("dnsConfig", new.Spec.Dns))
				ret.setDNSConfig(new)
			}

			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	ret.ccCtl = ccCtl
	ret.domain = ccCtl.Get().Status.Domain
	ret.setDNSConfig(ccCtl.Get())

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

type SvcInfo struct {
	Addresses []*corev1.Service_Status_Address
	CurIdx    uint32
}

func (s *DNSServer) Set(svc *corev1.Service) {
	zap.L().Debug("Setting Service", zap.String("name", svc.Metadata.Name), zap.Any("addrs", svc.Status.Addresses))
	s.cache.set(svc)
}

func (s *DNSServer) Unset(svc *corev1.Service) {
	s.cache.delete(svc)
}

func getRequestUDPSize(r *dns.Msg) int {
	if opt := r.IsEdns0(); opt != nil {
		if size := int(opt.UDPSize()); size >= dns.MinMsgSize {
			return size
		}
	}

	return dns.MinMsgSize
}

func writeUpstreamReply(w dns.ResponseWriter, r *dns.Msg, resp *dns.Msg) {
	resp.Id = r.Id
	resp.Question = r.Question
	resp.Response = true
	resp.RecursionAvailable = true

	resp.Truncate(getRequestUDPSize(r))

	if err := w.WriteMsg(resp); err != nil {
		zap.L().Debug("Could not write the DNS response", zap.Error(err))
	}
}

func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	if r == nil {
		return
	}

	if len(r.Question) == 0 {
		msg := dns.Msg{}
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
		zap.L().Debug("Empty list of questions")
		return
	}

	msg := dns.Msg{}
	msg.SetReply(r)

	domain := strings.ToLower(msg.Question[0].Name)

	switch msg.Question[0].Qtype {
	case dns.TypeA, dns.TypeAAAA:
	default:
		ret, err := s.getProxiedAnswer(domain, r.Question[0].Qtype)
		if err != nil {
			msg.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(&msg)
			zap.L().Debug("Could not getProxiedAnswer", zap.String("domain", domain))
			return
		}

		writeUpstreamReply(w, r, ret)
		return
	}

	if !govalidator.IsDNSName(domain) {
		msg := dns.Msg{}
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
		zap.L().Debug("Invalid domain req", zap.String("domain", domain))
		return
	}

	hostname, err := s.getHostname(domain)
	if err != nil {
		// zap.L().Debug("Could not get hostname", zap.String("domain", domain), zap.Error(err))
		ret, err := s.getProxiedAnswer(domain, r.Question[0].Qtype)
		if err != nil {
			msg.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(&msg)
			zap.L().Debug("Could not getProxiedAnswer", zap.String("domain", domain))
			return
		}

		writeUpstreamReply(w, r, ret)
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
		/*
			zap.L().Debug("Successfully resolved for domain",
				zap.String("domain", domain),
				zap.String("hostname", hostname),
				zap.String("addr", address.String()))
		*/
	}

	switch r.Question[0].Qtype {
	case dns.TypeA:
		doResolve(dns.TypeA)
		return
	case dns.TypeAAAA:
		doResolve(dns.TypeAAAA)
		return
	default:
		// zap.L().Debug("Invalid qType", zap.Uint16("type", r.Question[0].Qtype))
		msg.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(&msg)
		return
	}
}

func (s *DNSServer) getHostname(arg string) (string, error) {
	domainLen := len(arg)
	if domainLen < 1 || domainLen > 256 {
		return "", errNotFound
	}

	suffixList := []string{
		fmt.Sprintf(".local.%s.", s.domain),
		fmt.Sprintf(".%s.local.", s.domain),
		".local.",
	}

	idx := slices.IndexFunc(suffixList, func(suffix string) bool {
		return strings.HasSuffix(arg, suffix)
	})
	if idx < 0 {
		return s.getHostnameFromPossibleHostname(arg)
	}
	ret := strings.TrimSuffix(arg, suffixList[idx])

	if ret == "" {
		return "default.default", nil
	}

	parts := strings.Split(ret, ".")

	switch len(parts) {
	case 0:
		return "default.default", nil
	case 1:
		return fmt.Sprintf("%s.default", parts[0]), nil
	case 2:
		return ret, nil
	default:
		l := len(parts)
		return fmt.Sprintf("%s.%s", parts[l-2], parts[l-1]), nil
	}

}

func (s *DNSServer) getHostnameFromPossibleHostname(arg string) (string, error) {
	hostname := strings.TrimSuffix(arg, ".")

	parts := strings.Split(hostname, ".")
	switch len(parts) {
	case 1:
		ret := fmt.Sprintf("%s.default", hostname)
		if s.cache.has(ret) {
			return ret, nil
		}
	case 2:
		cacheExists := s.cache.has(hostname)
		if slices.Contains(wellKnownNamespaces, parts[1]) && cacheExists {
			return hostname, nil
		}
		if !slices.Contains(s.reservedNamespaces, parts[1]) && cacheExists {
			return hostname, nil
		}
	}

	return "", errNotFound
}

var errNotFound = errors.Errorf("not found")

func (s *DNSServer) Run(ctx context.Context) error {

	if err := s.ccCtl.Run(ctx); err != nil {
		return err
	}

	go s.startZoneCacheCleanupLoop(ctx)

	for _, addr := range []string{
		fmt.Sprintf("[::1]:%d", vutils.ManagedServicePort),
		fmt.Sprintf("127.0.0.1:%d", vutils.ManagedServicePort),
	} {
		srv := &dns.Server{Addr: addr, Net: "udp"}
		srv.Handler = s

		go func() {
			if err := srv.ListenAndServe(); err != nil {
				zap.L().Debug("Failed to set udp listener",
					zap.String("addr", addr), zap.Error(err))
			}
			zap.L().Debug("DNS server exited...", zap.String("addr", addr))
		}()
	}

	return nil
}

func (s *DNSServer) getProxiedAnswer(domain string, typ uint16) (*dns.Msg, error) {
	zone := s.getDNSZone(domain)

	if cached := zone.cache.get(domain, typ); cached != nil {
		return cached, nil
	}

	upstream := chooseUpstream(zone)
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

	zone.cache.set(domain, typ, r)

	return r, nil
}

func chooseUpstream(zone *dnsZone) *upstream {
	return zone.upstreams[utilrand.GetRandomRangeMath(0, len(zone.upstreams)-1)]
}

func (s *DNSServer) getDNSZone(domain string) *dnsZone {
	domain = strings.ToLower(dns.Fqdn(domain))

	s.mu.RLock()
	defer s.mu.RUnlock()

	ret := s.fallbackZone
	matchLen := 0
	for _, zone := range s.zones {
		for _, suffix := range zone.domains {
			if len(suffix) <= matchLen {
				continue
			}
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				ret = zone
				matchLen = len(suffix)
			}
		}
	}

	return ret
}

func (s *DNSServer) startZoneCacheCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(6 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			caches := make([]*zoneCache, 0, len(s.zones)+1)
			caches = append(caches, s.fallbackZoneCache)
			for _, zone := range s.zones {
				caches = append(caches, zone.cache)
			}
			s.mu.RUnlock()

			for _, cache := range caches {
				cache.doCleanup()
			}
		}
	}
}

func (s *DNSServer) setDNSConfig(cc *corev1.ClusterConfig) {
	s.setDefaultUpstreams(cc)

	s.mu.Lock()
	defer s.mu.Unlock()

	var dnsConfig *corev1.ClusterConfig_Spec_DNS
	if cc != nil && cc.Spec != nil {
		dnsConfig = cc.Spec.Dns
	}

	var fallbackConfig *corev1.ClusterConfig_Spec_DNS_Zone
	if dnsConfig != nil {
		fallbackConfig = dnsConfig.FallbackZone
	}
	s.fallbackZoneCache.setDuration(getZoneDuration(fallbackConfig))
	s.fallbackZone = &dnsZone{
		upstreams: s.upstreams,
		cache:     s.fallbackZoneCache,
	}

	s.zones = nil
	if dnsConfig == nil {
		return
	}

	for _, zoneConfig := range dnsConfig.Zones {
		if zoneConfig == nil {
			continue
		}

		zone := &dnsZone{
			upstreams: parseZoneUpstreams(zoneConfig.Servers),
			cache:     newZoneCache(getZoneDuration(zoneConfig)),
		}
		for _, domain := range zoneConfig.Domains {
			domain = strings.ToLower(dns.Fqdn(domain))
			if domain != "." {
				zone.domains = append(zone.domains, domain)
			}
		}

		if len(zone.domains) > 0 && len(zone.upstreams) > 0 {
			s.zones = append(s.zones, zone)
		}
	}
}

func getZoneDuration(zone *corev1.ClusterConfig_Spec_DNS_Zone) time.Duration {
	if zone == nil || zone.CacheDuration == nil {
		return 0
	}
	return umetav1.ToDuration(zone.CacheDuration).ToGo()
}

func parseZoneUpstreams(servers []string) []*upstream {
	var ret []*upstream

	for _, server := range servers {
		if ip := net.ParseIP(server); ip != nil {
			ret = append(ret, &upstream{host: server, port: 53})
			continue
		}

		arg := server
		if !strings.Contains(arg, "://") {
			arg = "dns://" + arg
		}

		u, err := url.Parse(arg)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" ||
			u.RawQuery != "" || u.Fragment != "" {
			zap.L().Warn("Could not parse DNS server. Skipping...",
				zap.Error(err), zap.String("server", server))
			continue
		}

		port := 0
		if u.Port() != "" {
			port, err = strconv.Atoi(u.Port())
			if err != nil || port < 1 || port > 65535 {
				zap.L().Warn("Could not parse DNS server port. Skipping...",
					zap.Error(err), zap.String("server", server))
				continue
			}
		}

		upstream := &upstream{host: u.Hostname()}
		switch u.Scheme {
		case "dns", "udp":
			if port == 0 {
				port = 53
			}
		case "tls":
			upstream.typ = "tcp-tls"
			if port == 0 {
				port = 853
			}
		default:
			continue
		}
		upstream.port = port
		ret = append(ret, upstream)
	}

	return ret
}

func (s *DNSServer) setDefaultUpstreams(cc *corev1.ClusterConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var servers []string
	if cc != nil && cc.Spec != nil && cc.Spec.Dns != nil && cc.Spec.Dns.FallbackZone != nil {
		servers = cc.Spec.Dns.FallbackZone.Servers
	}
	s.upstreams = parseZoneUpstreams(servers)

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

func (s *DNSServer) setReservedNamespaces(ctx context.Context) {

	resp, err := resty.New().SetDebug(ldflags.IsDev()).
		SetTimeout(5 * time.Second).
		R().
		SetContext(ctx).
		Get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
	if err != nil {
		s.reservedNamespaces = wellKnownTLDs
		zap.L().Warn("Could not fetch iana list of TLDs. Falling back to wellKnownTLDs")
		return
	}

	if !resp.IsSuccess() {
		s.reservedNamespaces = wellKnownTLDs
		zap.L().Warn("Could not fetch iana list of TLDs. Falling back to wellKnownTLDs...",
			zap.Int("statusCode", resp.StatusCode()))
		return
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(resp.Body()))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		line = strings.ToLower(line)

		if err := apivalidation.ValidateName(line, 0, 0); err != nil {
			continue
		}

		s.reservedNamespaces = append(s.reservedNamespaces, line)
	}

	if len(s.reservedNamespaces) < len(wellKnownTLDs) {
		s.reservedNamespaces = wellKnownTLDs
	} else {
		zap.L().Debug("Successfully fetched the iana list of TLDs",
			zap.Int("len", len(s.reservedNamespaces)))
	}
}

var wellKnownTLDs = []string{
	"com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "arpa",

	"academy", "accountant", "actor", "agency", "app", "art", "associates",
	"attorney", "auction", "audio", "auto", "band", "bank", "bargains",
	"beer", "best", "bike", "bio", "blog", "boats", "broker", "build",
	"builders", "business", "buzz", "cafe", "camera", "camp", "capital",
	"cards", "care", "careers", "cash", "casino", "catering", "center",
	"ceo", "chat", "church", "city", "claims", "cleaning", "click", "clinic",
	"clothing", "cloud", "club", "coach", "codes", "coffee", "community",
	"company", "computer", "condos", "construction", "consulting",
	"contact", "contractors", "cool", "credit", "deals", "dental",
	"dentist", "design", "dev", "diamonds", "digital", "directory",
	"discount", "doctor", "dog", "domains", "education", "email",
	"energy", "engineer", "engineering", "enterprises", "estate", "events",
	"exchange", "expert", "exposed", "express", "family", "fans", "farm",
	"fashion", "film", "finance", "financial", "firm", "fish", "fishing",
	"fit", "fitness", "flights", "florist", "flowers", "food", "football",
	"forsale", "foundation", "fund", "furniture", "gallery", "games",
	"garden", "gifts", "gives", "giving", "glass", "global", "gold",
	"golf", "graphics", "green", "group", "guide", "guitars", "guru",
	"hair", "haus", "health", "healthcare", "help", "homes", "horse",
	"hospital", "host", "hosting", "house", "how", "inc", "industries",
	"insure", "insurance", "international", "investments", "jewelry",
	"jobs", "land", "law", "lawyer", "lease", "legal", "life",
	"lighting", "limited", "limo", "link", "live", "loan", "loans",
	"lol", "love", "ltd", "luxury", "management", "market", "marketing",
	"markets", "media", "medical", "menu", "money", "mortgage",
	"motorcycles", "movie", "museum", "name", "network", "news", "ninja",
	"online", "partners", "parts", "pet", "photography", "photos", "photo",
	"pictures", "pizza", "place", "plumbing", "plus", "press", "pro",
	"productions", "properties", "property", "realty", "rentals",
	"repair", "report", "republican", "restaurant", "reviews", "sale",
	"school", "science", "services", "shop", "shopping", "site",
	"ski", "soccer", "social", "software", "solutions", "space", "store",
	"studio", "style", "systems", "tax", "taxi", "team", "tech", "technology",
	"theater", "tickets", "tips", "tires", "tools", "tours", "town", "toys",
	"trade", "training", "travel", "university", "vacations", "video",
	"villas", "vision", "vote", "voyage", "watch", "website", "wedding",
	"wiki", "wine", "work", "works", "world", "wtf", "xyz", "zone",

	"ac", "ad", "ae", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "as",
	"at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi",
	"bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz", "ca", "cc", "cd",
	"cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cx",
	"cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg", "er", "es",
	"et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb", "gd", "ge", "gf",
	"gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw",
	"gy", "hk", "hm", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "io",
	"iq", "ir", "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km",
	"kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls",
	"lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg", "mh", "mk", "ml", "mm",
	"mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz",
	"na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
	"pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw",
	"py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg",
	"sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "st", "su", "sv", "sy", "sz",
	"tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt",
	"tv", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg",
	"vi", "vn", "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw",
}

var wellKnownNamespaces = []string{
	"default", "octelium", "octelium-api", "cordium",
}
