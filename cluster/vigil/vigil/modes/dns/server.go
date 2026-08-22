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

package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/controllers"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

func qtypeString(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeMX:
		return "MX"
	case dns.TypeCNAME:
		return "CNAME"
	default:
		return "OTHER"
	}
}

func rcodeClassOf(rcode int) string {
	switch rcode {
	case dns.RcodeSuccess:
		return "NOERROR"
	case dns.RcodeNameError:
		return "NXDOMAIN"
	case dns.RcodeRefused:
		return "REFUSED"
	case dns.RcodeServerFailure:
		return "SERVFAIL"
	case dns.RcodeFormatError:
		return "FORMERR"
	case dns.RcodeNotImplemented:
		return "NOTIMP"
	case dns.RcodeNotAuth:
		return "NOTAUTH"
	default:
		return "OTHER"
	}
}

func malformedReason(r *dns.Msg) string {
	switch {
	case r.Response:
		return "RESPONSE"
	case r.Opcode != dns.OpcodeQuery:
		return "OPCODE"
	case len(r.Question) == 0:
		return "NO_QUESTION"
	default:
		return "MULTI_QUESTION"
	}
}

type countingResponseWriter struct {
	dns.ResponseWriter

	size      int
	truncated bool
	written   bool
}

func (w *countingResponseWriter) WriteMsg(m *dns.Msg) error {
	err := w.ResponseWriter.WriteMsg(m)
	if err != nil || m == nil {
		return err
	}

	w.size = m.Len()
	w.truncated = m.Truncated
	w.written = true

	return nil
}

type Server struct {
	octovigilC *octovigilc.Client
	vCache     *vcache.Cache
	mu         sync.RWMutex

	srv *dns.Server

	octeliumC octeliumc.ClientInterface

	cancelFn context.CancelFunc

	isClosed bool

	svcCtl     *controllers.ServiceController
	sessionCtl *controllers.SessionController
	lbManager  *loadbalancer.LBManager

	secretMan *secretman.SecretManager

	svcRef *metav1.ObjectReference

	metricsStore *metricsStore
}

type metricsStore struct {
	*metricutils.CommonMetrics
	dnsMetrics *metricutils.DNSMetrics
}

func New(ctx context.Context, opts *modes.Opts) (*Server, error) {
	ret := &Server{
		octovigilC:   opts.OctovigilC,
		vCache:       opts.VCache,
		octeliumC:    opts.OcteliumC,
		lbManager:    opts.LBManager,
		svcCtl:       &controllers.ServiceController{},
		sessionCtl:   &controllers.SessionController{},
		secretMan:    opts.SecretMan,
		metricsStore: &metricsStore{},
	}

	var err error
	ret.metricsStore.CommonMetrics, err = metricutils.NewCommonMetrics(ctx, opts.VCache.GetService())
	if err != nil {
		return nil, err
	}

	ret.metricsStore.dnsMetrics, err = metricutils.NewDNSMetrics(ctx, opts.VCache.GetService())
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Server) SetClusterCertificate(crt *corev1.Secret) error {
	return nil
}

func (s *Server) Run(ctx context.Context) error {
	zap.L().Debug("Starting running DNS server")

	svc := s.vCache.GetService()
	if svc == nil {
		return errors.Errorf("Nil svc")
	}
	s.svcRef = umetav1.GetObjectReference(svc)

	addr := &net.UDPAddr{
		IP:   net.ParseIP("::"),
		Port: ucorev1.ToService(svc).RealPort(),
	}

	zap.L().Debug("Listening to addr", zap.String("addr", addr.String()))

	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	s.srv = &dns.Server{Addr: addr.String(), Net: "udp"}
	s.srv.Handler = s

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	go func() {
		if err := s.srv.ListenAndServe(); err != nil {
			zap.L().Debug("Failed to listen DNS server", zap.Error(err))
		}
	}()

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	zap.L().Debug("Starting closing DNS server")
	s.isClosed = true
	if s.cancelFn != nil {
		s.cancelFn()
	}

	if s.srv != nil {
		_ = s.srv.Shutdown()
	}

	zap.L().Debug("DNS server is now closed")
	return nil
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	startedAt := time.Now()
	defer func() {
		if err := recover(); err != nil {
			zap.L().Error("Recovered from DNS request panic", zap.Any("error", err))
		}
	}()

	if r == nil {
		return
	}

	if r.Response || r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(msg)
		s.metricsStore.dnsMetrics.AddMalformed(malformedReason(r))
		return
	}

	cw := &countingResponseWriter{ResponseWriter: w}
	w = cw

	var (
		state      = "DENIED"
		reason     string
		qtype      string
		rcodeClass string
	)

	s.metricsStore.AtRequestStart()
	defer func() {
		attrs := []attribute.KeyValue{
			attribute.String("state", state),
		}
		if reason != "" {
			attrs = append(attrs, attribute.String("reason", reason))
		}
		if qtype != "" {
			attrs = append(attrs, attribute.String("qtype", qtype))
		}
		if rcodeClass != "" {
			attrs = append(attrs, attribute.String("rcode_class", rcodeClass))
		}
		s.metricsStore.AtRequestEnd(startedAt, metric.WithAttributeSet(attribute.NewSet(attrs...)))

		if cw.written {
			s.metricsStore.dnsMetrics.RecordResponseBytes(cw.size, cw.truncated)
		}
	}()

	svc := s.vCache.GetService()
	if svc == nil || svc.Spec.IsDisabled {
		if svc == nil {
			zap.L().Warn("Could not get the Service from cache")
		}
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(msg)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var address string
	var port int

	switch addr := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		address = addr.IP.String()
		port = addr.Port
	default:
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(msg)
		return
	}

	q := r.Question[0]
	qtype = qtypeString(q.Qtype)

	canonicalName := strings.ToLower(dns.Fqdn(q.Name))

	req := &coctovigilv1.DownstreamRequest{
		Source: &coctovigilv1.DownstreamRequest_Source{
			Address: address,
			Port:    int32(port),
		},
		Request: &corev1.RequestContext_Request{
			Type: &corev1.RequestContext_Request_Dns{
				Dns: &corev1.RequestContext_Request_DNS{
					Name:   canonicalName,
					TypeID: int32(q.Qtype),
				},
			},
		},
	}

	authResp, err := s.octovigilC.AuthenticateAndAuthorize(ctx, &octovigilc.AuthenticateAndAuthorizeRequest{
		Request: req,
	})
	if err != nil {
		zap.L().Warn("Could not get AuthenticateAndAuthorize", zap.Error(err))
		rcodeClass = rcodeClassOf(dns.RcodeServerFailure)
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(msg)
		return
	}

	if !authResp.IsAuthenticated {
		rcodeClass = rcodeClassOf(dns.RcodeRefused)
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(msg)
		return
	}

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       startedAt,
		IsAuthenticated: authResp.IsAuthenticated,
		IsAuthorized:    authResp.IsAuthorized,
		ReqCtx:          authResp.RequestContext,
		Reason:          authResp.AuthorizationDecisionReason,
	})

	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Dns{
		Dns: &corev1.AccessLog_Entry_Info_DNS{
			Type: func() corev1.AccessLog_Entry_Info_DNS_Type {
				switch q.Qtype {
				case dns.TypeA:
					return corev1.AccessLog_Entry_Info_DNS_A
				case dns.TypeAAAA:
					return corev1.AccessLog_Entry_Info_DNS_AAAA
				case dns.TypeTXT:
					return corev1.AccessLog_Entry_Info_DNS_TXT
				case dns.TypeMX:
					return corev1.AccessLog_Entry_Info_DNS_MX
				case dns.TypeCNAME:
					return corev1.AccessLog_Entry_Info_DNS_CNAME
				default:
					return corev1.AccessLog_Entry_Info_DNS_TYPE_OTHER
				}
			}(),
			TypeID: int64(q.Qtype),
			Name:   canonicalName,
		},
	}

	if !authResp.IsAuthorized {
		rcodeClass = rcodeClassOf(dns.RcodeRefused)
		reason = authResp.AuthorizationDecisionReason.GetType().String()
		logE.Entry.Info.GetDns().Rcode = int64(dns.RcodeRefused)
		otelutils.EmitAccessLog(logE)
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(msg)
		return
	}

	state = "ALLOWED"

	upstream, err := s.lbManager.GetUpstream(ctx, authResp)
	if err != nil {
		zap.L().Warn("Could not get lb upstream", zap.Error(err))
		rcodeClass = rcodeClassOf(dns.RcodeServerFailure)
		logE.Entry.Info.GetDns().Rcode = int64(dns.RcodeServerFailure)
		otelutils.EmitAccessLog(logE)

		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(msg)
		return
	}

	clientReq := r.Copy()

	client := dns.Client{
		Net: func() string {
			if upstream.URL == nil {
				return "udp"
			}
			switch upstream.URL.Scheme {
			case "tls", "tcp-tls", "dot":
				return "tcp-tls"
			case "tcp":
				return "tcp"
			default:
				return "udp"
			}
		}(),
		Timeout: 5 * time.Second,
	}

	proxiedMsg, _, err := client.Exchange(clientReq, upstream.HostPort)
	if err != nil || proxiedMsg == nil {
		zap.L().Warn("Could not do exchange", zap.Error(err), zap.String("upstream", upstream.HostPort))
		rcodeClass = rcodeClassOf(dns.RcodeServerFailure)
		logE.Entry.Info.GetDns().Rcode = int64(dns.RcodeServerFailure)
		otelutils.EmitAccessLog(logE)

		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(msg)
		return
	}

	resp := new(dns.Msg)
	resp.MsgHdr = proxiedMsg.MsgHdr
	resp.Id = r.Id

	resp.Question = r.Question
	resp.Answer = proxiedMsg.Answer
	resp.Ns = proxiedMsg.Ns
	resp.Extra = proxiedMsg.Extra

	_ = w.WriteMsg(resp)

	rcodeClass = rcodeClassOf(resp.Rcode)
	logE.Entry.Info.GetDns().Rcode = int64(resp.Rcode)
	if len(resp.Answer) > 0 {
		answer := resp.Answer[0]
		logE.Entry.Info.GetDns().Answer = strings.TrimPrefix(answer.String(), answer.Header().String())
	}
	otelutils.EmitAccessLog(logE)
}
