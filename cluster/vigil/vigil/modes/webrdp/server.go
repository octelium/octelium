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

package webrdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/coder/websocket"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/ocrypto"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/accesslog"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/auth"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/compress"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/metrics"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/preauth"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/rdp"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

//go:embed web
var fsWeb embed.FS

const (
	webSocketPath = "/ws"

	dialTimeout       = 20 * time.Second
	readHeaderTimeout = 5 * time.Second
	idleTimeout       = 60 * time.Second
	shutdownTimeout   = 10 * time.Second
	maxHeaderBytes    = 32 * 1024
	maxMessageSize    = 64 * 1024 * 1024
)

type Server struct {
	octeliumC  octeliumc.ClientInterface
	octovigilC *octovigilc.Client

	vCache    *vcache.Cache
	lbManager *loadbalancer.LBManager

	lis     net.Listener
	httpSrv *http.Server

	mu        sync.Mutex
	isClosed  bool
	secretMan *secretman.SecretManager

	crtMan struct {
		mu  sync.RWMutex
		crt *corev1.Secret
	}
	metricsStore *metricutils.CommonMetrics
	domain       string
}

type templateGlobals struct {
	WebSocketPath string `json:"webSocketPath,omitempty"`
	Destination   string `json:"destination,omitempty"`
	Secretless    bool   `json:"secretless,omitempty"`
}

var indexTmpl = template.Must(template.New("state").Parse(
	`<script nonce="{{ .Nonce }}">window.__OCTELIUM_RDP_WEB__ = {{ .Globals }}</script>`,
))

func New(ctx context.Context, opts *modes.Opts) (*Server, error) {
	ret := &Server{
		octeliumC:  opts.OcteliumC,
		octovigilC: opts.OctovigilC,
		vCache:     opts.VCache,
		lbManager:  opts.LBManager,
		secretMan:  opts.SecretMan,
	}

	var err error
	ret.metricsStore, err = metricutils.NewCommonMetrics(ctx, opts.VCache.GetService())
	if err != nil {
		return nil, err
	}

	cc, err := ret.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}
	ret.domain = cc.Status.Domain

	return ret, nil
}

func (s *Server) Run(ctx context.Context) error {
	svc := s.vCache.GetService()
	addr := fmt.Sprintf(":%d", ucorev1.ToService(svc).RealPort())

	handler, err := s.getHTTPHandler(ctx)
	if err != nil {
		return err
	}

	if svc.Spec.IsTLS {
		tlsCfg, err := s.getTLSConfig(ctx)
		if err != nil {
			return err
		}
		s.lis, err = tls.Listen("tcp", addr, tlsCfg)
	} else {
		s.lis, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return err
	}

	s.httpSrv = &http.Server{
		Handler:           handler,
		Addr:              addr,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	go func() {
		zap.L().Info("webrdp is running",
			zap.String("addr", addr),
			zap.String("webSocketPath", webSocketPath))

		if err := s.httpSrv.Serve(s.lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			zap.L().Error("webrdp HTTP server exited", zap.Error(err))
		}
	}()

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}
	s.isClosed = true
	s.mu.Unlock()
	if s.httpSrv == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := s.httpSrv.Shutdown(ctx); err != nil {
		s.httpSrv.Close()
		return err
	}

	zap.L().Debug("webrdp closed")
	return nil
}

func (s *Server) SetClusterCertificate(crt *corev1.Secret) error {
	s.crtMan.mu.Lock()
	defer s.crtMan.mu.Unlock()
	s.crtMan.crt = crt
	return nil
}

func (s *Server) getTLSConfig(ctx context.Context) (*tls.Config, error) {
	crt, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: vutils.ClusterCertSecretName})
	if err != nil && !grpcerr.IsNotFound(err) {
		return nil, err
	}

	s.crtMan.mu.Lock()
	s.crtMan.crt = crt
	s.crtMan.mu.Unlock()

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.crtMan.mu.RLock()
			defer s.crtMan.mu.RUnlock()
			return ocrypto.GetTLSCertificate(s.crtMan.crt)
		},
	}, nil
}

func (s *Server) getHTTPHandler(ctx context.Context) (http.Handler, error) {
	chain := middlewares.New()

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			svc := s.vCache.GetService()
			reqCtx := &middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}

			ctx := context.WithValue(r.Context(), middlewares.CtxRequestContext, reqCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		}), nil
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return metrics.New(ctx, next, s.metricsStore, nil)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return preauth.New(ctx, next, s.octeliumC, s.domain)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return compress.New(ctx, next)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return accesslog.New(ctx, next)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return auth.New(ctx, next, s.octeliumC, s.octovigilC, s.domain)
	})

	handler, err := chain.Then(s.getMux())
	if err != nil {
		return nil, err
	}

	return http.AllowQuerySemicolons(handler), nil
}

func (s *Server) getMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(fmt.Sprintf("GET %s", webSocketPath), s.handleWebSocket)
	mux.Handle("GET /assets/", s.handleStatic())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.handleIndex(w, r)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	return mux
}

func (s *Server) handleStatic() http.Handler {
	subFS, err := fs.Sub(fsWeb, "web")
	if err != nil {
		zap.L().Fatal("Could not initialize webrdp static fs", zap.Error(err))
	}

	fileServer := http.FileServer(http.FS(subFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setStaticHeaders(w)
		fileServer.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.renderIndex(w)
}

func (s *Server) renderIndex(w http.ResponseWriter) {
	nonce := utilrand.GetRandomStringCanonical(24)

	blob, err := fs.ReadFile(fsWeb, filepath.Join("web", "index.html"))
	if err != nil {
		zap.L().Error("Could not read webrdp index.html", zap.Error(err))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(blob))
	if err != nil {
		zap.L().Error("Could not parse webrdp index.html", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	globalsJSON, err := json.Marshal(s.buildTemplateGlobals())
	if err != nil {
		zap.L().Error("Could not marshal webrdp globals", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var scripts bytes.Buffer
	if err := indexTmpl.Execute(&scripts, struct {
		Nonce   string
		Globals template.JS
	}{
		Nonce:   nonce,
		Globals: template.JS(globalsJSON),
	}); err != nil {
		zap.L().Error("Could not execute webrdp index template", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	head := doc.Find("head").First()
	if head.Length() == 0 {
		zap.L().Error("No <head> in webrdp index.html")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	head.AppendHtml(scripts.String())

	doc.Find("script[src]").Each(func(_ int, sel *goquery.Selection) {
		sel.SetAttr("nonce", nonce)
	})

	doc.Find("link[rel='modulepreload']").Each(func(_ int, sel *goquery.Selection) {
		sel.SetAttr("nonce", nonce)
	})

	var out bytes.Buffer
	out.WriteString("<!DOCTYPE html>")
	if err := goquery.Render(&out, head.Parent()); err != nil {
		zap.L().Error("Could not render webrdp index.html", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.setIndexSecurityHeaders(w, nonce)
	w.Write(out.Bytes())
}

func (s *Server) buildTemplateGlobals() *templateGlobals {
	ret := &templateGlobals{
		WebSocketPath: webSocketPath,
	}

	cred, err := s.getInjectedCredential(context.Background())
	if err != nil {
		zap.L().Debug("Could not resolve webrdp injected credential for globals", zap.Error(err))
		return ret
	}

	ret.Secretless = cred != nil
	return ret
}

func (s *Server) setIndexSecurityHeaders(w http.ResponseWriter, nonce string) {
	csp := strings.Join([]string{
		"default-src 'none'",
		fmt.Sprintf("script-src 'self' 'nonce-%s' 'wasm-unsafe-eval'", nonce),
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob:",
		"font-src 'self' data:",
		"connect-src 'self' ws: wss: data:",
		"worker-src 'self' blob:",
		"frame-src 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"manifest-src 'self'",
	}, "; ")

	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func (s *Server) setStaticHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {

	zap.L().Debug("webrdp websocket connection attempt",
		zap.String("remoteAddr", r.RemoteAddr),
		zap.String("requestURI", r.RequestURI),
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("userAgent", r.UserAgent()),
		zap.Strings("header", r.Header["Sec-Websocket-Protocol"]))
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode:    websocket.CompressionDisabled,
		InsecureSkipVerify: true,
	})
	if err != nil {
		zap.L().Debug("Could not accept webrdp websocket", zap.Error(err))
		return
	}
	defer ws.CloseNow()

	ws.SetReadLimit(maxMessageSize)

	ctx := r.Context()

	msgType, reqBytes, err := ws.Read(ctx)
	if err != nil {
		zap.L().Debug("Could not read webrdp RDCleanPath request", zap.Error(err))
		return
	}

	if msgType != websocket.MessageBinary {
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathHTTPError(http.StatusBadRequest))
		ws.Close(websocket.StatusUnsupportedData, "RDCleanPath request must be binary")
		return
	}

	rdcpReq, err := decodeRDCleanPathRequest(reqBytes)
	if err != nil {
		zap.L().Debug("Could not decode RDCleanPath request", zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathHTTPError(http.StatusBadRequest))
		ws.Close(websocket.StatusUnsupportedData, "invalid RDCleanPath request")
		return
	}

	zap.L().Debug("Decoded RDCleanPath request",
		zap.String("destination", rdcpReq.Destination),
		zap.Int("clientX224Length", len(rdcpReq.X224ConnectionPDU)),
		zap.String("clientX224Hex", fmt.Sprintf("%x", rdcpReq.X224ConnectionPDU)))

	cred, err := s.getInjectedCredential(ctx)
	if err != nil {
		zap.L().Debug("Could not resolve webrdp injected credential", zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathGeneralError())
		ws.Close(websocket.StatusInternalError, "could not resolve injected credential")
		return
	}

	trust, err := s.getUpstreamTLSTrust()
	if err != nil {
		zap.L().Debug("Could not resolve webrdp upstream TLS trust", zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathGeneralError())
		ws.Close(websocket.StatusInternalError, "could not resolve upstream TLS trust")
		return
	}

	upstream, err := s.getUpstream(ctx)
	if err != nil {
		zap.L().Debug("Could not get webrdp upstream",
			zap.String("requestedDestination", rdcpReq.Destination),
			zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathHTTPError(http.StatusBadGateway))
		ws.Close(websocket.StatusTryAgainLater, "could not resolve upstream")
		return
	}

	zap.L().Debug("Got upstream", zap.Any("upstream", upstream))

	handshake, err := rdp.PerformHandshake(ctx, &rdp.HandshakeParams{
		Upstream:   upstream,
		ClientX224: rdcpReq.X224ConnectionPDU,
		Credential: cred,
		Trust:      trust,
	})
	if err != nil {
		zap.L().Debug("Could not perform RDP handshake",
			zap.String("requestedDestination", rdcpReq.Destination),
			zap.String("upstream", upstream.HostPort),
			zap.Bool("secretless", cred != nil),
			zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathHTTPError(http.StatusBadGateway))
		ws.Close(websocket.StatusTryAgainLater, "could not connect to upstream RDP server")
		return
	}

	if !handshake.Negotiation {
		zap.L().Debug("RDP handshake negotiation failed",
			zap.String("requestedDestination", rdcpReq.Destination),
			zap.String("upstream", upstream.HostPort),
			zap.Bool("secretless", cred != nil))
		resp, err := encodeRDCleanPathNegotiationError(handshake.X224PDU)
		if err != nil {
			writeRDCleanPathError(ctx, ws, encodeRDCleanPathGeneralError())
			ws.Close(websocket.StatusInternalError, "could not encode negotiation error")
			return
		}

		writeRDCleanPathError(ctx, ws, resp)
		ws.Close(websocket.StatusPolicyViolation, "RDP negotiation failed")
		return
	}

	defer handshake.TLSConn.Close()

	zap.L().Debug("RDP handshake successful",
		zap.String("requestedDestination", rdcpReq.Destination),
		zap.String("upstream", upstream.HostPort),
		zap.Bool("secretless", cred != nil),
		zap.Int("x224ForBrowserLength", len(handshake.X224PDU)),
		zap.String("x224ForBrowserHex", fmt.Sprintf("%x", handshake.X224PDU)),
		zap.Int("certChainCount", len(handshake.CertChain)))
	resp, err := encodeRDCleanPathResponse(
		handshake.ServerAddr,
		handshake.X224PDU,
		handshake.CertChain,
	)
	if err != nil {
		zap.L().Debug("Could not encode RDCleanPath response", zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathGeneralError())
		ws.Close(websocket.StatusInternalError, "could not encode RDCleanPath response")
		return
	}

	zap.L().Debug("Sending RDCleanPath response",
		zap.String("requestedDestination", rdcpReq.Destination),
		zap.String("upstream", upstream.HostPort),
		zap.Bool("secretless", cred != nil),
		zap.Int("responseLength", len(resp)),
		zap.String("responseHex", fmt.Sprintf("%x", resp)))
	if err := ws.Write(ctx, websocket.MessageBinary, resp); err != nil {
		zap.L().Debug("Could not write RDCleanPath response", zap.Error(err))
		return
	}

	wsConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer wsConn.Close()

	zap.L().Debug("webrdp session started",
		zap.String("remoteAddr", r.RemoteAddr),
		zap.String("requestedDestination", rdcpReq.Destination),
		zap.String("upstream", upstream.HostPort),
		zap.Bool("secretless", cred != nil))

	recvBytes, sentBytes := rdp.Relay(ctx, wsConn, handshake.TLSConn, cred != nil)

	zap.L().Debug("webrdp session ended",
		zap.String("remoteAddr", r.RemoteAddr),
		zap.String("requestedDestination", rdcpReq.Destination),
		zap.String("upstream", upstream.HostPort),
		zap.Uint64("receivedBytes", recvBytes),
		zap.Uint64("sentBytes", sentBytes))
}

func writeRDCleanPathError(ctx context.Context, ws *websocket.Conn, pdu []byte) {
	if len(pdu) == 0 {
		return
	}

	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := ws.Write(writeCtx, websocket.MessageBinary, pdu); err != nil {
		zap.L().Debug("Could not write RDCleanPath error", zap.Error(err))
	}
}

func (s *Server) getUpstream(ctx context.Context) (*loadbalancer.Upstream, error) {
	svc := s.vCache.GetService()
	if svc == nil {
		return nil, errors.Errorf("could not get Service from vcache")
	}

	upstream, err := s.lbManager.GetUpstreamFromConfig(ctx, svc, nil)
	if err != nil {
		return nil, err
	}

	if upstream == nil || upstream.HostPort == "" {
		return nil, errors.Errorf("empty webrdp upstream")
	}

	return upstream, nil
}
