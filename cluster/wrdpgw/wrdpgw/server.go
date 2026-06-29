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

package wrdpgw

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/coder/websocket"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
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

type server struct {
	octeliumC octeliumc.ClientInterface
	svcUID    string

	vCache    *vcache.Cache
	lbManager *loadbalancer.LBManager

	httpSrv *http.Server

	mu        sync.Mutex
	isClosed  bool
	secretMan *secretman.SecretManager
}

type templateGlobals struct {
	WebSocketPath string `json:"webSocketPath,omitempty"`
	Destination   string `json:"destination,omitempty"`
	Secretless    bool   `json:"secretless,omitempty"`
}

var indexTmpl = template.Must(template.New("state").Parse(
	`<script nonce="{{ .Nonce }}">window.__OCTELIUM_RDP_WEB__ = {{ .Globals }}</script>`,
))

func newServer(ctx context.Context, octeliumC octeliumc.ClientInterface, svc *corev1.Service) (*server, error) {
	var err error

	ret := &server{
		octeliumC: octeliumC,
		svcUID:    svc.Metadata.Uid,
	}

	ret.vCache, err = vcache.NewCache(ctx)
	if err != nil {
		return nil, err
	}

	ret.vCache.SetService(svc)
	ret.lbManager = loadbalancer.NewLbManager(octeliumC, ret.vCache)

	ret.httpSrv = &http.Server{
		Handler:           ret.getMux(),
		Addr:              vutils.ManagedServiceAddr,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	ret.secretMan, err = secretman.New(ctx, octeliumC, ret.vCache)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *server) run(ctx context.Context) error {
	if err := s.lbManager.Run(ctx); err != nil {
		return err
	}

	if err := s.secretMan.ApplyService(ctx); err != nil {
		return err
	}

	watcher := watchers.NewCoreV1(s.octeliumC)
	if err := watcher.Service(ctx, nil, s.onServiceAdd, s.onServiceUpdate, s.onServiceDelete); err != nil {
		return err
	}

	go func() {
		zap.L().Info("wrdpgw is running",
			zap.String("addr", vutils.ManagedServiceAddr),
			zap.String("webSocketPath", webSocketPath))

		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			zap.L().Error("wrdpgw HTTP server exited", zap.Error(err))
		}
	}()

	return nil
}

func (s *server) close() error {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}
	s.isClosed = true
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := s.httpSrv.Shutdown(ctx); err != nil {
		s.httpSrv.Close()
		return err
	}

	zap.L().Debug("wrdpgw closed")
	return nil
}

func (s *server) onServiceAdd(ctx context.Context, svc *corev1.Service) error {
	if svc.Metadata.Uid != s.svcUID {
		return nil
	}

	s.vCache.SetService(svc)
	return s.secretMan.ApplyService(ctx)
}

func (s *server) onServiceUpdate(ctx context.Context, new, old *corev1.Service) error {
	if new.Metadata.Uid != s.svcUID {
		return nil
	}

	s.vCache.SetService(new)
	return s.secretMan.ApplyService(ctx)
}

func (s *server) onServiceDelete(ctx context.Context, svc *corev1.Service) error {
	return nil
}

func (s *server) getMux() *http.ServeMux {
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

func (s *server) handleStatic() http.Handler {
	subFS, err := fs.Sub(fsWeb, "web")
	if err != nil {
		zap.L().Fatal("Could not initialize wrdpgw static fs", zap.Error(err))
	}

	fileServer := http.FileServer(http.FS(subFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setStaticHeaders(w)
		fileServer.ServeHTTP(w, r)
	})
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.renderIndex(w)
}

func (s *server) renderIndex(w http.ResponseWriter) {
	nonce := utilrand.GetRandomStringCanonical(24)

	blob, err := fs.ReadFile(fsWeb, filepath.Join("web", "index.html"))
	if err != nil {
		zap.L().Error("Could not read wrdpgw index.html", zap.Error(err))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(blob))
	if err != nil {
		zap.L().Error("Could not parse wrdpgw index.html", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	globalsJSON, err := json.Marshal(s.buildTemplateGlobals())
	if err != nil {
		zap.L().Error("Could not marshal wrdpgw globals", zap.Error(err))
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
		zap.L().Error("Could not execute wrdpgw index template", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	head := doc.Find("head").First()
	if head.Length() == 0 {
		zap.L().Error("No <head> in wrdpgw index.html")
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
		zap.L().Error("Could not render wrdpgw index.html", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.setIndexSecurityHeaders(w, nonce)
	w.Write(out.Bytes())
}

func (s *server) buildTemplateGlobals() *templateGlobals {
	ret := &templateGlobals{
		WebSocketPath: webSocketPath,
	}

	cred, err := s.getInjectedCredential(context.Background())
	if err != nil {
		zap.L().Debug("Could not resolve wrdpgw injected credential for globals", zap.Error(err))
		return ret
	}

	ret.Secretless = cred != nil
	return ret
}

func (s *server) setIndexSecurityHeaders(w http.ResponseWriter, nonce string) {
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

func (s *server) setStaticHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
}

func (s *server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode:    websocket.CompressionDisabled,
		InsecureSkipVerify: true,
	})
	if err != nil {
		zap.L().Debug("Could not accept wrdpgw websocket", zap.Error(err))
		return
	}
	defer ws.CloseNow()

	ws.SetReadLimit(maxMessageSize)

	ctx := r.Context()

	msgType, reqBytes, err := ws.Read(ctx)
	if err != nil {
		zap.L().Debug("Could not read wrdpgw RDCleanPath request", zap.Error(err))
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

	cred, err := s.getInjectedCredential(ctx)
	if err != nil {
		zap.L().Debug("Could not resolve wrdpgw injected credential", zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathGeneralError())
		ws.Close(websocket.StatusInternalError, "could not resolve injected credential")
		return
	}

	trust, err := s.getUpstreamTLSTrust()
	if err != nil {
		zap.L().Debug("Could not resolve wrdpgw upstream TLS trust", zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathGeneralError())
		ws.Close(websocket.StatusInternalError, "could not resolve upstream TLS trust")
		return
	}

	upstream, err := s.getUpstream(ctx)
	if err != nil {
		zap.L().Debug("Could not get wrdpgw upstream",
			zap.String("requestedDestination", rdcpReq.Destination),
			zap.Error(err))
		writeRDCleanPathError(ctx, ws, encodeRDCleanPathHTTPError(http.StatusBadGateway))
		ws.Close(websocket.StatusTryAgainLater, "could not resolve upstream")
		return
	}

	handshake, err := performRDPHandshake(ctx, &rdpHandshakeParams{
		upstream:   upstream,
		clientX224: rdcpReq.X224ConnectionPDU,
		cred:       cred,
		trust:      trust,
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

	if err := ws.Write(ctx, websocket.MessageBinary, resp); err != nil {
		zap.L().Debug("Could not write RDCleanPath response", zap.Error(err))
		return
	}

	wsConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer wsConn.Close()

	zap.L().Debug("wrdpgw session started",
		zap.String("remoteAddr", r.RemoteAddr),
		zap.String("requestedDestination", rdcpReq.Destination),
		zap.String("upstream", upstream.HostPort),
		zap.Bool("secretless", cred != nil))

	recvBytes, sentBytes := relay(ctx, wsConn, handshake.TLSConn)

	zap.L().Debug("wrdpgw session ended",
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

func (s *server) getUpstream(ctx context.Context) (*loadbalancer.Upstream, error) {
	svc := s.vCache.GetService()
	if svc == nil {
		return nil, errors.Errorf("could not get Service from vcache")
	}

	authResp := &coctovigilv1.AuthenticateAndAuthorizeResponse{
		RequestContext: &corev1.RequestContext{
			Service: svc,
		},
	}

	upstream, err := s.lbManager.GetUpstream(ctx, authResp)
	if err != nil {
		return nil, err
	}

	if upstream == nil || upstream.HostPort == "" {
		return nil, errors.Errorf("empty wrdpgw upstream")
	}

	return upstream, nil
}

type copyResult struct {
	direction string
	n         int64
	err       error
}

func relay(ctx context.Context, downstream net.Conn, upstream net.Conn) (uint64, uint64) {
	resCh := make(chan copyResult, 2)

	go copyConn(resCh, "downstream_to_upstream", upstream, downstream)
	go copyConn(resCh, "upstream_to_downstream", downstream, upstream)

	first := <-resCh

	if !isExpectedNetErr(first.err) {
		zap.L().Debug("wrdpgw relay copy ended with error",
			zap.String("direction", first.direction),
			zap.Error(first.err))
	}

	downstream.Close()
	upstream.Close()

	var second copyResult
	select {
	case second = <-resCh:
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		zap.L().Debug("Timed out waiting for wrdpgw relay copy shutdown")
	}

	if !isExpectedNetErr(second.err) {
		zap.L().Debug("wrdpgw relay copy ended with error",
			zap.String("direction", second.direction),
			zap.Error(second.err))
	}

	var receivedBytes uint64
	var sentBytes uint64

	for _, res := range []copyResult{first, second} {
		switch res.direction {
		case "downstream_to_upstream":
			receivedBytes = safeUint64(res.n)
		case "upstream_to_downstream":
			sentBytes = safeUint64(res.n)
		}
	}

	return receivedBytes, sentBytes
}

func copyConn(resCh chan<- copyResult, direction string, dst io.Writer, src io.Reader) {
	n, err := io.Copy(dst, src)

	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		if closeErr := cw.CloseWrite(); closeErr != nil && !isExpectedNetErr(closeErr) {
			zap.L().Debug("Could not CloseWrite in wrdpgw relay",
				zap.String("direction", direction),
				zap.Error(closeErr))
		}
	}

	resCh <- copyResult{
		direction: direction,
		n:         n,
		err:       err,
	}
}

func safeUint64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func isExpectedNetErr(err error) bool {
	if err == nil {
		return true
	}

	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}

	if websocket.CloseStatus(err) != -1 {
		return true
	}

	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}

func Run(ctx context.Context) error {
	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	svc, err := octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Uid: os.Getenv("OCTELIUM_SVC_UID"),
	})
	if err != nil {
		return err
	}

	s, err := newServer(ctx, octeliumC, svc)
	if err != nil {
		return err
	}

	if err := s.run(ctx); err != nil {
		return err
	}

	healthcheck.Run(vutils.HealthCheckPortManagedService)

	zap.L().Info("wrdpgw is running", zap.String("svc", svc.Metadata.Name))

	<-ctx.Done()

	return s.close()
}
