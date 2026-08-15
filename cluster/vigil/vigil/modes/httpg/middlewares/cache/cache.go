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

package cache

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/cluster/cvigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"
)

const (
	defaultMaxCacheBodySize  = 4 * 1024 * 1024
	absoluteMaxCacheBodySize = 32 * 1024 * 1024
	maxCachedHeaderBytes     = 64 * 1024
	maxCachedHeaderCount     = 256
	maxCachedEntrySize       = absoluteMaxCacheBodySize + maxCachedHeaderBytes + 64*1024
	cacheOperationTimeout    = 2 * time.Second

	maxFillWaitDuration = 5 * time.Second
)

type middleware struct {
	next      http.Handler
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
	celEngine *celengine.CELEngine
	octeliumC octeliumc.ClientInterface
	svcUID    string

	fills     fillGroup
	cfgHasher serviceConfigHasher
}

func New(ctx context.Context,
	next http.Handler, celEngine *celengine.CELEngine,
	octeliumC octeliumc.ClientInterface,
	svcUID string,
	phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) (http.Handler, error) {
	return &middleware{
		next:      next,
		phase:     phase,
		celEngine: celEngine,
		octeliumC: octeliumC,
		svcUID:    svcUID,
		fills: fillGroup{
			calls: make(map[string]*fillCall),
		},
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)
	if reqCtx == nil {
		m.next.ServeHTTP(rw, req)
		return
	}

	cfg := reqCtx.ServiceConfig

	plugins := ucorev1.ToServiceConfig(cfg).GetHTTPPlugins()
	if len(plugins) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	for _, plugin := range plugins {
		cacheC := plugin.GetCache()
		if cacheC == nil {
			continue
		}

		if !commonplugin.ShouldEnforcePlugin(ctx, &commonplugin.ShouldEnforcePluginOpts{
			Plugin:    plugin,
			CELEngine: m.celEngine,
			Phase:     m.phase,
		}) {
			continue
		}

		if !m.canUseCacheInPhase(reqCtx) || isStreamingRequest(req, reqCtx) {
			m.next.ServeHTTP(rw, req)
			return
		}

		if !cacheC.AllowUnsafeMethods {
			switch req.Method {
			case http.MethodGet, http.MethodHead:
			default:
				m.next.ServeHTTP(rw, req)
				return
			}
		}

		key, isCustomKey := m.getKey(ctx, cacheC, reqCtx, req)
		if len(key) == 0 {
			m.next.ServeHTTP(rw, req)
			return
		}

		if !requestAllowsCache(req, isCustomKey, m.phase) {
			m.next.ServeHTTP(rw, req)
			return
		}

		if m.serveCachedResponse(ctx, rw, req, key, cacheC) {
			return
		}

		release, isLeader, err := m.fills.acquire(ctx, string(key))
		if err != nil {
			m.next.ServeHTTP(rw, req)
			return
		}

		if !isLeader {
			if m.serveCachedResponse(ctx, rw, req, key, cacheC) {
				return
			}

			if cacheC.UseXCacheHeader {
				rw.Header().Set("X-Cache", "MISS")
			}

			m.next.ServeHTTP(rw, req)
			return
		}
		defer release()

		if m.serveCachedResponse(ctx, rw, req, key, cacheC) {
			return
		}

		if cacheC.UseXCacheHeader {
			rw.Header().Set("X-Cache", "MISS")
		}

		crw := newResponseWriter(rw, getMaxCacheBodySize(cacheC))
		m.next.ServeHTTP(crw, req)
		crw.finalize()

		if err := m.cacheResponse(req, key, crw, cacheC); err != nil {
			zap.L().Warn("Could not cache HTTP response", zap.Error(err))
		}
		return
	}

	m.next.ServeHTTP(rw, req)
}

func (m *middleware) canUseCacheInPhase(reqCtx *middlewares.RequestContext) bool {
	if m.phase != corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH {
		return true
	}

	if reqCtx == nil || reqCtx.Service == nil || !reqCtx.Service.Spec.IsAnonymous {
		return false
	}

	authz := reqCtx.Service.Spec.Authorization
	return authz == nil || !authz.EnableAnonymous
}

func (m *middleware) getKey(ctx context.Context,
	cacheC *corev1.Service_Spec_Config_HTTP_Plugin_Cache,
	reqCtx *middlewares.RequestContext,
	req *http.Request) ([]byte, bool) {
	if cacheC.Key != nil {
		switch cacheC.Key.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key_Eval:
			inputMap := reqCtx.ReqCtxMap
			if inputMap == nil {
				inputMap = map[string]any{}
			}

			key, err := m.celEngine.EvalPolicyString(ctx,
				cacheC.Key.GetEval(), inputMap)
			if err != nil {
				zap.L().Warn("Could not evaluate HTTP cache key", zap.Error(err))
				return nil, true
			}
			if key == "" {
				return nil, true
			}
			return m.doGetKey("custom:" + key), true
		}
	}

	parts := []string{
		"default",
		req.Method,
		req.Host,
		req.URL.RequestURI(),
	}

	if cfgHash, ok := m.cfgHasher.get(reqCtx.Service, reqCtx.ServiceConfig); ok {
		parts = append(parts, "cfg:"+cfgHash)
	} else {
		return nil, false
	}

	if m.phase == corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH {
		scope, ok := getDefaultPostAuthScope(reqCtx)
		if !ok {
			return nil, false
		}
		parts = append(parts, scope)
	}

	if cacheC.AllowUnsafeMethods {
		switch req.Method {
		case http.MethodGet, http.MethodHead:
		default:
			if len(reqCtx.Body) == 0 && req.ContentLength != 0 {
				return nil, false
			}
			bodyHash := sha256.Sum256(reqCtx.Body)
			parts = append(parts, fmt.Sprintf("body:%x", bodyHash[:]))
		}
	}

	return m.doGetKey(strings.Join(parts, "\x00")), false
}

func getDefaultPostAuthScope(reqCtx *middlewares.RequestContext) (string, bool) {
	if reqCtx == nil {
		return "", false
	}

	if !reqCtx.IsAuthenticated {
		return "scope:anonymous", true
	}

	if reqCtx.DownstreamInfo != nil {
		if reqCtx.DownstreamInfo.Session != nil &&
			reqCtx.DownstreamInfo.Session.Metadata != nil &&
			reqCtx.DownstreamInfo.Session.Metadata.Uid != "" {
			return "scope:session:" + reqCtx.DownstreamInfo.Session.Metadata.Uid, true
		}

		if reqCtx.DownstreamInfo.User != nil &&
			reqCtx.DownstreamInfo.User.Metadata != nil &&
			reqCtx.DownstreamInfo.User.Metadata.Uid != "" {
			return "scope:user:" + reqCtx.DownstreamInfo.User.Metadata.Uid, true
		}
	}

	return "", false
}

type serviceConfigHasher struct {
	mu   sync.RWMutex
	rv   string
	hash string
}

func (h *serviceConfigHasher) get(svc *corev1.Service,
	cfg *corev1.Service_Spec_Config) (string, bool) {
	if cfg == nil {
		return "none", true
	}

	var rv string
	if svc.GetMetadata() != nil && cfg == svc.GetSpec().GetConfig() {
		rv = svc.GetMetadata().ResourceVersion
	}

	if rv != "" {
		h.mu.RLock()
		if h.rv == rv {
			ret := h.hash
			h.mu.RUnlock()
			return ret, true
		}
		h.mu.RUnlock()
	}

	data, err := pbutils.Marshal(cfg)
	if err != nil {
		return "", false
	}

	sum := sha256.Sum256(data)
	ret := fmt.Sprintf("%x", sum[:])

	if rv != "" {
		h.mu.Lock()
		h.rv = rv
		h.hash = ret
		h.mu.Unlock()
	}

	return ret, true
}

func (m *middleware) doGetKey(arg string) []byte {
	return vutils.Sha256Sum([]byte(fmt.Sprintf("%s:%d:%s",
		m.svcUID, int32(m.phase), arg)))
}

func (m *middleware) serveCachedResponse(ctx context.Context,
	rw http.ResponseWriter,
	req *http.Request,
	key []byte,
	cacheC *corev1.Service_Spec_Config_HTTP_Plugin_Cache) bool {
	cacheCtx, cancel := context.WithTimeout(ctx, cacheOperationTimeout)
	defer cancel()

	resp, err := m.octeliumC.CacheC().GetCache(cacheCtx, &rcachev1.GetCacheRequest{
		Key: key,
	})
	if err != nil {
		if !grpcerr.IsNotFound(err) {
			zap.L().Warn("Could not read HTTP cache", zap.Error(err))
		}
		return false
	}

	if resp == nil || len(resp.Data) == 0 || len(resp.Data) > maxCachedEntrySize {
		return false
	}

	cached := &cvigilv1.CacheHTTP{}
	if err := pbutils.Unmarshal(resp.Data, cached); err != nil {
		zap.L().Warn("Could not unmarshal cached HTTP response", zap.Error(err))
		return false
	}

	if !isCacheableStatus(int(cached.Code)) ||
		len(cached.Body) > absoluteMaxCacheBodySize ||
		len(cached.Headers) > maxCachedHeaderCount ||
		uint64(len(cached.Body)) > getMaxCacheBodySize(cacheC) {
		return false
	}

	hdr := rw.Header()
	for _, cachedHeader := range cached.Headers {
		if cachedHeader == nil || !isReplayableHeader(cachedHeader.Key) {
			continue
		}

		if !httpguts.ValidHeaderFieldName(cachedHeader.Key) {
			continue
		}

		for _, value := range cachedHeader.Values {
			if httpguts.ValidHeaderFieldValue(value) {
				hdr.Add(cachedHeader.Key, value)
			}
		}
	}

	if cacheC.UseXCacheHeader {
		hdr.Set("X-Cache", "HIT")
	}

	if req.Method != http.MethodHead && responseMayHaveBody(int(cached.Code)) {
		hdr.Set("Content-Length", strconv.Itoa(len(cached.Body)))
	} else if req.Method != http.MethodHead {
		hdr.Del("Content-Length")
	}

	rw.WriteHeader(int(cached.Code))
	if req.Method != http.MethodHead && responseMayHaveBody(int(cached.Code)) && len(cached.Body) > 0 {
		if _, err := rw.Write(cached.Body); err != nil {
			zap.L().Debug("Could not write cached HTTP response", zap.Error(err))
		}
	}

	return true
}

func (m *middleware) cacheResponse(req *http.Request,
	key []byte,
	rw *responseWriter,
	cacheC *corev1.Service_Spec_Config_HTTP_Plugin_Cache) error {
	if rw == nil || rw.overflow || rw.hijacked || rw.flushed {
		return nil
	}

	if err := req.Context().Err(); err != nil {
		return nil
	}

	if !rw.isBodyComplete(req) {
		return nil
	}

	if !isCacheableStatus(rw.statusCode) || !responseAllowsCache(rw.headers) {
		return nil
	}

	headers, ok := getCacheableHeaders(rw.headers)
	if !ok {
		return nil
	}

	body := append([]byte(nil), rw.body.Bytes()...)
	entry := &cvigilv1.CacheHTTP{
		Code: int64(rw.statusCode),
		Body: body,
	}

	for key, values := range headers {
		entry.Headers = append(entry.Headers, &cvigilv1.CacheHTTP_Header{
			Key:    key,
			Values: append([]string(nil), values...),
		})
	}

	entryBytes, err := pbutils.Marshal(entry)
	if err != nil {
		return err
	}
	if len(entryBytes) > maxCachedEntrySize {
		return nil
	}

	duration := getCacheDuration(cacheC, rw.headers)

	ctx, cancel := context.WithTimeout(context.Background(), cacheOperationTimeout)
	defer cancel()

	_, err = m.octeliumC.CacheC().SetCache(ctx, &rcachev1.SetCacheRequest{
		Key:      key,
		Data:     entryBytes,
		Duration: duration,
	})
	return err
}

func getCacheDuration(cacheC *corev1.Service_Spec_Config_HTTP_Plugin_Cache,
	headers http.Header) *metav1.Duration {
	duration := cacheC.Ttl
	if duration == nil {
		duration = &metav1.Duration{
			Type: &metav1.Duration_Minutes{
				Minutes: 10,
			},
		}
	}

	maxAge, ok := getResponseMaxAgeSeconds(headers)
	if !ok {
		return duration
	}

	if maxAge < uint32(umetav1ToSeconds(duration)) {
		return &metav1.Duration{
			Type: &metav1.Duration_Seconds{
				Seconds: maxAge,
			},
		}
	}

	return duration
}

func umetav1ToSeconds(d *metav1.Duration) int64 {
	if d == nil {
		return 1<<62 - 1
	}

	return umetav1.ToDuration(d).ToSeconds()
}

func getResponseMaxAgeSeconds(headers http.Header) (uint32, bool) {
	if headers == nil {
		return 0, false
	}

	var ret uint32
	var found bool

	for _, value := range headers.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			name, arg, hasArg := strings.Cut(
				strings.ToLower(strings.TrimSpace(directive)), "=")
			if !hasArg {
				continue
			}

			seconds, err := strconv.ParseUint(strings.Trim(arg, `"`), 10, 32)
			if err != nil {
				continue
			}

			switch name {
			case "s-maxage":
				return uint32(seconds), true
			case "max-age":
				if !found || uint32(seconds) < ret {
					ret = uint32(seconds)
					found = true
				}
			}
		}
	}

	return ret, found
}

func getMaxCacheBodySize(cacheC *corev1.Service_Spec_Config_HTTP_Plugin_Cache) uint64 {
	if cacheC == nil || cacheC.MaxSize == 0 {
		return defaultMaxCacheBodySize
	}
	if cacheC.MaxSize > absoluteMaxCacheBodySize {
		return absoluteMaxCacheBodySize
	}
	return cacheC.MaxSize
}

func requestAllowsCache(req *http.Request,
	isCustomKey bool,
	phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) bool {
	if req == nil {
		return false
	}

	if req.Header.Get("Range") != "" || req.Header.Get("If-Range") != "" {
		return false
	}

	if hasNoCacheDirective(req.Header.Values("Cache-Control")) ||
		strings.EqualFold(strings.TrimSpace(req.Header.Get("Pragma")), "no-cache") {
		return false
	}

	if phase == corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH && !isCustomKey {
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
			return false
		}
	}

	if !isCustomKey && req.Header.Get("Origin") != "" {
		return false
	}

	return true
}

func responseAllowsCache(headers http.Header) bool {
	if headers == nil {
		return true
	}

	if headers.Get("Set-Cookie") != "" ||
		headers.Get("Set-Cookie2") != "" ||
		headers.Get("Content-Range") != "" {
		return false
	}

	if headers.Get("Trailer") != "" {
		return false
	}

	if hasNoCacheDirective(headers.Values("Cache-Control")) {
		return false
	}

	if strings.TrimSpace(headers.Get("Vary")) != "" {
		return false
	}

	return true
}

func hasNoCacheDirective(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			name, arg, hasArg := strings.Cut(
				strings.ToLower(strings.TrimSpace(directive)), "=")

			switch name {
			case "no-store", "no-cache", "private":
				return true
			case "max-age", "s-maxage":
				if hasArg && strings.Trim(arg, `"`) == "0" {
					return true
				}
			}
		}
	}
	return false
}

func isCacheableStatus(code int) bool {
	return code >= 200 && code < 300 && code != http.StatusPartialContent
}

func responseMayHaveBody(code int) bool {
	return code != http.StatusNoContent && code != http.StatusNotModified
}

func getCacheableHeaders(headers http.Header) (http.Header, bool) {
	ret := make(http.Header)
	var total int
	var count int

	for key, values := range headers {
		if !isReplayableHeader(key) || !httpguts.ValidHeaderFieldName(key) {
			continue
		}

		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				continue
			}

			count++
			if count > maxCachedHeaderCount {
				return nil, false
			}

			total += len(key) + len(value)
			if total > maxCachedHeaderBytes {
				return nil, false
			}
			ret.Add(key, value)
		}
	}

	return ret, true
}

func isReplayableHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Age",
		"Connection",
		"Date",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Set-Cookie",
		"Set-Cookie2",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"X-Cache":
		return false
	default:
		return true
	}
}

func isStreamingRequest(req *http.Request, reqCtx *middlewares.RequestContext) bool {
	if req == nil {
		return false
	}

	if httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		return true
	}
	if strings.EqualFold(req.Header.Get("X-Accel-Buffering"), "no") {
		return true
	}
	if strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream") {
		return true
	}
	if strings.HasPrefix(strings.ToLower(req.Header.Get("Content-Type")), "application/grpc") {
		return true
	}

	if reqCtx == nil || reqCtx.Service == nil {
		return false
	}

	if ucorev1.ToService(reqCtx.Service).IsGRPC() {
		return true
	}

	if !ucorev1.ToService(reqCtx.Service).IsKubernetes() {
		return false
	}

	path := req.URL.Path
	if strings.HasSuffix(path, "/exec") ||
		strings.HasSuffix(path, "/attach") ||
		strings.HasSuffix(path, "/log") ||
		strings.HasSuffix(path, "/portforward") {
		return true
	}

	query := req.URL.Query()
	return isTruthy(query.Get("follow")) || isTruthy(query.Get("watch"))
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true":
		return true
	default:
		return false
	}
}

type responseWriter struct {
	http.ResponseWriter

	maxBody uint64
	body    bytes.Buffer
	headers http.Header

	statusCode  int
	wroteHeader bool
	overflow    bool
	hijacked    bool
	flushed     bool
}

func newResponseWriter(w http.ResponseWriter, maxBody uint64) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		maxBody:        maxBody,
		statusCode:     http.StatusOK,
	}
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if statusCode >= 100 && statusCode < 200 {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}
	if w.wroteHeader {
		return
	}

	w.captureHeaders()
	w.statusCode = statusCode
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	n, err := w.ResponseWriter.Write(data)
	if n > 0 {
		w.captureBody(data[:n])
	}
	return n, err
}

func (w *responseWriter) captureBody(data []byte) {
	if w.overflow || len(data) == 0 {
		return
	}

	remaining := int64(w.maxBody) - int64(w.body.Len())
	if remaining <= 0 {
		w.overflow = true
		return
	}

	if int64(len(data)) > remaining {
		_, _ = w.body.Write(data[:remaining])
		w.overflow = true
		return
	}

	_, _ = w.body.Write(data)
}

func (w *responseWriter) captureHeaders() {
	if w.headers != nil {
		return
	}
	w.headers = w.ResponseWriter.Header().Clone()
}

func (w *responseWriter) finalize() {
	if !w.wroteHeader {
		w.captureHeaders()
		w.statusCode = http.StatusOK
	}
	if w.headers == nil {
		w.captureHeaders()
	}
}

func (w *responseWriter) isBodyComplete(req *http.Request) bool {
	if req != nil && req.Method == http.MethodHead {
		return w.body.Len() == 0
	}

	if !responseMayHaveBody(w.statusCode) {
		return w.body.Len() == 0
	}

	declared, ok := w.declaredContentLength()
	if !ok {
		return true
	}

	return declared == int64(w.body.Len())
}

func (w *responseWriter) declaredContentLength() (int64, bool) {
	if w.headers == nil {
		return 0, false
	}

	value := strings.TrimSpace(w.headers.Get("Content-Length"))
	if value == "" {
		return 0, false
	}

	ret, err := strconv.ParseInt(value, 10, 64)
	if err != nil || ret < 0 {
		return 0, false
	}

	return ret, true
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}
	w.hijacked = true
	return hijacker.Hijack()
}

func (w *responseWriter) Flush() {
	w.flushed = true
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type fillGroup struct {
	mu    sync.Mutex
	calls map[string]*fillCall
}

type fillCall struct {
	done chan struct{}
}

func noopRelease() {}

func (g *fillGroup) acquire(ctx context.Context, key string) (func(), bool, error) {
	g.mu.Lock()
	if call, ok := g.calls[key]; ok {
		done := call.done
		g.mu.Unlock()

		timer := time.NewTimer(maxFillWaitDuration)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-done:
			return noopRelease, false, nil
		case <-timer.C:
			return noopRelease, false, nil
		}
	}

	call := &fillCall{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			g.mu.Lock()
			delete(g.calls, key)
			close(call.done)
			g.mu.Unlock()
		})
	}

	return release, true, nil
}
