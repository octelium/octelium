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
	"bytes"
	"context"
	"fmt"
	"net/http"
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
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
)

type middleware struct {
	next      http.Handler
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
	celEngine *celengine.CELEngine
	octeliumC octeliumc.ClientInterface
	svcUID    string
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
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	ctx := req.Context()

	reqCtx := middlewares.GetCtxRequestContext(ctx)
	cfg := reqCtx.ServiceConfig

	if cfg == nil || cfg.GetHttp() == nil || len(cfg.GetHttp().Plugins) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	for _, plugin := range cfg.GetHttp().Plugins {
		switch plugin.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Cache_:
			if !commonplugin.ShouldEnforcePlugin(ctx, &commonplugin.ShouldEnforcePluginOpts{
				Plugin:    plugin,
				CELEngine: m.celEngine,
				Phase:     m.phase,
			}) {
				continue
			}

			cacheC := plugin.GetCache()

			if !cacheC.AllowUnsafeMethods {
				switch req.Method {
				case http.MethodGet, http.MethodHead:
				default:
					continue
				}
			}

			key := m.getKey(ctx, cacheC, reqCtx, req)
			if len(key) == 0 {
				continue
			}

			resp, err := m.octeliumC.CacheC().GetCache(ctx, &rcachev1.GetCacheRequest{
				Key: key,
			})
			if err != nil && !grpcerr.IsNotFound(err) {
				zap.L().Warn("Could not call getCache", zap.Error(err))
				continue
			}

			if err == nil {
				res := &cvigilv1.CacheHTTP{}
				if err := pbutils.Unmarshal(resp.Data, res); err != nil {
					continue
				}

				rwHdr := rw.Header()
				for _, hdr := range res.Headers {
					rwHdr[hdr.Key] = hdr.Values
				}

				if cacheC.UseXCacheHeader {
					rwHdr.Set("X-Cache", "HIT")
				}

				rw.WriteHeader(int(res.Code))
				rw.Write(res.Body)
				return
			}

			crw := newResponseWriter(rw)
			m.next.ServeHTTP(crw, req)

			go m.doCache(crw, key, cacheC)
			return
		default:
			continue
		}
	}

	m.next.ServeHTTP(rw, req)
}

func (m *middleware) getKey(ctx context.Context,
	cacheC *corev1.Service_Spec_Config_HTTP_Plugin_Cache,
	reqCtx *middlewares.RequestContext, req *http.Request) []byte {

	if cacheC.Key != nil {
		switch cacheC.Key.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key_Eval:
			if key, err := m.celEngine.EvalPolicyString(ctx,
				cacheC.Key.GetEval(), reqCtx.ReqCtxMap); err == nil && key != "" {
				return m.doGetKey(key)
			}
		}
	}

	return m.doGetKey(fmt.Sprintf("%s:%s", req.Method, req.URL.RequestURI()))
}

func (m *middleware) doGetKey(arg string) []byte {

	return vutils.Sha256Sum([]byte(fmt.Sprintf("%s:%s", m.svcUID, arg)))
}

func (m *middleware) doCache(rw *responseWriter, key []byte, cacheC *corev1.Service_Spec_Config_HTTP_Plugin_Cache) {
	maxBody := cacheC.MaxSize
	if maxBody == 0 {
		maxBody = 4_000_000
	}

	if uint64(rw.body.Len()) > maxBody {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entry := &cvigilv1.CacheHTTP{
		Code: int64(rw.statusCode),
		Body: rw.body.Bytes(),
	}

	for k, v := range rw.Header() {
		entry.Headers = append(entry.Headers, &cvigilv1.CacheHTTP_Header{
			Key:    k,
			Values: v,
		})
	}

	entryBytes, err := pbutils.Marshal(entry)
	if err != nil {
		zap.L().Warn("Could not marshal cacheHTTP", zap.Error(err))
		return
	}

	duration := cacheC.Ttl
	if duration == nil {
		duration = &metav1.Duration{
			Type: &metav1.Duration_Minutes{
				Minutes: 10,
			},
		}
	}

	_, err = m.octeliumC.CacheC().SetCache(ctx, &rcachev1.SetCacheRequest{
		Key:      key,
		Data:     entryBytes,
		Duration: duration,
	})
	if err != nil {
		zap.L().Warn("Could not setCache", zap.Error(err))
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		body:           new(bytes.Buffer),
		statusCode:     200,
	}
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

/*
func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	return hj.Hijack()
}

func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := p.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
*/
