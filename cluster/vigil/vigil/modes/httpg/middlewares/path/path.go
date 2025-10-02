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

package path

import (
	"context"
	"net/http"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
)

type middleware struct {
	next      http.Handler
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
	celEngine *celengine.CELEngine
}

func New(ctx context.Context, next http.Handler, celEngine *celengine.CELEngine, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) (http.Handler, error) {
	return &middleware{
		next:      next,
		phase:     phase,
		celEngine: celEngine,
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
		case *corev1.Service_Spec_Config_HTTP_Plugin_Path_:

			if !commonplugin.ShouldEnforcePlugin(ctx, &commonplugin.ShouldEnforcePluginOpts{
				Plugin:    plugin,
				CELEngine: m.celEngine,
				Phase:     m.phase,
			}) {
				continue
			}

			pth := plugin.GetPath()

			if pth.RemovePrefix != "" {
				req.URL.Path = fixPrefixSlash(strings.TrimPrefix(req.URL.Path, pth.RemovePrefix))
				if req.URL.RawPath != "" {
					req.URL.RawPath = fixPrefixSlash(strings.TrimPrefix(req.URL.RawPath, pth.RemovePrefix))
				}

				req.RequestURI = req.URL.RequestURI()
			}

			if pth.AddPrefix != "" {
				req.URL.Path = fixPrefixSlash(pth.AddPrefix + req.URL.Path)
				if req.URL.RawPath != "" {
					req.URL.RawPath = fixPrefixSlash(pth.AddPrefix + req.URL.RawPath)
				}

				req.RequestURI = req.URL.RequestURI()
			}
		default:
			continue
		}
	}

	m.next.ServeHTTP(rw, req)
}

func fixPrefixSlash(arg string) string {
	if arg == "" {
		return arg
	}

	if arg[0] == '/' {
		return arg
	}

	return "/" + arg
}
