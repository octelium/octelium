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

package jsonschema

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/kaptinlin/jsonschema"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
)

type middleware struct {
	next http.Handler
	sync.RWMutex
	cMap      map[string]*jsonschema.Schema
	compiler  *jsonschema.Compiler
	celEngine *celengine.CELEngine
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
}

func New(ctx context.Context, next http.Handler, celEngine *celengine.CELEngine, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) (http.Handler, error) {
	return &middleware{
		next:      next,
		phase:     phase,
		celEngine: celEngine,
		cMap:      make(map[string]*jsonschema.Schema),
		compiler:  jsonschema.NewCompiler(),
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	ctx := req.Context()

	reqCtx := middlewares.GetCtxRequestContext(ctx)
	cfg := reqCtx.ServiceConfig

	if reqCtx.Body == nil ||
		cfg == nil || cfg.GetHttp() == nil || len(cfg.GetHttp().Plugins) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	if reqCtx.BodyJSONMap == nil {
		bodyMap := make(map[string]any)
		if err := json.Unmarshal(reqCtx.Body, &bodyMap); err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		reqCtx.BodyJSONMap = bodyMap
	}

	for _, plugin := range cfg.GetHttp().Plugins {
		switch plugin.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema:

			if !commonplugin.ShouldEnforcePlugin(ctx, &commonplugin.ShouldEnforcePluginOpts{
				Plugin:    plugin,
				CELEngine: m.celEngine,
				Phase:     m.phase,
			}) {
				continue
			}

			jsonSchemaC := plugin.GetJsonSchema()

			schema := m.getSchema(jsonSchemaC.GetInline())

			res := schema.Validate(reqCtx.BodyJSONMap)
			if res == nil || res.IsValid() {
				continue
			}

			body := jsonSchemaC.Body

			for k, v := range jsonSchemaC.Headers {
				rw.Header().Set(k, v)
			}
			rw.Header().Set("Server", "octelium")

			if jsonSchemaC.StatusCode >= 200 && jsonSchemaC.StatusCode < 600 {
				rw.WriteHeader(int(jsonSchemaC.StatusCode))
			} else {
				rw.WriteHeader(http.StatusBadRequest)
			}

			if body != nil {
				switch body.Type.(type) {
				case *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body_Inline:
					rw.Write([]byte(body.GetInline()))
				case *corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body_InlineBytes:
					rw.Write(body.GetInlineBytes())
				}
			}

			return
		default:
			continue
		}
	}

	m.next.ServeHTTP(rw, req)
}

func (m *middleware) getSchema(arg string) *jsonschema.Schema {
	m.RLock()
	if ret, ok := m.cMap[getKey(arg)]; ok {
		m.RUnlock()
		return ret
	}
	m.RUnlock()

	return m.setAndGetSchema(arg)
}

func (m *middleware) setAndGetSchema(arg string) *jsonschema.Schema {

	schema, err := m.compiler.Compile([]byte(arg))
	if err != nil {
		return nil
	}
	m.Lock()
	m.cMap[getKey(arg)] = schema
	m.Unlock()
	return schema
}

func getKey(schemaContent string) string {
	hsh := sha256.Sum256([]byte(schemaContent))
	return fmt.Sprintf("%x", hsh[:])
}
