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

package validation

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"sync"

	"github.com/kaptinlin/jsonschema"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
)

type middleware struct {
	next http.Handler
	sync.RWMutex
	cMap     map[string]*jsonschema.Schema
	compiler *jsonschema.Compiler
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &middleware{
		next:     next,
		cMap:     make(map[string]*jsonschema.Schema),
		compiler: jsonschema.NewCompiler(),
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqCtx := middlewares.GetCtxRequestContext(req.Context())
	cfg := reqCtx.ServiceConfig

	if reqCtx.BodyJSONMap == nil {
		m.next.ServeHTTP(rw, req)
		return
	}

	if cfg == nil || cfg.GetHttp() == nil || cfg.GetHttp().Body == nil ||
		cfg.GetHttp().Body.Validation == nil || cfg.GetHttp().Body.Validation.GetJsonSchema() == nil ||
		cfg.GetHttp().Body.Validation.GetJsonSchema().GetInline() == "" {
		m.next.ServeHTTP(rw, req)
		return
	}

	schema := m.getSchema(cfg.GetHttp().Body.Validation.GetJsonSchema().GetInline())
	if schema == nil {
		m.next.ServeHTTP(rw, req)
		return
	}

	res := schema.Validate(reqCtx.BodyJSONMap)
	if res == nil || !res.IsValid() {
		rw.WriteHeader(http.StatusBadRequest)
		return
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
