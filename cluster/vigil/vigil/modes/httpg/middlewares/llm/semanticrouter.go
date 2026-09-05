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

package llm

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	defaultRouteMinSimilarity = 0.6
	maxSemanticRoutes         = 64
	maxSemanticRouteTexts     = 256
	maxSemanticRouteTables    = 16
)

type routeEntry struct {
	name          string
	model         string
	minSimilarity float32
	vector        []float32
}

type semanticRouter struct {
	next      http.Handler
	celEngine *celengine.CELEngine
	embedder  *embedder

	mu     sync.Mutex
	tables map[string][]*routeEntry
	builds map[string]chan struct{}
}

func NewSemanticRouter(ctx context.Context, next http.Handler,
	o *SemanticOpts) (http.Handler, error) {
	return &semanticRouter{
		next:      next,
		celEngine: o.CELEngine,
		embedder:  newEmbedder(o.SecretMan, o.Upstream),
		tables:    make(map[string][]*routeEntry),
		builds:    make(map[string]chan struct{}),
	}, nil
}

func (m *semanticRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsLLM() {
		m.next.ServeHTTP(w, req)
		return
	}

	for _, plugin := range ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetLLMPlugins() {
		cfg := plugin.GetSemanticRouter()
		if cfg == nil {
			continue
		}

		isEnforced, ok := shouldEnforcePlugin(ctx, &enforcePluginOpts{
			w:         w,
			reqCtx:    reqCtx,
			celEngine: m.celEngine,
			plugin:    plugin,
			errCode:   ErrCodeSemanticRouter,
		})
		if !ok {
			return
		}
		if !isEnforced {
			continue
		}

		m.route(ctx, reqCtx, plugin, cfg)
		break
	}

	m.next.ServeHTTP(w, req)
}

func (m *semanticRouter) route(ctx context.Context,
	reqCtx *middlewares.RequestContext,
	plugin *corev1.Service_Spec_Config_LLM_Plugin,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter) {

	ret := &middlewares.LLMSemanticRouterInfo{
		Plugin: plugin.GetName(),
	}
	reqCtx.LLMSemanticRouter = ret

	entry, similarity, result := m.match(ctx, reqCtx, plugin, cfg)
	ret.Result = result

	if entry == nil {
		ret.Model = cfg.GetFallbackModel()
		return
	}

	ret.Route = entry.name
	ret.Similarity = similarity
	ret.Model = entry.model
}

func (m *semanticRouter) match(ctx context.Context,
	reqCtx *middlewares.RequestContext,
	plugin *corev1.Service_Spec_Config_LLM_Plugin,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter) (*routeEntry, float32,
	middlewares.LLMSemanticRouterResult) {

	if !isSemanticRequest(reqCtx) {
		return nil, 0, middlewares.LLMSemanticRouterBypass
	}

	embeddingCfg := resolveEmbedding(reqCtx, cfg.GetEmbedding())
	if embeddingCfg == nil {
		zap.L().Warn("The LLM SemanticRouter Plugin has no embedding configuration",
			zap.String("plugin", plugin.GetName()))
		return nil, 0, middlewares.LLMSemanticRouterError
	}

	identity, err := getSemanticIdentity(reqCtx)
	if err != nil {
		return nil, 0, middlewares.LLMSemanticRouterBypass
	}

	table, err := m.getTable(ctx, reqCtx, plugin, cfg, embeddingCfg)
	if err != nil {
		zap.L().Warn("Could not embed the LLM SemanticRouter Routes",
			zap.String("plugin", plugin.GetName()), zap.Error(err))
		return nil, 0, middlewares.LLMSemanticRouterError
	}

	vector, err := m.embedder.embedSubject(ctx, embeddingCfg, reqCtx, identity.subject)
	if err != nil {
		zap.L().Warn("Could not embed the LLM request",
			zap.String("plugin", plugin.GetName()), zap.Error(err))
		return nil, 0, middlewares.LLMSemanticRouterError
	}

	var ret *routeEntry
	var retSimilarity float32

	for _, entry := range table {
		similarity := cosineSimilarity(vector, entry.vector)
		if similarity < entry.minSimilarity {
			continue
		}
		if ret != nil && similarity <= retSimilarity {
			continue
		}

		ret = entry
		retSimilarity = similarity
	}

	if ret == nil {
		return nil, 0, middlewares.LLMSemanticRouterNoMatch
	}

	return ret, retSimilarity, middlewares.LLMSemanticRouterMatch
}

func (m *semanticRouter) getTable(ctx context.Context,
	reqCtx *middlewares.RequestContext,
	plugin *corev1.Service_Spec_Config_LLM_Plugin,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter,
	embeddingCfg *corev1.Service_Spec_Config_LLM_Embedding) ([]*routeEntry, error) {

	key := getRouteTableKey(plugin, cfg, embeddingCfg)

	for {
		m.mu.Lock()
		if ret, ok := m.tables[key]; ok {
			m.mu.Unlock()
			return ret, nil
		}

		build, ok := m.builds[key]
		if !ok {
			build = make(chan struct{})
			m.builds[key] = build
			m.mu.Unlock()

			ret, err := m.buildTable(ctx, reqCtx, cfg, embeddingCfg)

			m.mu.Lock()
			delete(m.builds, key)
			if err == nil {
				if len(m.tables) >= maxSemanticRouteTables {
					m.tables = make(map[string][]*routeEntry)
				}
				m.tables[key] = ret
			}
			m.mu.Unlock()

			close(build)
			return ret, err
		}
		m.mu.Unlock()

		select {
		case <-build:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (m *semanticRouter) buildTable(ctx context.Context,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter,
	embeddingCfg *corev1.Service_Spec_Config_LLM_Embedding) ([]*routeEntry, error) {

	routes := cfg.GetRoutes()
	if len(routes) == 0 || len(routes) > maxSemanticRoutes {
		return nil, errors.Errorf("Invalid Route count: %d", len(routes))
	}

	minSimilarity := cfg.GetMinSimilarity()
	if minSimilarity <= 0 {
		minSimilarity = defaultRouteMinSimilarity
	}

	var texts []string
	var ret []*routeEntry

	for _, route := range routes {
		if route.GetName() == "" || route.GetModel() == "" {
			return nil, errors.Errorf("The Route name and model must both be set")
		}

		threshold := route.GetMinSimilarity()
		if threshold <= 0 {
			threshold = minSimilarity
		}

		for _, text := range getRouteTexts(route) {
			texts = append(texts, text)
			ret = append(ret, &routeEntry{
				name:          route.GetName(),
				model:         route.GetModel(),
				minSimilarity: threshold,
			})
		}
	}

	if len(texts) == 0 || len(texts) > maxSemanticRouteTexts {
		return nil, errors.Errorf("Invalid Route text count: %d", len(texts))
	}

	for i := 0; i < len(texts); i += maxEmbeddingTexts {
		end := min(i+maxEmbeddingTexts, len(texts))

		vectors, err := m.embedder.embed(ctx, embeddingCfg, reqCtx, texts[i:end])
		if err != nil {
			return nil, err
		}

		for j, vector := range vectors {
			ret[i+j].vector = vector
		}
	}

	return ret, nil
}

func getRouteTexts(
	route *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter_Route) []string {
	var ret []string

	if val := route.GetDescription(); val != "" {
		ret = append(ret, val)
	}

	for _, val := range route.GetExamples() {
		if val != "" {
			ret = append(ret, val)
		}
	}

	return ret
}

func getRouteTableKey(plugin *corev1.Service_Spec_Config_LLM_Plugin,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter,
	embeddingCfg *corev1.Service_Spec_Config_LLM_Embedding) string {

	routesRaw, err := pbutils.Marshal(cfg)
	if err != nil {
		routesRaw = nil
	}

	embeddingRaw, err := pbutils.Marshal(embeddingCfg)
	if err != nil {
		embeddingRaw = nil
	}

	return vutils.Sha256SumHex([]byte(fmt.Sprintf("%s:%s:%s",
		plugin.GetName(), string(routesRaw), string(embeddingRaw))))
}
