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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	defaultCacheMinSimilarity = 0.95
	defaultSemanticCacheSize  = 256 << 10
	maxSemanticCacheSize      = 1 << 20
	semanticCacheSearchLimit  = 4
	semanticCacheTimeout      = 5 * time.Second
	semanticCacheStoreTimeout = 10 * time.Second
)

type semanticCache struct {
	next      http.Handler
	celEngine *celengine.CELEngine
	octeliumC octeliumc.ClientInterface
	embedder  *embedder
	svcUID    string
}

func NewSemanticCache(ctx context.Context, next http.Handler,
	octeliumC octeliumc.ClientInterface, o *SemanticOpts) (http.Handler, error) {
	return &semanticCache{
		next:      next,
		celEngine: o.CELEngine,
		octeliumC: octeliumC,
		embedder:  newEmbedder(o.SecretMan, o.Upstream),
		svcUID:    o.SvcUID,
	}, nil
}

type cacheEntry struct {
	Status      int    `json:"status"`
	ContentType string `json:"contentType,omitempty"`
	Body        []byte `json:"body"`
}

type cacheKey struct {
	collection []byte
	partition  []byte
	id         []byte
	subject    string
}

type cacheLookup struct {
	entry      *cacheEntry
	result     corev1.AccessLog_Entry_Info_LLM_SemanticCache_Result
	similarity float32
	vector     []float32
}

func (m *semanticCache) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsLLM() {
		m.next.ServeHTTP(w, req)
		return
	}

	plugin, cfg, ok := m.resolve(ctx, w, reqCtx)
	if !ok {
		return
	}

	if cfg == nil {
		m.next.ServeHTTP(w, req)
		return
	}

	m.serve(w, req, reqCtx, plugin, cfg)
}

func (m *semanticCache) resolve(ctx context.Context, w http.ResponseWriter,
	reqCtx *middlewares.RequestContext) (*corev1.Service_Spec_Config_LLM_Plugin,
	*corev1.Service_Spec_Config_LLM_Plugin_SemanticCache, bool) {

	for _, plugin := range ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetLLMPlugins() {
		cfg := plugin.GetSemanticCache()
		if cfg == nil {
			continue
		}

		isEnforced, ok := shouldEnforcePlugin(ctx, &enforcePluginOpts{
			w:         w,
			reqCtx:    reqCtx,
			celEngine: m.celEngine,
			plugin:    plugin,
			errCode:   ErrCodeSemanticCache,
		})
		if !ok {
			return nil, nil, false
		}
		if !isEnforced {
			continue
		}

		return plugin, cfg, true
	}

	return nil, nil, true
}

func (m *semanticCache) serve(w http.ResponseWriter, req *http.Request,
	reqCtx *middlewares.RequestContext,
	plugin *corev1.Service_Spec_Config_LLM_Plugin,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache) {

	ctx := req.Context()

	embeddingCfg := resolveEmbedding(reqCtx, cfg.GetEmbedding())
	if !isSemanticRequest(reqCtx) || embeddingCfg == nil {
		setSemanticCacheResult(reqCtx,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_BYPASS, 0)
		m.next.ServeHTTP(w, req)
		return
	}

	key, err := m.getKey(ctx, req, reqCtx, plugin, cfg)
	if err != nil {
		zap.L().Debug("Could not build the LLM SemanticCache key",
			zap.String("plugin", plugin.GetName()), zap.Error(err))
		setSemanticCacheResult(reqCtx,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_BYPASS, 0)
		m.next.ServeHTTP(w, req)
		return
	}

	res := m.lookup(ctx, reqCtx, key, embeddingCfg, cfg)
	setSemanticCacheResult(reqCtx, res.result, res.similarity)

	if res.entry != nil {
		m.writeEntry(w, cfg, res.entry)
		return
	}

	if cfg.GetUseXCacheHeader() {
		w.Header().Set("X-Cache", "MISS")
	}

	crw := &cacheResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		maxSize:        getSemanticCacheMaxSize(cfg),
		isStorable:     len(res.vector) > 0,
	}

	reqCtx.AddOnResponse(func() {
		m.store(ctx, reqCtx, key, res.vector, crw, cfg)
	})

	m.next.ServeHTTP(crw, req)
}

func (m *semanticCache) getKey(ctx context.Context, req *http.Request,
	reqCtx *middlewares.RequestContext,
	plugin *corev1.Service_Spec_Config_LLM_Plugin,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache) (*cacheKey, error) {

	subject, digest, err := getSemanticSubject(reqCtx)
	if err != nil {
		return nil, err
	}

	scope, err := m.getScope(ctx, reqCtx, cfg.GetScope())
	if err != nil {
		return nil, err
	}

	return &cacheKey{
		collection: []byte(fmt.Sprintf("llm:sc:%s:%s", m.svcUID, plugin.GetName())),
		partition: vutils.Sha256Sum([]byte(fmt.Sprintf("%s\x00%d\x00%d\x00%s\x00%s\x00%s\x00%t\x00%x",
			scope, reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(),
			req.Method, req.URL.Path, req.URL.RawQuery,
			reqCtx.LLM.GetStream(), digest))),
		id:      vutils.Sha256Sum([]byte(subject)),
		subject: subject,
	}, nil
}

func (m *semanticCache) getScope(ctx context.Context,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope) (string, error) {

	var userUID, sessionUID string
	if reqCtx.DownstreamInfo != nil {
		if reqCtx.DownstreamInfo.User != nil {
			userUID = reqCtx.DownstreamInfo.User.Metadata.Uid
		}
		if reqCtx.DownstreamInfo.Session != nil {
			sessionUID = reqCtx.DownstreamInfo.Session.Metadata.Uid
		}
	}

	switch cfg.GetType().(type) {
	case *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope_PerSession:
		if sessionUID == "" {
			return "", errors.Errorf("The request carries no Session")
		}
		return fmt.Sprintf("session:%s", sessionUID), nil
	case *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope_Shared:
		return "shared", nil
	case *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope_Eval:
		if reqCtx.ReqCtxMap == nil {
			reqCtx.SetReqCtxMap()
		}
		ret, err := m.celEngine.EvalPolicyString(ctx, cfg.GetEval(), map[string]any{
			"ctx": reqCtx.ReqCtxMap,
		})
		if err != nil {
			return "", err
		}
		if ret == "" {
			return "", errors.Errorf("The cache scope expression returned an empty result")
		}
		return fmt.Sprintf("eval:%s", ret), nil
	default:
		switch {
		case userUID != "":
			return fmt.Sprintf("user:%s", userUID), nil
		case sessionUID != "":
			return fmt.Sprintf("session:%s", sessionUID), nil
		default:
			return "", errors.Errorf("The request carries no User nor Session")
		}
	}
}

func (m *semanticCache) lookup(ctx context.Context,
	reqCtx *middlewares.RequestContext, key *cacheKey,
	embeddingCfg *corev1.Service_Spec_Config_LLM_Embedding,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache) *cacheLookup {

	ret := &cacheLookup{
		result: corev1.AccessLog_Entry_Info_LLM_SemanticCache_MISS,
	}

	getCtx, cancel := context.WithTimeout(ctx, semanticCacheTimeout)
	defer cancel()

	resp, err := m.octeliumC.VectorC().GetVectors(getCtx, &rvectorv1.GetVectorsRequest{
		Collection: key.collection,
		Partition:  key.partition,
		Ids:        [][]byte{key.id},
	})
	if err != nil {
		if grpcerr.IsInternal(err) {
			zap.L().Warn("GetVectors error", zap.Error(err))
		}
		ret.result = corev1.AccessLog_Entry_Info_LLM_SemanticCache_ERROR
		return ret
	}

	if len(resp.Results) > 0 {
		if entry := decodeCacheEntry(resp.Results[0].Data); entry != nil {
			ret.entry = entry
			ret.result = corev1.AccessLog_Entry_Info_LLM_SemanticCache_EXACT_HIT
			ret.similarity = 1
			return ret
		}
	}

	vector, err := m.embedder.embedSubject(ctx, embeddingCfg, reqCtx, key.subject)
	if err != nil {
		zap.L().Warn("Could not embed the LLM request", zap.Error(err))
		ret.result = corev1.AccessLog_Entry_Info_LLM_SemanticCache_ERROR
		return ret
	}
	ret.vector = vector

	searchCtx, searchCancel := context.WithTimeout(ctx, semanticCacheTimeout)
	defer searchCancel()

	searchResp, err := m.octeliumC.VectorC().SearchVectors(searchCtx,
		&rvectorv1.SearchVectorsRequest{
			Collection:    key.collection,
			Partition:     key.partition,
			Vector:        vector,
			MinSimilarity: getSemanticCacheMinSimilarity(cfg),
			Limit:         semanticCacheSearchLimit,
		})
	if err != nil {
		if grpcerr.IsInternal(err) {
			zap.L().Warn("SearchVectors error", zap.Error(err))
		}
		ret.result = corev1.AccessLog_Entry_Info_LLM_SemanticCache_ERROR
		return ret
	}

	for _, result := range searchResp.Results {
		entry := decodeCacheEntry(result.Data)
		if entry == nil {
			continue
		}

		ret.entry = entry
		ret.result = corev1.AccessLog_Entry_Info_LLM_SemanticCache_SEMANTIC_HIT
		ret.similarity = result.Similarity
		return ret
	}

	return ret
}

func (m *semanticCache) store(ctx context.Context,
	reqCtx *middlewares.RequestContext, key *cacheKey, vector []float32,
	crw *cacheResponseWriter, cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache) {

	if len(vector) == 0 || reqCtx.LLMResponseDenied {
		return
	}

	statusCode, contentType, body := crw.stored()
	if len(body) == 0 || hasToolCallResponse(body) ||
		isToolCallFinishReason(reqCtx.LLMResponse.GetFinishReason()) {
		return
	}

	data, err := json.Marshal(&cacheEntry{
		Status:      statusCode,
		ContentType: contentType,
		Body:        body,
	})
	if err != nil {
		return
	}

	storeCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), semanticCacheStoreTimeout)
	defer cancel()

	if _, err := m.octeliumC.VectorC().UpsertVectors(storeCtx,
		&rvectorv1.UpsertVectorsRequest{
			Collection: key.collection,
			Partition:  key.partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     key.id,
					Vector: vector,
					Data:   data,
				},
			},
			Duration: getSemanticCacheTTL(cfg),
		}); err != nil {
		if grpcerr.IsInternal(err) {
			zap.L().Warn("UpsertVectors error", zap.Error(err))
		}
		return
	}

	if reqCtx.LLMSemanticCache != nil {
		reqCtx.LLMSemanticCache.IsStored = true
	}
}

func (m *semanticCache) writeEntry(w http.ResponseWriter,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache, entry *cacheEntry) {

	hdr := w.Header()
	if entry.ContentType != "" {
		hdr.Set("Content-Type", entry.ContentType)
	}
	hdr.Del("Content-Length")

	if cfg.GetUseXCacheHeader() {
		hdr.Set("X-Cache", "HIT")
	}

	statusCode := entry.Status
	if statusCode < 200 || statusCode > 299 {
		statusCode = http.StatusOK
	}

	w.WriteHeader(statusCode)
	w.Write(entry.Body)
}

func setSemanticCacheResult(reqCtx *middlewares.RequestContext,
	result corev1.AccessLog_Entry_Info_LLM_SemanticCache_Result, similarity float32) {
	reqCtx.LLMSemanticCache = &middlewares.LLMSemanticCacheInfo{
		Result:     result,
		Similarity: similarity,
	}
}

func decodeCacheEntry(data []byte) *cacheEntry {
	if len(data) == 0 {
		return nil
	}

	ret := &cacheEntry{}
	if err := json.Unmarshal(data, ret); err != nil {
		return nil
	}

	if len(ret.Body) == 0 {
		return nil
	}

	return ret
}

var toolCallMarkers = [][]byte{
	[]byte(`"tool_calls"`),
	[]byte(`"tool_use"`),
	[]byte(`"toolUse"`),
	[]byte(`"functionCall"`),
	[]byte(`"function_call"`),
}

func hasToolCallResponse(body []byte) bool {
	for _, marker := range toolCallMarkers {
		if bytes.Contains(body, marker) {
			return true
		}
	}
	return false
}

func isToolCallFinishReason(arg string) bool {
	switch arg {
	case "tool_calls", "tool_use", "function_call":
		return true
	default:
		return false
	}
}

func getSemanticCacheMinSimilarity(
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache) float32 {
	if ret := cfg.GetMinSimilarity(); ret > 0 {
		return ret
	}
	return defaultCacheMinSimilarity
}

func getSemanticCacheMaxSize(
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache) int {
	ret := int(cfg.GetMaxSize())
	switch {
	case ret <= 0:
		return defaultSemanticCacheSize
	case ret > maxSemanticCacheSize:
		return maxSemanticCacheSize
	default:
		return ret
	}
}

func getSemanticCacheTTL(
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache) *metav1.Duration {
	if umetav1.ToDuration(cfg.GetTtl()).ToGo() > 0 {
		return cfg.GetTtl()
	}

	return &metav1.Duration{
		Type: &metav1.Duration_Hours{
			Hours: 1,
		},
	}
}
