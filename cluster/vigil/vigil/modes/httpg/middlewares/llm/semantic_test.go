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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

type fakeEmbeddings struct {
	srv *httptest.Server

	mu      sync.Mutex
	vectors map[string][]float32
	count   int
	err     bool
}

func newFakeEmbeddings(vectors map[string][]float32) *fakeEmbeddings {
	ret := &fakeEmbeddings{
		vectors: vectors,
	}
	ret.srv = httptest.NewServer(http.HandlerFunc(ret.serve))
	return ret
}

func (f *fakeEmbeddings) serve(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	f.count++
	isErr := f.err
	f.mu.Unlock()

	if isErr {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	var in struct {
		Input []string `json:"input"`
	}
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	type entry struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	}
	out := struct {
		Data []entry `json:"data"`
	}{}

	for i, text := range in.Input {
		out.Data = append(out.Data, entry{
			Index:     i,
			Embedding: f.vector(text),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&out)
}

func (f *fakeEmbeddings) vector(text string) []float32 {
	f.mu.Lock()
	defer f.mu.Unlock()

	if ret, ok := f.vectors[text]; ok {
		return ret
	}

	sum := sha256.Sum256([]byte(text))
	return []float32{
		float32(sum[0]) + 1, float32(sum[1]), float32(sum[2]), float32(sum[3]),
	}
}

func (f *fakeEmbeddings) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

func (f *fakeEmbeddings) setErr(arg bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = arg
}

func (f *fakeEmbeddings) upstreamFn() UpstreamFn {
	return func(ctx context.Context) (*url.URL, error) {
		return url.Parse(f.srv.URL)
	}
}

func (f *fakeEmbeddings) config() *corev1.Service_Spec_Config_LLM_Embedding {
	return &corev1.Service_Spec_Config_LLM_Embedding{
		Model: "text-embedding-3-small",
		Source: &corev1.Service_Spec_Config_LLM_Embedding_Source{
			Type: &corev1.Service_Spec_Config_LLM_Embedding_Source_CurrentUpstream{
				CurrentUpstream: true,
			},
		},
	}
}

type fakeVectorEntry struct {
	id     []byte
	vector []float32
	data   []byte
}

type fakeVector struct {
	rvectorv1.MainServiceClient

	mu      sync.Mutex
	entries map[string][]*fakeVectorEntry

	upsertCount int
	getErr      error
	searchErr   error
}

func newFakeVector() *fakeVector {
	return &fakeVector{
		entries: make(map[string][]*fakeVectorEntry),
	}
}

func (c *fakeVector) key(collection, partition []byte) string {
	return fmt.Sprintf("%x:%x", collection, partition)
}

func (c *fakeVector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	var ret int
	for _, entries := range c.entries {
		ret = ret + len(entries)
	}
	return ret
}

func (c *fakeVector) UpsertVectors(ctx context.Context,
	req *rvectorv1.UpsertVectorsRequest,
	opts ...grpc.CallOption) (*rvectorv1.UpsertVectorsResponse, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	c.upsertCount++
	key := c.key(req.Collection, req.Partition)

	for _, entry := range req.Entries {
		cur := &fakeVectorEntry{
			id:     entry.Id,
			vector: entry.Vector,
			data:   entry.Data,
		}

		var isSet bool
		for i, existing := range c.entries[key] {
			if string(existing.id) == string(entry.Id) {
				c.entries[key][i] = cur
				isSet = true
				break
			}
		}
		if !isSet {
			c.entries[key] = append(c.entries[key], cur)
		}
	}

	return &rvectorv1.UpsertVectorsResponse{}, nil
}

func (c *fakeVector) GetVectors(ctx context.Context,
	req *rvectorv1.GetVectorsRequest,
	opts ...grpc.CallOption) (*rvectorv1.GetVectorsResponse, error) {

	if c.getErr != nil {
		return nil, c.getErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ret := &rvectorv1.GetVectorsResponse{}
	for _, entry := range c.entries[c.key(req.Collection, req.Partition)] {
		for _, id := range req.Ids {
			if string(id) != string(entry.id) {
				continue
			}
			ret.Results = append(ret.Results, &rvectorv1.Result{
				Id:   entry.id,
				Data: entry.data,
			})
		}
	}

	return ret, nil
}

func (c *fakeVector) SearchVectors(ctx context.Context,
	req *rvectorv1.SearchVectorsRequest,
	opts ...grpc.CallOption) (*rvectorv1.SearchVectorsResponse, error) {

	if c.searchErr != nil {
		return nil, c.searchErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ret := &rvectorv1.SearchVectorsResponse{}
	for _, entry := range c.entries[c.key(req.Collection, req.Partition)] {
		similarity := cosineSimilarity(req.Vector, entry.vector)
		if similarity < req.MinSimilarity {
			continue
		}

		ret.Results = append(ret.Results, &rvectorv1.Result{
			Id:         entry.id,
			Data:       entry.data,
			Similarity: similarity,
		})
	}

	return ret, nil
}

func newDownstream(userUID string) *corev1.RequestContext {
	return &corev1.RequestContext{
		User: &corev1.User{
			Metadata: &metav1.Metadata{
				Uid: userUID,
			},
		},
		Session: &corev1.Session{
			Metadata: &metav1.Metadata{
				Uid: "5c2b1e40-0000-0000-0000-000000000001",
			},
		},
	}
}

func upstreamCompletion(text string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-1",
			"model":   "gpt-4o",
			"choices": []map[string]any{{"message": map[string]any{"content": text}}},
			"usage":   map[string]any{"total_tokens": 12},
		})
	}
}

func newTestIdentity(t *testing.T, body string) *semanticIdentity {
	d, err := newDoc(corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS, []byte(body))
	assert.Nil(t, err)

	ret, err := d.getSemanticIdentity()
	assert.Nil(t, err, "%+v", err)
	return ret
}

func TestSemanticIdentity(t *testing.T) {
	{
		identity := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"system","content":"Be terse"},`+
			`{"role":"user","content":"What is Octelium?"}]}`)
		assert.Equal(t, "What is Octelium?", identity.subject)
		assert.False(t, identity.isOpaque)
		assert.True(t, identity.isCacheable())

		other := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"system","content":"Be terse"},`+
			`{"role":"user","content":"Tell me about Octelium"}]}`)
		assert.Equal(t, "Tell me about Octelium", other.subject)
		assert.Equal(t, identity.digest, other.digest)
	}

	{
		identity := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"system","content":"Be terse"},`+
			`{"role":"user","content":"Hi"}]}`)
		other := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"system","content":"Be verbose"},`+
			`{"role":"user","content":"Hi"}]}`)
		assert.NotEqual(t, identity.digest, other.digest)
	}

	{
		identity := newTestIdentity(t, `{"model":"gpt-4o","temperature":0.1,`+
			`"messages":[{"role":"user","content":"Hi"}]}`)
		other := newTestIdentity(t, `{"model":"gpt-4o","temperature":0.9,`+
			`"messages":[{"role":"user","content":"Hi"}]}`)
		assert.NotEqual(t, identity.digest, other.digest)
	}

	{
		identity := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"user","content":"First"},`+
			`{"role":"assistant","content":"Second"},`+
			`{"role":"user","content":"Third"}]}`)
		other := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"user","content":"First"},`+
			`{"role":"assistant","content":"Other"},`+
			`{"role":"user","content":"Third"}]}`)
		assert.NotEqual(t, identity.digest, other.digest)
	}

	{
		d, err := newDoc(corev1.Service_Spec_Config_LLM_OPENAI,
			corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
			[]byte(`{"model":"gpt-4o","messages":[{"role":"assistant","content":"Hi"}]}`))
		assert.Nil(t, err)

		_, err = d.getSemanticIdentity()
		assert.NotNil(t, err)
	}
}

func TestSemanticIdentityIsCacheable(t *testing.T) {
	{
		identity := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"user","content":[`+
			`{"type":"text","text":"summarize this"},`+
			`{"type":"tool_result","tool_use_id":"1","content":"DATA-A"}]}]}`)
		assert.Equal(t, "summarize this", identity.subject)
		assert.True(t, identity.isOpaque)
		assert.False(t, identity.isCacheable())

		other := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"user","content":[`+
			`{"type":"text","text":"summarize this"},`+
			`{"type":"tool_result","tool_use_id":"1","content":"DATA-B"}]}]}`)
		assert.Equal(t, identity.digest, other.digest)
		assert.True(t, other.isOpaque)
	}

	{
		identity := newTestIdentity(t, `{"model":"gpt-4o","messages":[`+
			`{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
		assert.False(t, identity.isOpaque)
		assert.True(t, identity.isCacheable())
	}

	{
		long := strings.Repeat("a", maxEmbeddingTextBytes+1)
		identity := newTestIdentity(t, newChatBody(long))
		assert.Equal(t, long, identity.subject)
		assert.False(t, identity.isCacheable())

		other := newTestIdentity(t, newChatBody(long+"b"))
		assert.NotEqual(t, identity.subject, other.subject)
	}
}

func TestCosineSimilarity(t *testing.T) {
	assert.InDelta(t, 1, cosineSimilarity([]float32{1, 1}, []float32{2, 2}), 0.0001)
	assert.InDelta(t, 0, cosineSimilarity([]float32{1, 0}, []float32{0, 1}), 0.0001)
	assert.Zero(t, cosineSimilarity([]float32{1, 0}, []float32{-1, 0}))
	assert.Zero(t, cosineSimilarity([]float32{1, 0}, []float32{1, 0, 0}))
	assert.Zero(t, cosineSimilarity(nil, nil))
	assert.Zero(t, cosineSimilarity([]float32{0, 0}, []float32{1, 1}))
}

func TestTruncateText(t *testing.T) {
	assert.Equal(t, "abc", truncateText("abc", 8))
	assert.Equal(t, "abc", truncateText("abcdef", 3))
	assert.Equal(t, "ab", truncateText("abé", 3))
}

func newSemanticRouterPlugin(
	embedding *fakeEmbeddings) *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter {
	return &corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter{
		Routes: []*corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter_Route{
			{
				Name:     "code",
				Examples: []string{"Why does this Go program deadlock?"},
				Model:    "gpt-5",
			},
			{
				Name:     "simple",
				Examples: []string{"What is the capital of Egypt?"},
				Model:    "gpt-5-nano",
			},
		},
		FallbackModel: "gpt-5-mini",
	}
}

func TestSemanticRouter(t *testing.T) {
	embedding := newFakeEmbeddings(map[string][]float32{
		"Why does this Go program deadlock?": {1, 0, 0, 0},
		"What is the capital of Egypt?":      {0, 1, 0, 0},
		"Why is my Go service hanging?":      {0.99, 0.1, 0, 0},
		"What is the capital of France?":     {0.1, 0.99, 0, 0},
		"Draw me a picture":                  {0, 0, 1, 0},
	})

	{
		res := servePlugins(t, &pluginOpts{
			body:      newChatBody("Why is my Go service hanging?"),
			embedding: embedding,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("router", newSemanticRouterPlugin(embedding)),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "gpt-5", res.upstream["model"])
		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_SemanticRouter_MATCH,
			res.reqCtx.LLMSemanticRouter.Result)
		assert.Equal(t, "code", res.reqCtx.LLMSemanticRouter.Route)
		assert.Equal(t, "gpt-5", res.reqCtx.LLMSemanticRouter.Model)
		assert.Equal(t, "router", res.reqCtx.LLMSemanticRouter.Plugin)
		assert.True(t, res.reqCtx.LLMSemanticRouter.Similarity > 0.9)
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:      newChatBody("What is the capital of France?"),
			embedding: embedding,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("router", newSemanticRouterPlugin(embedding)),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.Equal(t, "gpt-5-nano", res.upstream["model"])
		assert.Equal(t, "simple", res.reqCtx.LLMSemanticRouter.Route)
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:      newChatBody("Draw me a picture"),
			embedding: embedding,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("router", newSemanticRouterPlugin(embedding)),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.Equal(t, "gpt-5-mini", res.upstream["model"])
		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_SemanticRouter_NO_MATCH,
			res.reqCtx.LLMSemanticRouter.Result)
		assert.Empty(t, res.reqCtx.LLMSemanticRouter.Route)
		assert.Equal(t, "gpt-5-mini", res.reqCtx.LLMSemanticRouter.Model)
	}
}

func TestSemanticRouterModelPrecedence(t *testing.T) {
	embedding := newFakeEmbeddings(map[string][]float32{
		"Why does this Go program deadlock?": {1, 0, 0, 0},
		"What is the capital of Egypt?":      {0, 1, 0, 0},
		"Why is my Go service hanging?":      {0.99, 0.1, 0, 0},
	})

	{
		res := servePlugins(t, &pluginOpts{
			body:      newChatBody("Why is my Go service hanging?"),
			embedding: embedding,
			model: &corev1.Service_Spec_Config_LLM_Model{
				Type: &corev1.Service_Spec_Config_LLM_Model_Value{Value: "gpt-4o-mini"},
			},
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("router", newSemanticRouterPlugin(embedding)),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.Equal(t, "gpt-5", res.upstream["model"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:      newChatBody("Why is my Go service hanging?"),
			embedding: embedding,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("router", newSemanticRouterPlugin(embedding)),
				newPlugin("explicit", &corev1.Service_Spec_Config_LLM_Model{
					Type: &corev1.Service_Spec_Config_LLM_Model_Value{Value: "o3"},
				}),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.Equal(t, "o3", res.upstream["model"])
		assert.Equal(t, "code", res.reqCtx.LLMSemanticRouter.Route)
	}
}

func TestSemanticRouterMinSimilarity(t *testing.T) {
	embedding := newFakeEmbeddings(map[string][]float32{
		"Why does this Go program deadlock?": {1, 0, 0, 0},
		"What is the capital of Egypt?":      {0, 1, 0, 0},
		"Why is my Go service hanging?":      {0.99, 0.1, 0, 0},
	})

	cfg := newSemanticRouterPlugin(embedding)
	cfg.Routes[0].MinSimilarity = 0.999

	res := servePlugins(t, &pluginOpts{
		body:      newChatBody("Why is my Go service hanging?"),
		embedding: embedding,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("router", cfg),
		},
		downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
	})

	assert.Equal(t, "gpt-5-mini", res.upstream["model"])
	assert.Empty(t, res.reqCtx.LLMSemanticRouter.Route)
}

func TestSemanticRouterEmbeddingError(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	embedding.setErr(true)

	res := servePlugins(t, &pluginOpts{
		body:      newChatBody("Why is my Go service hanging?"),
		embedding: embedding,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("router", newSemanticRouterPlugin(embedding)),
		},
		downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
	})

	assert.True(t, res.isNext)
	assert.Equal(t, "gpt-5-mini", res.upstream["model"])
	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_SemanticRouter_ERROR,
		res.reqCtx.LLMSemanticRouter.Result)
}

func TestSemanticRouterRouteTableIsCached(t *testing.T) {
	embedding := newFakeEmbeddings(map[string][]float32{
		"Why does this Go program deadlock?": {1, 0, 0, 0},
		"What is the capital of Egypt?":      {0, 1, 0, 0},
	})

	router, err := NewSemanticRouter(context.Background(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		&SemanticOpts{Upstream: embedding.upstreamFn()})
	assert.Nil(t, err)

	cfg := newSemanticRouterPlugin(embedding)
	plugin := newPlugin("router", cfg)

	reqCtx := &middlewares.RequestContext{
		ServiceConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Llm{
				Llm: &corev1.Service_Spec_Config_LLM{},
			},
		},
	}

	for range 3 {
		table, err := router.(*semanticRouter).getTable(context.Background(),
			reqCtx, plugin, cfg, embedding.config())
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(table))
	}

	assert.Equal(t, 1, embedding.requests())
}

func newSemanticCachePlugin(
	cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache) *corev1.Service_Spec_Config_LLM_Plugin {
	if cfg == nil {
		cfg = &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache{}
	}
	cfg.UseXCacheHeader = true
	return newPlugin("cache", cfg)
}

func TestSemanticCacheExactHit(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	newOpts := func() *pluginOpts {
		return &pluginOpts{
			body:      newChatBody("What is Octelium?"),
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("Octelium is a zero trust platform"),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		}
	}

	{
		res := servePlugins(t, newOpts())

		assert.True(t, res.isNext)
		assert.Equal(t, "MISS", res.header.Get("X-Cache"))
		assert.Contains(t, res.body, "zero trust platform")
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_MISS,
			res.reqCtx.LLMSemanticCache.Result)
		assert.True(t, res.reqCtx.LLMSemanticCache.IsStored)
		assert.Equal(t, 1, vectorC.count())
	}

	{
		res := servePlugins(t, newOpts())

		assert.False(t, res.isNext)
		assert.Equal(t, "HIT", res.header.Get("X-Cache"))
		assert.Equal(t, http.StatusOK, res.code)
		assert.Contains(t, res.body, "zero trust platform")
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_EXACT_HIT,
			res.reqCtx.LLMSemanticCache.Result)
		assert.Zero(t, res.reqCtx.LLMSemanticCache.Similarity)
		assert.Equal(t, "cache", res.reqCtx.LLMSemanticCache.Plugin)
		assert.Equal(t, "application/json", res.header.Get("Content-Type"))
	}

	assert.Equal(t, 1, embedding.requests())
	assert.Equal(t, 1, vectorC.upsertCount)
}

func TestSemanticCacheSemanticHit(t *testing.T) {
	embedding := newFakeEmbeddings(map[string][]float32{
		"What is Octelium?":         {1, 0, 0, 0},
		"Tell me about Octelium":    {0.99, 0.1, 0, 0},
		"What is the weather today": {0, 1, 0, 0},
	})
	vectorC := newFakeVector()

	newOpts := func(content string) *pluginOpts {
		return &pluginOpts{
			body:      newChatBody(content),
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("Octelium is a zero trust platform"),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		}
	}

	servePlugins(t, newOpts("What is Octelium?"))

	{
		res := servePlugins(t, newOpts("Tell me about Octelium"))

		assert.False(t, res.isNext)
		assert.Contains(t, res.body, "zero trust platform")
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_SEMANTIC_HIT,
			res.reqCtx.LLMSemanticCache.Result)
		assert.True(t, res.reqCtx.LLMSemanticCache.Similarity > 0.95)
	}

	{
		res := servePlugins(t, newOpts("What is the weather today"))

		assert.True(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_MISS,
			res.reqCtx.LLMSemanticCache.Result)
	}
}

func TestSemanticCacheScope(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	newOpts := func(userUID string,
		scope *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope) *pluginOpts {
		return &pluginOpts{
			body:      newChatBody("What is Octelium?"),
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("an answer"),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(
					&corev1.Service_Spec_Config_LLM_Plugin_SemanticCache{
						Scope: scope,
					}),
			},
			downstream: newDownstream(userUID),
		}
	}

	servePlugins(t, newOpts("8f1a9b7c-0000-0000-0000-000000000001", nil))

	{
		res := servePlugins(t, newOpts("8f1a9b7c-0000-0000-0000-000000000002", nil))
		assert.True(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_MISS,
			res.reqCtx.LLMSemanticCache.Result)
	}

	shared := &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope{
		Type: &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope_Shared{
			Shared: true,
		},
	}

	servePlugins(t, newOpts("8f1a9b7c-0000-0000-0000-000000000003", shared))

	{
		res := servePlugins(t, newOpts("8f1a9b7c-0000-0000-0000-000000000004", shared))
		assert.False(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_EXACT_HIT,
			res.reqCtx.LLMSemanticCache.Result)
	}
}

func TestSemanticCacheBypass(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	{
		res := servePlugins(t, &pluginOpts{
			path:      "/v1/embeddings",
			body:      `{"model":"text-embedding-3-small","input":"hello"}`,
			embedding: embedding,
			vectorC:   vectorC,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.True(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_BYPASS,
			res.reqCtx.LLMSemanticCache.Result)
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:     newChatBody("What is Octelium?"),
			vectorC:  vectorC,
			upstream: upstreamCompletion("an answer"),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.True(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_BYPASS,
			res.reqCtx.LLMSemanticCache.Result)
	}

	assert.Zero(t, vectorC.count())
}

func TestSemanticCacheNotStored(t *testing.T) {
	embedding := newFakeEmbeddings(nil)

	newOpts := func(vectorC *fakeVector,
		cfg *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache,
		upstream http.HandlerFunc) *pluginOpts {
		return &pluginOpts{
			body:      newChatBody("What is Octelium?"),
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstream,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(cfg),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		}
	}

	{
		vectorC := newFakeVector()
		res := servePlugins(t, newOpts(vectorC, nil,
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"choices":[{"finish_reason":"tool_calls",` +
					`"message":{"tool_calls":[{"id":"1"}]}}]}`))
			}))

		assert.True(t, res.isNext)
		assert.False(t, res.reqCtx.LLMSemanticCache.IsStored)
		assert.Zero(t, vectorC.count())
	}

	{
		vectorC := newFakeVector()
		res := servePlugins(t, newOpts(vectorC,
			&corev1.Service_Spec_Config_LLM_Plugin_SemanticCache{
				MaxSize: 8,
			}, upstreamCompletion("a much longer answer than eight bytes")))

		assert.True(t, res.isNext)
		assert.False(t, res.reqCtx.LLMSemanticCache.IsStored)
		assert.Zero(t, vectorC.count())
	}

	{
		vectorC := newFakeVector()
		res := servePlugins(t, newOpts(vectorC, nil,
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":{"message":"slow down"}}`))
			}))

		assert.True(t, res.isNext)
		assert.False(t, res.reqCtx.LLMSemanticCache.IsStored)
		assert.Zero(t, vectorC.count())
	}

	{
		vectorC := newFakeVector()
		opts := newOpts(vectorC, nil, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant",` +
				`"content":"the key is AKIADEADBEEFDEADBEEF"}}]}`))
		})
		opts.plugins = append(opts.plugins, newGuardrailPlugin("leak",
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_RESPONSE,
			&corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets_{
					Secrets: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets{},
				},
			}))

		res := servePlugins(t, opts)

		assert.Equal(t, http.StatusForbidden, res.code)
		assert.True(t, res.reqCtx.LLMResponseDenied)
		assert.False(t, res.reqCtx.LLMSemanticCache.IsStored)
		assert.Zero(t, vectorC.count())
	}
}

func TestSemanticCacheFailOpen(t *testing.T) {
	embedding := newFakeEmbeddings(nil)

	{
		vectorC := newFakeVector()
		vectorC.getErr = errors.Errorf("the vector store is unavailable")

		res := servePlugins(t, &pluginOpts{
			body:      newChatBody("What is Octelium?"),
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("an answer"),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, http.StatusOK, res.code)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_ERROR,
			res.reqCtx.LLMSemanticCache.Result)
		assert.False(t, res.reqCtx.LLMSemanticCache.IsStored)
	}

	{
		failing := newFakeEmbeddings(nil)
		failing.setErr(true)
		vectorC := newFakeVector()

		res := servePlugins(t, &pluginOpts{
			body:      newChatBody("What is Octelium?"),
			embedding: failing,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("an answer"),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, http.StatusOK, res.code)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_ERROR,
			res.reqCtx.LLMSemanticCache.Result)
		assert.Zero(t, vectorC.count())
	}
}

func TestSemanticCacheKeyIsModelAware(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	newOpts := func(model string) *pluginOpts {
		ret := &pluginOpts{
			body:      newChatBody("What is Octelium?"),
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("an answer"),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		}
		if model != "" {
			ret.model = &corev1.Service_Spec_Config_LLM_Model{
				Type: &corev1.Service_Spec_Config_LLM_Model_Value{Value: model},
			}
		}
		return ret
	}

	servePlugins(t, newOpts(""))

	{
		res := servePlugins(t, newOpts("gpt-5"))
		assert.True(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_MISS,
			res.reqCtx.LLMSemanticCache.Result)
	}

	{
		res := servePlugins(t, newOpts("gpt-5"))
		assert.False(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_EXACT_HIT,
			res.reqCtx.LLMSemanticCache.Result)
	}
}

func TestSemanticIdentityProtocols(t *testing.T) {
	newIdentity := func(t *testing.T, protocol corev1.Service_Spec_Config_LLM_Protocol,
		operation corev1.RequestContext_Request_LLM_Operation, body string) (string, []byte) {

		d, err := newDoc(protocol, operation, []byte(body))
		assert.Nil(t, err)

		ret, err := d.getSemanticIdentity()
		assert.Nil(t, err, "%+v", err)
		return ret.subject, ret.digest
	}

	{
		subject, digest := newIdentity(t, corev1.Service_Spec_Config_LLM_GEMINI,
			corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
			`{"contents":[{"role":"user","parts":[{"text":"What is Octelium?"}]},`+
				`{"role":"model","parts":[{"text":"A platform"}]},`+
				`{"role":"user","parts":[{"text":"Tell me more"}]}]}`)
		assert.Equal(t, "Tell me more", subject)

		_, otherDigest := newIdentity(t, corev1.Service_Spec_Config_LLM_GEMINI,
			corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
			`{"contents":[{"role":"user","parts":[{"text":"What is Octelium?"}]},`+
				`{"role":"model","parts":[{"text":"A platform"}]},`+
				`{"role":"user","parts":[{"text":"Say more"}]}]}`)
		assert.Equal(t, digest, otherDigest)

		_, changedDigest := newIdentity(t, corev1.Service_Spec_Config_LLM_GEMINI,
			corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
			`{"contents":[{"role":"user","parts":[{"text":"What is Octelium?"}]},`+
				`{"role":"model","parts":[{"text":"Another platform"}]},`+
				`{"role":"user","parts":[{"text":"Tell me more"}]}]}`)
		assert.NotEqual(t, digest, changedDigest)
	}

	{
		subject, digest := newIdentity(t, corev1.Service_Spec_Config_LLM_BEDROCK,
			corev1.RequestContext_Request_LLM_CONVERSE,
			`{"system":[{"text":"Be terse"}],"messages":[`+
				`{"role":"user","content":[{"text":"What is Octelium?"}]}]}`)
		assert.Equal(t, "What is Octelium?", subject)

		_, otherDigest := newIdentity(t, corev1.Service_Spec_Config_LLM_BEDROCK,
			corev1.RequestContext_Request_LLM_CONVERSE,
			`{"system":[{"text":"Be verbose"}],"messages":[`+
				`{"role":"user","content":[{"text":"What is Octelium?"}]}]}`)
		assert.NotEqual(t, digest, otherDigest)
	}

	{
		subject, _ := newIdentity(t, corev1.Service_Spec_Config_LLM_ANTHROPIC,
			corev1.RequestContext_Request_LLM_MESSAGES,
			`{"model":"claude-sonnet-4","system":"Be terse","messages":[`+
				`{"role":"user","content":[{"type":"text","text":"What is Octelium?"}]}]}`)
		assert.Equal(t, "What is Octelium?", subject)
	}
}

func TestSemanticCacheContentEncoding(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	newOpts := func() *pluginOpts {
		return &pluginOpts{
			body:      newChatBody("What is Octelium?"),
			embedding: embedding,
			vectorC:   vectorC,
			upstream: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "gzip")
				w.Write([]byte("\x1f\x8b\x08\x00compressed"))
			},
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		}
	}

	servePlugins(t, newOpts())

	res := servePlugins(t, newOpts())

	assert.False(t, res.isNext)
	assert.Equal(t, "gzip", res.header.Get("Content-Encoding"))
	assert.Equal(t, "application/json", res.header.Get("Content-Type"))
	assert.Equal(t, "\x1f\x8b\x08\x00compressed", res.body)
}

func TestSemanticCachePartialStream(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	res := servePlugins(t, &pluginOpts{
		body:      newChatBody("What is Octelium?"),
		embedding: embedding,
		vectorC:   vectorC,
		upstream:  upstreamCompletion("a truncated answer"),
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newSemanticCachePlugin(nil),
		},
		downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		llmResponse: &middlewares.LLMResponseInfo{
			UsageSource: corev1.AccessLog_Entry_Info_LLM_Usage_PARTIAL,
		},
	})

	assert.True(t, res.isNext)
	assert.False(t, res.reqCtx.LLMSemanticCache.IsStored)
	assert.Zero(t, vectorC.count())
}

func TestSemanticCacheOpaqueContent(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	newOpts := func(data string) *pluginOpts {
		return &pluginOpts{
			body: `{"model":"gpt-4o","messages":[{"role":"user","content":[` +
				`{"type":"text","text":"summarize this"},` +
				`{"type":"tool_result","tool_use_id":"1","content":"` + data + `"}]}]}`,
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("a summary of " + data),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		}
	}

	servePlugins(t, newOpts("DATA-A"))

	res := servePlugins(t, newOpts("DATA-B"))

	assert.True(t, res.isNext)
	assert.Contains(t, res.body, "DATA-B")
	assert.Equal(t,
		corev1.AccessLog_Entry_Info_LLM_SemanticCache_BYPASS,
		res.reqCtx.LLMSemanticCache.Result)
	assert.Zero(t, vectorC.count())
}

func TestSemanticCacheLongSubject(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	prefix := strings.Repeat("a", maxEmbeddingTextBytes+1)

	newOpts := func(suffix string) *pluginOpts {
		return &pluginOpts{
			body:      newChatBody(prefix + suffix),
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("an answer for " + suffix),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		}
	}

	servePlugins(t, newOpts("ONE"))

	res := servePlugins(t, newOpts("TWO"))

	assert.True(t, res.isNext)
	assert.Contains(t, res.body, "TWO")
	assert.Equal(t,
		corev1.AccessLog_Entry_Info_LLM_SemanticCache_BYPASS,
		res.reqCtx.LLMSemanticCache.Result)
	assert.Zero(t, vectorC.count())
}

func TestSemanticCacheKeyIsolation(t *testing.T) {
	embedding := newFakeEmbeddings(nil)
	vectorC := newFakeVector()

	newOpts := func() *pluginOpts {
		return &pluginOpts{
			body:      newChatBody("What is Octelium?"),
			embedding: embedding,
			vectorC:   vectorC,
			upstream:  upstreamCompletion("an answer"),
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newSemanticCachePlugin(nil),
			},
			downstream: newDownstream("8f1a9b7c-0000-0000-0000-000000000001"),
		}
	}

	servePlugins(t, newOpts())

	{
		res := servePlugins(t, newOpts())
		assert.False(t, res.isNext)
	}

	{
		opts := newOpts()
		opts.configName = "premium"

		res := servePlugins(t, opts)
		assert.True(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_MISS,
			res.reqCtx.LLMSemanticCache.Result)
	}

	{
		opts := newOpts()
		opts.embeddingCfg = embedding.config()
		opts.embeddingCfg.Model = "text-embedding-3-large"

		res := servePlugins(t, opts)
		assert.True(t, res.isNext)
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_SemanticCache_MISS,
			res.reqCtx.LLMSemanticCache.Result)
	}
}

func TestSemanticRouterTableSingleflight(t *testing.T) {
	embedding := newFakeEmbeddings(map[string][]float32{
		"Why does this Go program deadlock?": {1, 0, 0, 0},
		"What is the capital of Egypt?":      {0, 1, 0, 0},
	})

	router, err := NewSemanticRouter(context.Background(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		&SemanticOpts{Upstream: embedding.upstreamFn()})
	assert.Nil(t, err)

	cfg := newSemanticRouterPlugin(embedding)
	plugin := newPlugin("router", cfg)

	reqCtx := &middlewares.RequestContext{
		ServiceConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Llm{
				Llm: &corev1.Service_Spec_Config_LLM{},
			},
		},
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			table, err := router.(*semanticRouter).getTable(context.Background(),
				reqCtx, plugin, cfg, embedding.config())
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, 2, len(table))
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, embedding.requests())
}

func TestEmbeddingEndpoint(t *testing.T) {
	newURL := func(t *testing.T, arg string) *url.URL {
		ret, err := url.Parse(arg)
		assert.Nil(t, err)
		return ret
	}

	assert.Equal(t, "https://api.openai.com/v1/embeddings",
		embeddingEndpoint(newURL(t, "https://api.openai.com/v1"), "/embeddings"))

	assert.Equal(t, "https://api.openai.com/v1/embeddings",
		embeddingEndpoint(newURL(t, "https://api.openai.com/v1/"), "/embeddings"))

	assert.Equal(t, "https://example.com/api/v1/embeddings",
		embeddingEndpoint(newURL(t, "https://example.com/api/v1"), "/embeddings"))

	assert.Equal(t, "https://example.com/embeddings",
		embeddingEndpoint(newURL(t, "https://example.com"), "/embeddings"))

	assert.Equal(t,
		"https://example.openai.azure.com/openai/deployments/emb/embeddings?api-version=2024-02-01",
		embeddingEndpoint(newURL(t,
			"https://example.openai.azure.com/openai/deployments/emb?api-version=2024-02-01"),
			"/embeddings"))

	assert.Equal(t,
		"https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:batchEmbedContents",
		embeddingEndpoint(newURL(t, "https://generativelanguage.googleapis.com/v1beta"),
			"/models/gemini-embedding-001:batchEmbedContents"))

	assert.Equal(t, "http://embeddings.octelium.svc:8080/v1/embeddings",
		embeddingEndpoint(newURL(t, "http://embeddings.octelium.svc:8080/v1"), "/embeddings"))
}
