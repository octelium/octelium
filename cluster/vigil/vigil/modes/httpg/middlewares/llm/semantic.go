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
	"encoding/json"
	"fmt"
	"math"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
)

const maxSemanticSubjectBytes = 16384

type SemanticOpts struct {
	CELEngine *celengine.CELEngine
	SecretMan *secretman.SecretManager
	SvcUID    string
	Upstream  UpstreamFn
}

func isSemanticOperation(operation corev1.RequestContext_Request_LLM_Operation) bool {
	switch operation {
	case corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_RESPONSES,
		corev1.RequestContext_Request_LLM_MESSAGES,
		corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
		corev1.RequestContext_Request_LLM_CONVERSE:
		return true
	default:
		return false
	}
}

func isSemanticRequest(reqCtx *middlewares.RequestContext) bool {
	llmReq := reqCtx.LLM
	if llmReq == nil || !llmReq.IsBodyValid {
		return false
	}

	if !isSemanticOperation(llmReq.GetOperation()) {
		return false
	}

	return !llmReq.GetHasImageInput() && !llmReq.GetHasAudioInput()
}

func resolveEmbedding(reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Embedding) *corev1.Service_Spec_Config_LLM_Embedding {
	if cfg != nil {
		return cfg
	}

	return ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetLLM().GetEmbedding()
}

func (d *doc) semanticIdentity() (string, []byte, error) {
	msgs, err := d.messages()
	if err != nil {
		return "", nil, err
	}

	idx := -1
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].isItem() {
			continue
		}
		if d.isRole(msgs[i].Role, roleUser) {
			idx = i
			break
		}
	}

	if idx < 0 {
		return "", nil, errors.Errorf("The request carries no user message")
	}

	subject := contentText(msgs[idx].Content)
	if subject == "" {
		return "", nil, errors.Errorf("The last user message carries no text")
	}

	rest := make([]*message, 0, len(msgs))
	for i, msg := range msgs {
		if i != idx {
			rest = append(rest, msg)
			continue
		}

		cur := *msg
		cur.Content = nil
		rest = append(rest, &cur)
	}

	raw, err := json.Marshal(rest)
	if err != nil {
		return "", nil, err
	}

	root := make(map[string]json.RawMessage, len(d.root))
	for key, val := range d.root {
		root[key] = val
	}
	root[d.messagesKey()] = raw

	out, err := json.Marshal(root)
	if err != nil {
		return "", nil, err
	}

	return truncateText(subject, maxSemanticSubjectBytes), vutils.Sha256Sum(out), nil
}

func getSemanticSubject(reqCtx *middlewares.RequestContext) (string, []byte, error) {
	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return "", nil, err
	}

	return d.semanticIdentity()
}

func getEmbeddingKey(cfg *corev1.Service_Spec_Config_LLM_Embedding, subject string) string {
	return vutils.Sha256SumHex([]byte(fmt.Sprintf("%s:%d:%s:%s",
		cfg.GetModel(), cfg.GetDimensions(), embeddingSourceKey(cfg), subject)))
}

func embeddingSourceKey(cfg *corev1.Service_Spec_Config_LLM_Embedding) string {
	switch cfg.GetSource().GetType().(type) {
	case *corev1.Service_Spec_Config_LLM_Embedding_Source_Upstream_:
		return cfg.GetSource().GetUpstream().GetUrl()
	default:
		return "currentUpstream"
	}
}

func (e *embedder) embedSubject(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Embedding,
	reqCtx *middlewares.RequestContext, subject string) ([]float32, error) {

	key := getEmbeddingKey(cfg, subject)
	if vec, ok := reqCtx.LLMEmbeddings[key]; ok {
		return vec, nil
	}

	vecs, err := e.embed(ctx, cfg, reqCtx, []string{subject})
	if err != nil {
		return nil, err
	}

	if reqCtx.LLMEmbeddings == nil {
		reqCtx.LLMEmbeddings = make(map[string][]float32)
	}
	reqCtx.LLMEmbeddings[key] = vecs[0]

	return vecs[0], nil
}

func cosineSimilarity(a, b []float32) float32 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}

	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	if normA <= 0 || normB <= 0 {
		return 0
	}

	ret := dot / (math.Sqrt(normA) * math.Sqrt(normB))
	switch {
	case ret <= 0:
		return 0
	case ret > 1:
		return 1
	default:
		return float32(ret)
	}
}
