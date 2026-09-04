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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
)

const (
	maxEmbeddingTexts     = 64
	maxEmbeddingTextBytes = 8192
	maxEmbeddingDimension = 4096
	maxEmbeddingBodyBytes = 16 << 20
	embeddingTimeout      = 10 * time.Second
)

type UpstreamFn func(ctx context.Context) (*url.URL, error)

type embedder struct {
	client    *http.Client
	secretMan *secretman.SecretManager
	upstream  UpstreamFn
}

func newEmbedder(secretMan *secretman.SecretManager, upstream UpstreamFn) *embedder {
	return &embedder{
		client: &http.Client{
			Timeout: embeddingTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		secretMan: secretMan,
		upstream:  upstream,
	}
}

type embeddingTarget struct {
	url      *url.URL
	protocol corev1.Service_Spec_Config_LLM_Protocol
	auth     *corev1.Service_Spec_Config_HTTP_Auth
}

func (e *embedder) embed(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Embedding,
	reqCtx *middlewares.RequestContext, texts []string) ([][]float32, error) {

	if cfg == nil {
		return nil, errors.Errorf("The embedding configuration is not set")
	}

	if cfg.GetModel() == "" {
		return nil, errors.Errorf("The embedding model is not set")
	}

	if len(texts) == 0 || len(texts) > maxEmbeddingTexts {
		return nil, errors.Errorf("Invalid embedding input count: %d", len(texts))
	}

	target, err := e.resolve(ctx, cfg, reqCtx)
	if err != nil {
		return nil, err
	}

	inputs := make([]string, 0, len(texts))
	for _, text := range texts {
		inputs = append(inputs, truncateText(text, maxEmbeddingTextBytes))
	}

	switch target.protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return e.embedGemini(ctx, cfg, target, inputs)
	case corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_PROTOCOL_UNSET:
		return e.embedOpenAI(ctx, cfg, target, inputs)
	default:
		return nil, errors.Errorf("This protocol serves no embedding operation: %s",
			target.protocol.String())
	}
}

func (e *embedder) resolve(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Embedding,
	reqCtx *middlewares.RequestContext) (*embeddingTarget, error) {

	switch cfg.GetSource().GetType().(type) {
	case *corev1.Service_Spec_Config_LLM_Embedding_Source_CurrentUpstream:
		if e.upstream == nil {
			return nil, errors.Errorf("The Service upstream is unavailable")
		}

		upstream, err := e.upstream(ctx)
		if err != nil {
			return nil, err
		}

		svcCfg := ucorev1.ToServiceConfig(reqCtx.ServiceConfig)
		return &embeddingTarget{
			url:      upstream,
			protocol: svcCfg.GetLLMProtocol(),
			auth:     svcCfg.GetHTTPAuth(),
		}, nil
	case *corev1.Service_Spec_Config_LLM_Embedding_Source_Upstream_:
		upstream := cfg.GetSource().GetUpstream()

		parsed, err := url.Parse(upstream.GetUrl())
		if err != nil {
			return nil, err
		}
		if parsed.Host == "" {
			return nil, errors.Errorf("The embedding upstream URL has no host")
		}
		switch parsed.Scheme {
		case "http", "https":
		default:
			return nil, errors.Errorf("Invalid embedding upstream URL scheme: %s",
				parsed.Scheme)
		}

		return &embeddingTarget{
			url:      parsed,
			protocol: upstream.GetProtocol(),
			auth:     upstream.GetAuth(),
		}, nil
	default:
		return nil, errors.Errorf("The embedding source is not set")
	}
}

type openAIEmbeddingResponse struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

func (e *embedder) embedOpenAI(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Embedding,
	target *embeddingTarget, texts []string) ([][]float32, error) {

	body := map[string]any{
		"model": cfg.GetModel(),
		"input": texts,
	}
	if cfg.GetDimensions() > 0 {
		body["dimensions"] = cfg.GetDimensions()
	}

	out := &openAIEmbeddingResponse{}
	if err := e.do(ctx, target,
		embeddingEndpoint(target.url, "/embeddings"), body, out); err != nil {
		return nil, err
	}

	if len(out.Data) != len(texts) {
		return nil, errors.Errorf("Unexpected embedding count: %d", len(out.Data))
	}

	ret := make([][]float32, len(texts))
	for _, entry := range out.Data {
		if entry.Index < 0 || entry.Index >= len(ret) {
			return nil, errors.Errorf("Invalid embedding index: %d", entry.Index)
		}
		ret[entry.Index] = entry.Embedding
	}

	return checkEmbeddings(ret)
}

type geminiEmbeddingResponse struct {
	Embeddings []struct {
		Values []float32 `json:"values"`
	} `json:"embeddings"`
}

func (e *embedder) embedGemini(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Embedding,
	target *embeddingTarget, texts []string) ([][]float32, error) {

	model := cfg.GetModel()
	if strings.ContainsAny(model, "/:") {
		return nil, errors.Errorf("The embedding model name contains an invalid character")
	}

	requests := make([]map[string]any, 0, len(texts))
	for _, text := range texts {
		entry := map[string]any{
			"model": fmt.Sprintf("models/%s", model),
			"content": map[string]any{
				partsKey: []map[string]any{
					{"text": text},
				},
			},
		}
		if cfg.GetDimensions() > 0 {
			entry["outputDimensionality"] = cfg.GetDimensions()
		}
		requests = append(requests, entry)
	}

	out := &geminiEmbeddingResponse{}
	if err := e.do(ctx, target, embeddingEndpoint(target.url,
		fmt.Sprintf("/models/%s:batchEmbedContents", model)),
		map[string]any{"requests": requests}, out); err != nil {
		return nil, err
	}

	if len(out.Embeddings) != len(texts) {
		return nil, errors.Errorf("Unexpected embedding count: %d", len(out.Embeddings))
	}

	ret := make([][]float32, 0, len(texts))
	for _, entry := range out.Embeddings {
		ret = append(ret, entry.Values)
	}

	return checkEmbeddings(ret)
}

func (e *embedder) do(ctx context.Context, target *embeddingTarget,
	endpoint string, body, out any) error {

	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "octelium")

	if err := e.setAuth(ctx, req, target.auth); err != nil {
		return err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return errors.Errorf("The embedding API returned the status code: %d", resp.StatusCode)
	}

	return json.NewDecoder(io.LimitReader(resp.Body, maxEmbeddingBodyBytes)).Decode(out)
}

func (e *embedder) setAuth(ctx context.Context, req *http.Request,
	auth *corev1.Service_Spec_Config_HTTP_Auth) error {

	if auth == nil {
		return nil
	}

	if e.secretMan == nil {
		return errors.Errorf("The Secret manager is unavailable")
	}

	switch {
	case auth.GetBearer().GetFromSecret() != "":
		secret, err := e.secretMan.GetByName(ctx, auth.GetBearer().GetFromSecret())
		if err != nil {
			return err
		}
		req.Header.Set("Authorization",
			fmt.Sprintf("Bearer %s", ucorev1.ToSecret(secret).GetValueStr()))
	case auth.GetBasic().GetPassword().GetFromSecret() != "":
		secret, err := e.secretMan.GetByName(ctx,
			auth.GetBasic().GetPassword().GetFromSecret())
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s",
			base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s",
				auth.GetBasic().GetUsername(),
				ucorev1.ToSecret(secret).GetValueStr())))))
	case auth.GetCustom().GetValue().GetFromSecret() != "":
		secret, err := e.secretMan.GetByName(ctx,
			auth.GetCustom().GetValue().GetFromSecret())
		if err != nil {
			return err
		}
		req.Header.Set(auth.GetCustom().GetHeader(),
			ucorev1.ToSecret(secret).GetValueStr())
	case auth.GetOauth2ClientCredentials().GetClientSecret().GetFromSecret() != "":
		cc := auth.GetOauth2ClientCredentials()
		accessToken, err := e.secretMan.GetOAuth2CCToken(ctx, &secretman.GetOAuth2CCTokenReq{
			ClientID:   cc.GetClientID(),
			SecretName: cc.GetClientSecret().GetFromSecret(),
			TokenURL:   cc.GetTokenURL(),
			Scopes:     cc.GetScopes(),
		})
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}

	return nil
}

func embeddingEndpoint(base *url.URL, path string) string {
	ret := *base

	switch ret.Scheme {
	case "http", "https":
	case "ws":
		ret.Scheme = "http"
	case "wss":
		ret.Scheme = "https"
	default:
		ret.Scheme = "https"
	}

	ret.Path = strings.TrimSuffix(base.Path, "/") + path
	ret.RawPath = ""
	ret.Fragment = ""

	return ret.String()
}

func checkEmbeddings(arg [][]float32) ([][]float32, error) {
	for _, vec := range arg {
		if len(vec) == 0 || len(vec) > maxEmbeddingDimension {
			return nil, errors.Errorf("Invalid embedding dimension: %d", len(vec))
		}
		if len(vec) != len(arg[0]) {
			return nil, errors.Errorf("Inconsistent embedding dimensions")
		}
		for _, val := range vec {
			if math.IsNaN(float64(val)) || math.IsInf(float64(val), 0) {
				return nil, errors.Errorf("The embedding values are not finite")
			}
		}
	}

	return arg, nil
}

func truncateText(arg string, maxBytes int) string {
	if len(arg) <= maxBytes {
		return arg
	}

	ret := arg[:maxBytes]
	for len(ret) > 0 && !utf8.ValidString(ret) {
		ret = ret[:len(ret)-1]
	}

	return ret
}
