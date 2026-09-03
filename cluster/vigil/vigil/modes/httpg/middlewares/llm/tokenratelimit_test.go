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
	"net/http"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

const chatBodyWithMaxTokens = `{"model":"gpt-4o","max_tokens":900,` +
	`"messages":[{"role":"user","content":"Hello"}]}`

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	rateLimitC *fakeRateLimit
}

func (c *fakeOcteliumC) RateLimitC() rratelimitv1.MainServiceClient {
	return c.rateLimitC
}

type fakeRateLimit struct {
	rratelimitv1.MainServiceClient

	entries map[string]map[string]int64

	reserveErr   error
	reconcileErr error

	reserveCount   int
	reconcileCount int
}

func newFakeRateLimit() *fakeRateLimit {
	return &fakeRateLimit{
		entries: make(map[string]map[string]int64),
	}
}

func (c *fakeRateLimit) ReserveSlidingWindow(ctx context.Context,
	req *rratelimitv1.ReserveSlidingWindowRequest,
	opts ...grpc.CallOption) (*rratelimitv1.ReserveSlidingWindowResponse, error) {

	if c.reserveErr != nil {
		return nil, c.reserveErr
	}

	c.reserveCount++
	c.set(req.Key, req.Id, req.Amount)

	total := c.total(req.Key)
	if total > req.Limit {
		c.set(req.Key, req.Id, 0)
		return &rratelimitv1.ReserveSlidingWindowResponse{
			Total: total - req.Amount,
		}, nil
	}

	return &rratelimitv1.ReserveSlidingWindowResponse{
		IsAllowed: true,
		Total:     total,
	}, nil
}

func (c *fakeRateLimit) ReconcileSlidingWindow(ctx context.Context,
	req *rratelimitv1.ReconcileSlidingWindowRequest,
	opts ...grpc.CallOption) (*rratelimitv1.ReconcileSlidingWindowResponse, error) {

	if c.reconcileErr != nil {
		return nil, c.reconcileErr
	}

	c.reconcileCount++
	c.set(req.Key, req.Id, req.Amount)

	return &rratelimitv1.ReconcileSlidingWindowResponse{
		Total: c.total(req.Key),
	}, nil
}

func (c *fakeRateLimit) set(key, id []byte, amount int64) {
	entries := c.entries[string(key)]
	if entries == nil {
		entries = make(map[string]int64)
		c.entries[string(key)] = entries
	}

	if amount > 0 {
		entries[string(id)] = amount
	} else {
		delete(entries, string(id))
	}
}

func (c *fakeRateLimit) total(key []byte) int64 {
	var ret int64
	for _, amount := range c.entries[string(key)] {
		ret += amount
	}
	return ret
}

func (c *fakeRateLimit) sum() int64 {
	var ret int64
	for key := range c.entries {
		ret += c.total([]byte(key))
	}
	return ret
}

func (c *fakeRateLimit) keyCount() int {
	var ret int
	for key := range c.entries {
		if len(c.entries[key]) > 0 {
			ret++
		}
	}
	return ret
}

func newTokenRateLimit(limit int64,
	scope corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_Scope,
) *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit {
	return &corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit{
		Scope: scope,
		Limit: limit,
		Window: &metav1.Duration{
			Type: &metav1.Duration_Minutes{Minutes: 1},
		},
	}
}

func newProviderUsage(inputTokens, outputTokens uint64) *middlewares.LLMResponseInfo {
	return &middlewares.LLMResponseInfo{
		UsageSource: corev1.AccessLog_Entry_Info_LLM_Usage_PROVIDER,
		Usage: httputils.LLMUsage{
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			TotalTokens:  inputTokens + outputTokens,
		},
	}
}

func TestTokenRateLimitUnset(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body:       chatBody,
		rateLimitC: rateLimitC,
	})

	assert.True(t, res.isNext)
	assert.Equal(t, http.StatusOK, res.code)
	assert.Equal(t, 0, rateLimitC.reserveCount)
	assert.Equal(t, 0, rateLimitC.reconcileCount)
}

func TestTokenRateLimitReserveAndReconcile(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC:  rateLimitC,
		llmResponse: newProviderUsage(11, 22),
	})

	assert.True(t, res.isNext)
	assert.Equal(t, http.StatusOK, res.code)
	assert.Equal(t, 1, rateLimitC.reserveCount)
	assert.Equal(t, 1, rateLimitC.reconcileCount)
	assert.Equal(t, int64(33), rateLimitC.sum())
}

func TestTokenRateLimitReservesEstimateAndMaxOutput(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC: rateLimitC,
	})

	assert.True(t, res.isNext)
	assert.Equal(t,
		int64(res.reqCtx.LLM.GetEstimatedInputTokens())+900, rateLimitC.sum())
}

func TestTokenRateLimitClampsHugeOutputMax(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	servePlugins(t, &pluginOpts{
		body: `{"model":"gpt-4o","max_tokens":1152921504606846976,` +
			`"messages":[{"role":"user","content":"Hello"}]}`,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(1<<50,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC: rateLimitC,
	})

	assert.Equal(t, int64(maxReservationTokens), rateLimitC.sum())
}

func TestTokenRateLimitDenied(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(10,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC: rateLimitC,
	})

	assert.False(t, res.isNext)
	assert.Equal(t, http.StatusTooManyRequests, res.code)
	assert.Contains(t, res.body, ErrCodeTokenRateLimit)
	assert.Equal(t, int64(0), rateLimitC.sum())
	assert.Equal(t, 0, rateLimitC.reconcileCount)
}

func TestTokenRateLimitDenyMessageAndHeaders(t *testing.T) {
	cfg := newTokenRateLimit(1,
		corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)
	cfg.DenyMessage = "You are out of tokens"
	cfg.Headers = []*corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_KeyValue{
		{
			Key:   "Retry-After",
			Value: "60",
		},
	}

	res := servePlugins(t, &pluginOpts{
		body: chatBody,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", cfg),
		},
	})

	assert.False(t, res.isNext)
	assert.Equal(t, http.StatusTooManyRequests, res.code)
	assert.Contains(t, res.body, "You are out of tokens")
}

func TestTokenRateLimitScopeInput(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_INPUT)),
		},
		rateLimitC: rateLimitC,
	})

	assert.Equal(t, int64(res.reqCtx.LLM.GetEstimatedInputTokens()), rateLimitC.sum())

	res.reqCtx.LLMResponse = newProviderUsage(11, 22)
	res.reqCtx.RunOnResponse()

	assert.Equal(t, int64(11), rateLimitC.sum())
}

func TestTokenRateLimitScopeOutput(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_OUTPUT)),
		},
		rateLimitC:  rateLimitC,
		llmResponse: newProviderUsage(11, 22),
	})

	assert.True(t, res.isNext)
	assert.Equal(t, int64(22), rateLimitC.sum())
}

func TestTokenRateLimitDefaultOutputTokens(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	cfg := newTokenRateLimit(100000,
		corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_OUTPUT)
	cfg.DefaultOutputTokens = 4096

	servePlugins(t, &pluginOpts{
		body: chatBody,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", cfg),
		},
		rateLimitC: rateLimitC,
	})

	assert.Equal(t, int64(4096), rateLimitC.sum())
}

func TestTokenRateLimitDeclaredOutputWinsOverDefault(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	cfg := newTokenRateLimit(100000,
		corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_OUTPUT)
	cfg.DefaultOutputTokens = 4096

	servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", cfg),
		},
		rateLimitC: rateLimitC,
	})

	assert.Equal(t, int64(900), rateLimitC.sum())
}

func TestTokenRateLimitReleasesUnusedUpstream(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC: rateLimitC,
		llmResponse: &middlewares.LLMResponseInfo{
			UsageSource: corev1.AccessLog_Entry_Info_LLM_Usage_SOURCE_UNSET,
		},
	})

	assert.Equal(t, int64(0), rateLimitC.sum())
	assert.Equal(t, 1, rateLimitC.reconcileCount)
}

func TestTokenRateLimitKeepsUnmeasuredUsage(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC: rateLimitC,
		llmResponse: &middlewares.LLMResponseInfo{
			UsageSource: corev1.AccessLog_Entry_Info_LLM_Usage_ESTIMATED,
		},
	})

	assert.Equal(t,
		int64(res.reqCtx.LLM.GetEstimatedInputTokens())+900, rateLimitC.sum())
	assert.Equal(t, 0, rateLimitC.reconcileCount)
}

func TestTokenRateLimitPartialUsage(t *testing.T) {
	{
		rateLimitC := newFakeRateLimit()

		res := servePlugins(t, &pluginOpts{
			body: chatBodyWithMaxTokens,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("tpm", newTokenRateLimit(100000,
					corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
			},
			rateLimitC: rateLimitC,
			llmResponse: &middlewares.LLMResponseInfo{
				UsageSource: corev1.AccessLog_Entry_Info_LLM_Usage_PARTIAL,
				Usage: httputils.LLMUsage{
					InputTokens:  11,
					OutputTokens: 22,
					TotalTokens:  33,
				},
			},
		})

		assert.Equal(t,
			int64(res.reqCtx.LLM.GetEstimatedInputTokens())+900, rateLimitC.sum())
	}

	{
		rateLimitC := newFakeRateLimit()

		servePlugins(t, &pluginOpts{
			body: chatBodyWithMaxTokens,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("tpm", newTokenRateLimit(100000,
					corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
			},
			rateLimitC:  rateLimitC,
			llmResponse: newProviderUsage(1000, 90000),
		})

		assert.Equal(t, int64(91000), rateLimitC.sum())
	}
}

func TestTokenRateLimitReleasesEarlierPluginsOnDeny(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
			newPlugin("daily", newTokenRateLimit(10,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC: rateLimitC,
	})

	assert.False(t, res.isNext)
	assert.Equal(t, http.StatusTooManyRequests, res.code)
	assert.Equal(t, 2, rateLimitC.reserveCount)
	assert.Equal(t, int64(0), rateLimitC.sum())
}

func TestTokenRateLimitSeparateWindowsPerPlugin(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
			newPlugin("daily", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC: rateLimitC,
	})

	assert.True(t, res.isNext)
	assert.Equal(t, 2, rateLimitC.keyCount())
}

func TestTokenRateLimitPluginCondition(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	plugin := newPlugin("tpm", newTokenRateLimit(10,
		corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL))
	plugin.Condition = &corev1.Condition{
		Type: &corev1.Condition_Match{
			Match: `ctx.request.llm.model == "gpt-5"`,
		},
	}

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			plugin,
		},
		rateLimitC: rateLimitC,
	})

	assert.True(t, res.isNext)
	assert.Equal(t, 0, rateLimitC.reserveCount)
}

func TestTokenRateLimitPluginDisabled(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	plugin := newPlugin("tpm", newTokenRateLimit(10,
		corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL))
	plugin.IsDisabled = true

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			plugin,
		},
		rateLimitC: rateLimitC,
	})

	assert.True(t, res.isNext)
	assert.Equal(t, 0, rateLimitC.reserveCount)
}

func TestTokenRateLimitFailOpen(t *testing.T) {
	rateLimitC := newFakeRateLimit()
	rateLimitC.reserveErr = errors.New("Redis is down")

	res := servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(10,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC:  rateLimitC,
		llmResponse: newProviderUsage(11, 22),
	})

	assert.True(t, res.isNext)
	assert.Equal(t, http.StatusOK, res.code)
	assert.Equal(t, 1, rateLimitC.reconcileCount)
	assert.Equal(t, int64(33), rateLimitC.sum())
}

func TestTokenRateLimitKeyEvalError(t *testing.T) {
	newEvalKeyPlugin := func(name string,
		eval string) *corev1.Service_Spec_Config_LLM_Plugin {
		cfg := newTokenRateLimit(100000,
			corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)
		cfg.Key = &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_Eval{
				Eval: eval,
			},
		}
		return newPlugin(name, cfg)
	}

	{
		rateLimitC := newFakeRateLimit()

		res := servePlugins(t, &pluginOpts{
			body: chatBodyWithMaxTokens,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newEvalKeyPlugin("tpm", `((((`),
			},
			rateLimitC: rateLimitC,
		})

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusInternalServerError, res.code)
		assert.Equal(t, 0, rateLimitC.reserveCount)
	}

	{
		rateLimitC := newFakeRateLimit()

		res := servePlugins(t, &pluginOpts{
			body: chatBodyWithMaxTokens,
			plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("tpm", newTokenRateLimit(100000,
					corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
				newEvalKeyPlugin("daily", `((((`),
			},
			rateLimitC: rateLimitC,
		})

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusInternalServerError, res.code)
		assert.Equal(t, 1, rateLimitC.reserveCount)
		assert.Equal(t, int64(0), rateLimitC.sum())
	}
}

func TestTokenRateLimitInconsistentProviderUsage(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_INPUT)),
		},
		rateLimitC: rateLimitC,
		llmResponse: &middlewares.LLMResponseInfo{
			UsageSource: corev1.AccessLog_Entry_Info_LLM_Usage_PROVIDER,
			Usage: httputils.LLMUsage{
				InputTokens:  11,
				OutputTokens: 22,
				TotalTokens:  5,
			},
		},
	})

	assert.Equal(t, int64(11), rateLimitC.sum())
}

func TestTokenRateLimitKeyPerUser(t *testing.T) {
	cfg := newTokenRateLimit(100000,
		corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)
	cfg.Key = &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
		Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerUser{
			PerUser: true,
		},
	}

	first := newFakeRateLimit()
	servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", cfg),
		},
		rateLimitC: first,
		downstream: &corev1.RequestContext{
			User: &corev1.User{
				Metadata: &metav1.Metadata{
					Uid: "8f1a9b7c-0000-0000-0000-000000000001",
				},
			},
		},
	})

	second := newFakeRateLimit()
	servePlugins(t, &pluginOpts{
		body: chatBodyWithMaxTokens,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", cfg),
		},
		rateLimitC: second,
		downstream: &corev1.RequestContext{
			User: &corev1.User{
				Metadata: &metav1.Metadata{
					Uid: "8f1a9b7c-0000-0000-0000-000000000002",
				},
			},
		},
	})

	assert.Equal(t, 1, first.keyCount())
	assert.Equal(t, 1, second.keyCount())

	for key := range first.entries {
		_, ok := second.entries[key]
		assert.False(t, ok)
	}
}

func TestTokenRateLimitUnsupportedOperation(t *testing.T) {
	rateLimitC := newFakeRateLimit()

	res := servePlugins(t, &pluginOpts{
		path: "/v1/models",
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tpm", newTokenRateLimit(100000,
				corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL)),
		},
		rateLimitC: rateLimitC,
	})

	assert.True(t, res.isNext)
	assert.Equal(t, int64(0), rateLimitC.sum())
}
