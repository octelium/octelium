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
	"net/http"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
)

const messagesBody = `{"model":"claude-sonnet-4-5","max_tokens":1024,` +
	`"messages":[{"role":"user","content":"Hello"}]}`

func newReasoningLevelCfg(
	level corev1.Service_Spec_Config_LLM_Reasoning_Level) *corev1.Service_Spec_Config_LLM_Reasoning {
	return &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{Level: level},
	}
}

func newReasoningTokenBudgetCfg(
	tokenBudget uint64) *corev1.Service_Spec_Config_LLM_Reasoning {
	return &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_TokenBudget{
			TokenBudget: tokenBudget,
		},
	}
}

func newReasoningEffortCfg(
	effort string) *corev1.Service_Spec_Config_LLM_Reasoning {
	return &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Effort{Effort: effort},
	}
}

func TestReasoningUnset(t *testing.T) {
	res := servePlugins(t, &pluginOpts{
		body: chatBody,
	})

	assert.True(t, res.isNext)
	assert.Nil(t, res.upstream["reasoning_effort"])
	assert.Equal(t, chatBody, string(res.reqCtx.Body))
}

func TestReasoningLevelOpenAI(t *testing.T) {

	{
		res := servePlugins(t, &pluginOpts{
			body: chatBody,
			reasoning: newReasoningLevelCfg(
				corev1.Service_Spec_Config_LLM_Reasoning_HIGH),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "high", res.upstream["reasoning_effort"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body: chatBody,
			reasoning: newReasoningLevelCfg(
				corev1.Service_Spec_Config_LLM_Reasoning_NONE),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "none", res.upstream["reasoning_effort"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body: chatBody,
			reasoning: newReasoningLevelCfg(
				corev1.Service_Spec_Config_LLM_Reasoning_MINIMAL),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "minimal", res.upstream["reasoning_effort"])
	}
}

func TestReasoningLevelResponses(t *testing.T) {
	res := servePlugins(t, &pluginOpts{
		path: "/v1/responses",
		body: `{"model":"gpt-5","input":"Hello",` +
			`"reasoning":{"summary":"auto","effort":"high"}}`,
		reasoning: newReasoningLevelCfg(
			corev1.Service_Spec_Config_LLM_Reasoning_LOW),
	})

	assert.True(t, res.isNext)
	assert.Nil(t, res.upstream["reasoning_effort"])

	reasoning, ok := res.upstream["reasoning"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "low", reasoning["effort"])
	assert.Equal(t, "auto", reasoning["summary"])
}

func TestReasoningLevelAnthropic(t *testing.T) {

	{
		res := servePlugins(t, &pluginOpts{
			protocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
			path:     "/v1/messages",
			body:     messagesBody,
			reasoning: newReasoningLevelCfg(
				corev1.Service_Spec_Config_LLM_Reasoning_MEDIUM),
		})

		assert.True(t, res.isNext)

		thinking, ok := res.upstream["thinking"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "enabled", thinking["type"])
		assert.Equal(t, float64(mediumReasoningBudget), thinking["budget_tokens"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			protocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
			path:     "/v1/messages",
			body:     messagesBody,
			reasoning: newReasoningLevelCfg(
				corev1.Service_Spec_Config_LLM_Reasoning_NONE),
		})

		assert.True(t, res.isNext)

		thinking, ok := res.upstream["thinking"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "disabled", thinking["type"])
		assert.Nil(t, thinking["budget_tokens"])
	}
}

func TestReasoningTokenBudget(t *testing.T) {

	{
		res := servePlugins(t, &pluginOpts{
			protocol:  corev1.Service_Spec_Config_LLM_ANTHROPIC,
			path:      "/v1/messages",
			body:      messagesBody,
			reasoning: newReasoningTokenBudgetCfg(8192),
		})

		assert.True(t, res.isNext)

		thinking, ok := res.upstream["thinking"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, float64(8192), thinking["budget_tokens"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			protocol:  corev1.Service_Spec_Config_LLM_ANTHROPIC,
			path:      "/v1/messages",
			body:      messagesBody,
			reasoning: newReasoningTokenBudgetCfg(16),
		})

		assert.True(t, res.isNext)

		thinking, ok := res.upstream["thinking"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "disabled", thinking["type"])
		assert.Nil(t, thinking["budget_tokens"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:      chatBody,
			reasoning: newReasoningTokenBudgetCfg(mediumReasoningBudget + 1),
		})

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:      chatBody,
			reasoning: newReasoningTokenBudgetCfg(0),
		})

		assert.True(t, res.isNext)
		assert.Nil(t, res.upstream["reasoning_effort"])
		assert.Equal(t, chatBody, string(res.reqCtx.Body))
	}
}

func TestReasoningLevelDowngrade(t *testing.T) {

	for _, level := range []corev1.Service_Spec_Config_LLM_Reasoning_Level{
		corev1.Service_Spec_Config_LLM_Reasoning_XHIGH,
		corev1.Service_Spec_Config_LLM_Reasoning_MAX,
	} {
		res := servePlugins(t, &pluginOpts{
			body:      chatBody,
			reasoning: newReasoningLevelCfg(level),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "high", res.upstream["reasoning_effort"])
	}
}

func TestReasoningEffort(t *testing.T) {

	{
		res := servePlugins(t, &pluginOpts{
			body:      chatBody,
			reasoning: newReasoningEffortCfg("xhigh"),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "xhigh", res.upstream["reasoning_effort"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			path: "/v1/responses",
			body: `{"model":"gpt-5","input":"Hello",` +
				`"reasoning":{"summary":"auto"}}`,
			reasoning: newReasoningEffortCfg("xhigh"),
		})

		assert.True(t, res.isNext)

		reasoning, ok := res.upstream["reasoning"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "xhigh", reasoning["effort"])
		assert.Equal(t, "auto", reasoning["summary"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			protocol:  corev1.Service_Spec_Config_LLM_ANTHROPIC,
			path:      "/v1/messages",
			body:      messagesBody,
			reasoning: newReasoningEffortCfg("xhigh"),
		})

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}
}

func TestReasoningGeminiTokenBudget(t *testing.T) {

	{
		o := newGeminiOpts(geminiBody)
		o.reasoning = newReasoningTokenBudgetCfg(2048)

		res := servePlugins(t, o)

		assert.True(t, res.isNext)

		generation, ok := res.upstream["generationConfig"].(map[string]any)
		assert.True(t, ok)
		thinking, ok := generation["thinkingConfig"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, float64(2048), thinking["thinkingBudget"])
	}

	{
		o := newGeminiOpts(geminiBody)
		o.reasoning = newReasoningTokenBudgetCfg(64)

		res := servePlugins(t, o)

		assert.True(t, res.isNext)

		generation, ok := res.upstream["generationConfig"].(map[string]any)
		assert.True(t, ok)
		thinking, ok := generation["thinkingConfig"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, float64(0), thinking["thinkingBudget"])
	}
}

func TestReasoningBedrockNova(t *testing.T) {

	{
		o := newBedrockOpts(bedrockBody)
		o.reasoning = newReasoningTokenBudgetCfg(2048)

		res := servePlugins(t, o)

		assert.True(t, res.isNext)

		fields, ok := res.upstream["additionalModelRequestFields"].(map[string]any)
		assert.True(t, ok)
		reasoning, ok := fields["reasoning_config"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, float64(2048), reasoning["budget_tokens"])
	}

	{
		o := newBedrockOpts(bedrockBody)
		o.path = "/model/us.amazon.nova-pro-v1:0/converse"
		o.reasoning = newReasoningLevelCfg(
			corev1.Service_Spec_Config_LLM_Reasoning_MAX)

		res := servePlugins(t, o)

		assert.True(t, res.isNext)

		fields, ok := res.upstream["additionalModelRequestFields"].(map[string]any)
		assert.True(t, ok)
		reasoning, ok := fields["reasoningConfig"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "enabled", reasoning["type"])
		assert.Equal(t, "high", reasoning["maxReasoningEffort"])
	}

	{
		o := newBedrockOpts(bedrockBody)
		o.path = "/model/amazon.nova-pro-v1:0/converse"
		o.reasoning = newReasoningLevelCfg(
			corev1.Service_Spec_Config_LLM_Reasoning_MINIMAL)

		res := servePlugins(t, o)

		assert.True(t, res.isNext)

		fields, ok := res.upstream["additionalModelRequestFields"].(map[string]any)
		assert.True(t, ok)
		reasoning, ok := fields["reasoningConfig"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, "disabled", reasoning["type"])
	}

	{
		o := newBedrockOpts(bedrockBody)
		o.path = "/model/amazon.nova-pro-v1:0/converse"
		o.reasoning = newReasoningTokenBudgetCfg(2048)

		res := servePlugins(t, o)

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}
}

func TestReasoningReadsTheRewrittenModel(t *testing.T) {
	o := newBedrockOpts(bedrockBody)
	o.reasoning = newReasoningLevelCfg(
		corev1.Service_Spec_Config_LLM_Reasoning_HIGH)
	o.model = &corev1.Service_Spec_Config_LLM_Model{
		Type: &corev1.Service_Spec_Config_LLM_Model_Value{
			Value: "amazon.nova-pro-v1:0",
		},
	}

	res := servePlugins(t, o)

	assert.True(t, res.isNext)
	assert.Equal(t, "/model/amazon.nova-pro-v1:0/converse", res.upstreamPath)

	fields, ok := res.upstream["additionalModelRequestFields"].(map[string]any)
	assert.True(t, ok)
	reasoning, ok := fields["reasoningConfig"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "high", reasoning["maxReasoningEffort"])
	assert.Nil(t, fields["reasoning_config"])
}

func TestReasoningEval(t *testing.T) {

	{
		res := servePlugins(t, &pluginOpts{
			body: chatBody,
			reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
				Type: &corev1.Service_Spec_Config_LLM_Reasoning_Eval{
					Eval: `"MEDIUM"`,
				},
			},
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "medium", res.upstream["reasoning_effort"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			protocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
			path:     "/v1/messages",
			body:     messagesBody,
			reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
				Type: &corev1.Service_Spec_Config_LLM_Reasoning_Eval{
					Eval: `"2048"`,
				},
			},
		})

		assert.True(t, res.isNext)

		thinking, ok := res.upstream["thinking"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, float64(2048), thinking["budget_tokens"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body: chatBody,
			reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
				Type: &corev1.Service_Spec_Config_LLM_Reasoning_Eval{
					Eval: `""`,
				},
			},
		})

		assert.True(t, res.isNext)
		assert.Nil(t, res.upstream["reasoning_effort"])
		assert.Equal(t, chatBody, string(res.reqCtx.Body))
	}

	{
		res := servePlugins(t, &pluginOpts{
			body: chatBody,
			reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
				Type: &corev1.Service_Spec_Config_LLM_Reasoning_Eval{
					Eval: `"ultra"`,
				},
			},
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "ultra", res.upstream["reasoning_effort"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body: chatBody,
			reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
				Type: &corev1.Service_Spec_Config_LLM_Reasoning_Eval{
					Eval: `"high\u0000"`,
				},
			},
		})

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusInternalServerError, res.code)
	}
}

func TestReasoningUnsupportedOperation(t *testing.T) {
	res := servePlugins(t, &pluginOpts{
		path: "/v1/embeddings",
		body: `{"model":"text-embedding-3-small","input":"Hello"}`,
		reasoning: newReasoningLevelCfg(
			corev1.Service_Spec_Config_LLM_Reasoning_HIGH),
	})

	assert.True(t, res.isNext)
	assert.Nil(t, res.upstream["reasoning_effort"])
	assert.Nil(t, res.upstream["reasoning"])
}

func TestReasoningPluginOverridesConfig(t *testing.T) {
	res := servePlugins(t, &pluginOpts{
		body: chatBody,
		reasoning: newReasoningLevelCfg(
			corev1.Service_Spec_Config_LLM_Reasoning_HIGH),
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("reasoning-1", newReasoningLevelCfg(
				corev1.Service_Spec_Config_LLM_Reasoning_LOW)),
		},
	})

	assert.True(t, res.isNext)
	assert.Equal(t, "low", res.upstream["reasoning_effort"])
}

func TestReasoningLastPluginWins(t *testing.T) {
	res := servePlugins(t, &pluginOpts{
		body: chatBody,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("reasoning-1", newReasoningLevelCfg(
				corev1.Service_Spec_Config_LLM_Reasoning_LOW)),
			newPlugin("reasoning-2", newReasoningLevelCfg(
				corev1.Service_Spec_Config_LLM_Reasoning_HIGH)),
		},
	})

	assert.True(t, res.isNext)
	assert.Equal(t, "high", res.upstream["reasoning_effort"])
}

func TestReasoningPluginCondition(t *testing.T) {
	plugin := newPlugin("reasoning-1", newReasoningLevelCfg(
		corev1.Service_Spec_Config_LLM_Reasoning_HIGH))
	plugin.Condition = &corev1.Condition{
		Type: &corev1.Condition_Match{
			Match: `ctx.request.llm.model == "gpt-4o-mini"`,
		},
	}

	res := servePlugins(t, &pluginOpts{
		body: chatBody,
		reasoning: newReasoningLevelCfg(
			corev1.Service_Spec_Config_LLM_Reasoning_LOW),
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{plugin},
	})

	assert.True(t, res.isNext)
	assert.Equal(t, "low", res.upstream["reasoning_effort"])
}

func TestModelPluginOverridesConfig(t *testing.T) {
	res := servePlugins(t, &pluginOpts{
		body: chatBody,
		model: &corev1.Service_Spec_Config_LLM_Model{
			Type: &corev1.Service_Spec_Config_LLM_Model_Value{Value: "gpt-4o-mini"},
		},
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("model-1", &corev1.Service_Spec_Config_LLM_Model{
				Type: &corev1.Service_Spec_Config_LLM_Model_Value{Value: "gpt-5"},
			}),
		},
	})

	assert.True(t, res.isNext)
	assert.Equal(t, "gpt-5", res.upstream["model"])
}

func TestReasoningReadsTheRequestedModel(t *testing.T) {
	plugin := newPlugin("reasoning-1", newReasoningLevelCfg(
		corev1.Service_Spec_Config_LLM_Reasoning_HIGH))
	plugin.Condition = &corev1.Condition{
		Type: &corev1.Condition_Match{
			Match: `ctx.request.llm.model == "gpt-4o"`,
		},
	}

	res := servePlugins(t, &pluginOpts{
		body: chatBody,
		plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("model-1", &corev1.Service_Spec_Config_LLM_Model{
				Type: &corev1.Service_Spec_Config_LLM_Model_Value{Value: "gpt-5"},
			}),
			plugin,
		},
	})

	assert.True(t, res.isNext)
	assert.Equal(t, "gpt-5", res.upstream["model"])
	assert.Equal(t, "high", res.upstream["reasoning_effort"])
}
