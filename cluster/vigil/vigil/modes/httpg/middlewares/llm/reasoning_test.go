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

func newReasoningMaxTokensCfg(
	maxTokens uint64) *corev1.Service_Spec_Config_LLM_Reasoning {
	return &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_MaxTokens{MaxTokens: maxTokens},
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

func TestReasoningMaxTokens(t *testing.T) {

	{
		res := servePlugins(t, &pluginOpts{
			protocol:  corev1.Service_Spec_Config_LLM_ANTHROPIC,
			path:      "/v1/messages",
			body:      messagesBody,
			reasoning: newReasoningMaxTokensCfg(8192),
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
			reasoning: newReasoningMaxTokensCfg(16),
		})

		assert.True(t, res.isNext)

		thinking, ok := res.upstream["thinking"].(map[string]any)
		assert.True(t, ok)
		assert.Equal(t, float64(minReasoningBudget), thinking["budget_tokens"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:      chatBody,
			reasoning: newReasoningMaxTokensCfg(mediumReasoningBudget + 1),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "medium", res.upstream["reasoning_effort"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:      chatBody,
			reasoning: newReasoningMaxTokensCfg(64),
		})

		assert.True(t, res.isNext)
		assert.Equal(t, "minimal", res.upstream["reasoning_effort"])
	}

	{
		res := servePlugins(t, &pluginOpts{
			body:      chatBody,
			reasoning: newReasoningMaxTokensCfg(0),
		})

		assert.True(t, res.isNext)
		assert.Nil(t, res.upstream["reasoning_effort"])
		assert.Equal(t, chatBody, string(res.reqCtx.Body))
	}
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
					Eval: `"not-a-level"`,
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
