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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/stretchr/testify/assert"
)

const geminiPath = "/v1beta/models/gemini-2.5-pro:generateContent"

const geminiBody = `{"contents":[{"role":"user","parts":[{"text":"Hello"}]}]}`

const geminiSystemBody = `{"contents":[{"role":"user","parts":[{"text":"Hello"}]}],` +
	`"systemInstruction":{"parts":[{"text":"Be terse"}]}}`

const bedrockPath = "/model/anthropic.claude-sonnet-4-5-v1:0/converse"

const bedrockBody = `{"messages":[{"role":"user","content":[{"text":"Hello"}]}]}`

const bedrockSystemBody = `{"messages":[{"role":"user","content":[{"text":"Hello"}]}],` +
	`"system":[{"text":"Be terse"}]}`

func newGeminiOpts(body string) *pluginOpts {
	return &pluginOpts{
		protocol: corev1.Service_Spec_Config_LLM_GEMINI,
		path:     geminiPath,
		body:     body,
	}
}

func newBedrockOpts(body string) *pluginOpts {
	return &pluginOpts{
		protocol: corev1.Service_Spec_Config_LLM_BEDROCK,
		path:     bedrockPath,
		body:     body,
	}
}

func upstreamParts(t *testing.T, upstream map[string]any, key string) []any {
	obj, ok := upstream[key].(map[string]any)
	assert.True(t, ok, key)
	parts, ok := obj["parts"].([]any)
	assert.True(t, ok, key)
	return parts
}

func partText(t *testing.T, part any) string {
	obj, ok := part.(map[string]any)
	assert.True(t, ok)
	ret, ok := obj["text"].(string)
	assert.True(t, ok)
	return ret
}

func TestPromptSystemGemini(t *testing.T) {
	{
		o := newGeminiOpts(geminiBody)
		o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("sys", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
				Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_{
					System: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System{
						Content: newContentValue("Governed by Octelium"),
					},
				},
			}),
		}

		res := servePlugins(t, o)

		assert.True(t, res.isNext)
		parts := upstreamParts(t, res.upstream, "systemInstruction")
		assert.Equal(t, 1, len(parts))
		assert.Equal(t, "Governed by Octelium", partText(t, parts[0]))
	}

	{
		o := newGeminiOpts(geminiSystemBody)
		o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("sys", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
				Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_{
					System: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System{
						Mode:    corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_PREPEND,
						Content: newContentValue("Governed by Octelium"),
					},
				},
			}),
		}

		res := servePlugins(t, o)

		parts := upstreamParts(t, res.upstream, "systemInstruction")
		assert.Equal(t, 2, len(parts))
		assert.Equal(t, "Governed by Octelium", partText(t, parts[0]))
		assert.Equal(t, "Be terse", partText(t, parts[1]))
	}

	{
		o := newGeminiOpts(geminiSystemBody)
		o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("sys", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
				Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_{
					System: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System{
						Mode: corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_STRIP,
					},
				},
			}),
		}

		res := servePlugins(t, o)

		_, ok := res.upstream["systemInstruction"]
		assert.False(t, ok)
	}
}

func TestPromptSystemBedrock(t *testing.T) {
	{
		o := newBedrockOpts(bedrockBody)
		o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("sys", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
				Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_{
					System: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System{
						Content: newContentValue("Governed by Octelium"),
					},
				},
			}),
		}

		res := servePlugins(t, o)

		assert.True(t, res.isNext)
		blocks, ok := res.upstream["system"].([]any)
		assert.True(t, ok)
		assert.Equal(t, 1, len(blocks))
		assert.Equal(t, "Governed by Octelium", partText(t, blocks[0]))
	}

	{
		o := newBedrockOpts(bedrockSystemBody)
		o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("sys", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
				Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_{
					System: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System{
						Mode:    corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_APPEND,
						Content: newContentValue("Governed by Octelium"),
					},
				},
			}),
		}

		res := servePlugins(t, o)

		blocks, ok := res.upstream["system"].([]any)
		assert.True(t, ok)
		assert.Equal(t, 2, len(blocks))
		assert.Equal(t, "Be terse", partText(t, blocks[0]))
		assert.Equal(t, "Governed by Octelium", partText(t, blocks[1]))
	}
}

func TestPromptMessageGemini(t *testing.T) {
	o := newGeminiOpts(geminiBody)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("msg", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
			Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_{
				Message: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message{
					Role:     corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_USER,
					Position: corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_APPEND,
					Content:  newContentValue("Answer in English"),
				},
			},
		}),
	}

	res := servePlugins(t, o)

	contents, ok := res.upstream["contents"].([]any)
	assert.True(t, ok)
	assert.Equal(t, 1, len(contents))

	msg, ok := contents[0].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "user", msg["role"])

	parts, ok := msg["parts"].([]any)
	assert.True(t, ok)
	assert.Equal(t, 2, len(parts))
	assert.Equal(t, "Hello", partText(t, parts[0]))
	assert.Equal(t, "Answer in English", partText(t, parts[1]))
}

func TestPromptMessageBedrock(t *testing.T) {
	o := newBedrockOpts(bedrockBody)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("msg", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
			Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_{
				Message: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message{
					Role:     corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_USER,
					Position: corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_AFTER,
					Content:  newContentValue("Answer in English"),
				},
			},
		}),
	}

	res := servePlugins(t, o)

	msgs, ok := res.upstream["messages"].([]any)
	assert.True(t, ok)
	assert.Equal(t, 2, len(msgs))

	inserted, ok := msgs[1].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "user", inserted["role"])

	blocks, ok := inserted["content"].([]any)
	assert.True(t, ok)
	assert.Equal(t, "Answer in English", partText(t, blocks[0]))
}

func TestPromptAssistantRoleGemini(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"Hello"}]},` +
		`{"role":"model","parts":[{"text":"Hi"}]},` +
		`{"role":"user","parts":[{"text":"Again"}]}]}`

	o := newGeminiOpts(body)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("msg", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
			Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_{
				Message: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message{
					Role:     corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_ASSISTANT,
					Position: corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_APPEND,
					Content:  newContentValue("(edited)"),
				},
			},
		}),
	}

	res := servePlugins(t, o)

	contents, ok := res.upstream["contents"].([]any)
	assert.True(t, ok)
	assert.Equal(t, 3, len(contents))

	msg, ok := contents[1].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "model", msg["role"])

	parts, ok := msg["parts"].([]any)
	assert.True(t, ok)
	assert.Equal(t, 2, len(parts))
	assert.Equal(t, "(edited)", partText(t, parts[1]))
}

func TestToolsGemini(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"Hello"}]}],` +
		`"tools":[{"functionDeclarations":[{"name":"read_file"},{"name":"rm_rf"}]}]}`

	o := newGeminiOpts(body)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("tools", &corev1.Service_Spec_Config_LLM_Plugin_Tools{
			Filters: []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter{
				{
					Match: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name{
						Name: "rm_*",
					},
					Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REMOVE,
				},
			},
		}),
	}

	res := servePlugins(t, o)

	groups, ok := res.upstream["tools"].([]any)
	assert.True(t, ok)
	assert.Equal(t, 1, len(groups))

	group, ok := groups[0].(map[string]any)
	assert.True(t, ok)

	decls, ok := group["functionDeclarations"].([]any)
	assert.True(t, ok)
	assert.Equal(t, 1, len(decls))

	decl, ok := decls[0].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "read_file", decl["name"])
}

func TestToolsBedrock(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"text":"Hello"}]}],` +
		`"toolConfig":{"tools":[{"toolSpec":{"name":"read_file"}},` +
		`{"toolSpec":{"name":"rm_rf"}}]}}`

	o := newBedrockOpts(body)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("tools", &corev1.Service_Spec_Config_LLM_Plugin_Tools{
			Filters: []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter{
				{
					Match: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name{
						Name: "rm_*",
					},
					Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_DENY,
				},
			},
		}),
	}

	res := servePlugins(t, o)

	assert.False(t, res.isNext)
	assert.Equal(t, http.StatusForbidden, res.code)
	assert.Contains(t, res.body, "this tool is not allowed")
	assert.NotContains(t, res.body, ErrCodeToolDenied)
}

func TestReasoningGemini(t *testing.T) {
	o := newGeminiOpts(geminiBody)
	o.reasoning = newReasoningLevelCfg(corev1.Service_Spec_Config_LLM_Reasoning_MEDIUM)

	res := servePlugins(t, o)

	cfg, ok := res.upstream["generationConfig"].(map[string]any)
	assert.True(t, ok)

	thinking, ok := cfg["thinkingConfig"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, float64(mediumReasoningBudget), thinking["thinkingBudget"])
}

func TestReasoningGeminiNone(t *testing.T) {
	o := newGeminiOpts(geminiBody)
	o.reasoning = newReasoningLevelCfg(corev1.Service_Spec_Config_LLM_Reasoning_NONE)

	res := servePlugins(t, o)

	cfg, ok := res.upstream["generationConfig"].(map[string]any)
	assert.True(t, ok)

	thinking, ok := cfg["thinkingConfig"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, float64(0), thinking["thinkingBudget"])
}

func TestReasoningGeminiPreservesGenerationConfig(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"Hello"}]}],` +
		`"generationConfig":{"temperature":0.5,"maxOutputTokens":128}}`

	o := newGeminiOpts(body)
	o.reasoning = newReasoningMaxTokensCfg(2048)

	res := servePlugins(t, o)

	cfg, ok := res.upstream["generationConfig"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, float64(0.5), cfg["temperature"])
	assert.Equal(t, float64(128), cfg["maxOutputTokens"])

	thinking, ok := cfg["thinkingConfig"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, float64(2048), thinking["thinkingBudget"])
}

func TestReasoningBedrock(t *testing.T) {
	o := newBedrockOpts(bedrockBody)
	o.reasoning = newReasoningLevelCfg(corev1.Service_Spec_Config_LLM_Reasoning_HIGH)

	res := servePlugins(t, o)

	fields, ok := res.upstream["additionalModelRequestFields"].(map[string]any)
	assert.True(t, ok)

	reasoning, ok := fields["reasoning_config"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "enabled", reasoning["type"])
	assert.Equal(t, float64(highReasoningBudget), reasoning["budget_tokens"])
}

func TestModelGemini(t *testing.T) {
	o := newGeminiOpts(geminiBody)
	o.model = &corev1.Service_Spec_Config_LLM_Model{
		Type: &corev1.Service_Spec_Config_LLM_Model_Value{Value: "gemini-2.5-flash"},
	}

	res := servePlugins(t, o)

	assert.True(t, res.isNext)
	assert.Equal(t, "gemini-2.5-pro", res.reqCtx.LLM.GetModel())
}

func TestGuardrailGemini(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"my key is ` +
		githubToken + `"}]}]}`

	o := newGeminiOpts(body)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("gr", &corev1.Service_Spec_Config_LLM_Plugin_Guardrail{
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				{
					Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets_{
						Secrets: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets{},
					},
					Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT,
				},
			},
		}),
	}

	res := servePlugins(t, o)

	assert.True(t, res.isNext)

	contents, ok := res.upstream["contents"].([]any)
	assert.True(t, ok)

	msg, ok := contents[0].(map[string]any)
	assert.True(t, ok)

	parts, ok := msg["parts"].([]any)
	assert.True(t, ok)
	assert.NotContains(t, partText(t, parts[0]), githubToken)
}

func TestGuardrailBedrockInstructions(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"text":"Hello"}]}],` +
		`"system":[{"text":"my key is ` + githubToken + `"}]}`

	o := newBedrockOpts(body)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("gr", &corev1.Service_Spec_Config_LLM_Plugin_Guardrail{
			Scopes: []corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope{
				corev1.Service_Spec_Config_LLM_Plugin_Guardrail_INSTRUCTIONS,
			},
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				{
					Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets_{
						Secrets: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets{},
					},
					Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY,
				},
			},
		}),
	}

	res := servePlugins(t, o)

	assert.False(t, res.isNext)
	assert.Equal(t, http.StatusForbidden, res.code)
	assert.Contains(t, res.body, "this content is not allowed")
}

func TestInvokeModelIsNotParsed(t *testing.T) {
	o := newBedrockOpts(`{"anthropic_version":"bedrock-2023-05-31"}`)
	o.path = "/model/anthropic.claude-sonnet-4-5-v1:0/invoke"
	o.reasoning = newReasoningLevelCfg(corev1.Service_Spec_Config_LLM_Reasoning_HIGH)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("sys", &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
			Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_{
				System: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System{
					Content: newContentValue("Governed by Octelium"),
				},
			},
		}),
	}

	res := servePlugins(t, o)

	assert.True(t, res.isNext)
	assert.Equal(t, "bedrock-2023-05-31", res.upstream["anthropic_version"])
	assert.Equal(t, 1, len(res.upstream))
}

func TestErrorShapeGemini(t *testing.T) {
	o := newGeminiOpts(geminiSystemBody)
	o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("gr", &corev1.Service_Spec_Config_LLM_Plugin_Guardrail{
			Scopes: []corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope{
				corev1.Service_Spec_Config_LLM_Plugin_Guardrail_INSTRUCTIONS,
			},
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				{
					Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex{
						Regex: "terse",
					},
					Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY,
				},
			},
			DenyMessage: "Not allowed here",
		}),
	}

	res := servePlugins(t, o)

	assert.False(t, res.isNext)
	assert.Equal(t, http.StatusForbidden, res.code)

	var body struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	assert.Nil(t, json.Unmarshal([]byte(res.body), &body))
	assert.NotNil(t, body.Error)
	assert.Equal(t, http.StatusForbidden, body.Error.Code)
	assert.Equal(t, "PERMISSION_DENIED", body.Error.Status)
	assert.Equal(t, "Not allowed here", body.Error.Message)
}

func TestUpstreamPathPrefixes(t *testing.T) {
	assert.Equal(t, "/v1",
		httputils.GetLLMVersionPrefix(corev1.Service_Spec_Config_LLM_OPENAI))
	assert.Equal(t, "/v1",
		httputils.GetLLMVersionPrefix(corev1.Service_Spec_Config_LLM_ANTHROPIC))
	assert.Equal(t, "/v1beta",
		httputils.GetLLMVersionPrefix(corev1.Service_Spec_Config_LLM_GEMINI))
	assert.Equal(t, "",
		httputils.GetLLMVersionPrefix(corev1.Service_Spec_Config_LLM_BEDROCK))
}

func TestToolsGeminiProviderHosted(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"Hello"}]}],` +
		`"tools":[{"googleSearch":{}},` +
		`{"functionDeclarations":[{"name":"read_file"},{"name":"rm_rf"}]}]}`

	{
		o := newGeminiOpts(body)
		o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tools", &corev1.Service_Spec_Config_LLM_Plugin_Tools{
				Filters: []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter{
					{
						Match: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Type{
							Type: "googleSearch",
						},
						Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_ALLOW,
					},
					{
						Match: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name{
							Name: "rm_*",
						},
						Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REMOVE,
					},
				},
			}),
		}

		res := servePlugins(t, o)

		groups, ok := res.upstream["tools"].([]any)
		assert.True(t, ok)
		assert.Equal(t, 2, len(groups))

		declGroup, ok := groups[0].(map[string]any)
		assert.True(t, ok)
		decls, ok := declGroup["functionDeclarations"].([]any)
		assert.True(t, ok)
		assert.Equal(t, 1, len(decls))

		hosted, ok := groups[1].(map[string]any)
		assert.True(t, ok)
		_, ok = hosted["googleSearch"]
		assert.True(t, ok)
	}

	{
		o := newGeminiOpts(body)
		o.plugins = []*corev1.Service_Spec_Config_LLM_Plugin{
			newPlugin("tools", &corev1.Service_Spec_Config_LLM_Plugin_Tools{
				Filters: []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter{
					{
						Match: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name{
							Name: "read_*",
						},
						Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_ALLOW,
					},
				},
			}),
		}

		res := servePlugins(t, o)

		groups, ok := res.upstream["tools"].([]any)
		assert.True(t, ok)
		assert.Equal(t, 1, len(groups))

		declGroup, ok := groups[0].(map[string]any)
		assert.True(t, ok)
		decls, ok := declGroup["functionDeclarations"].([]any)
		assert.True(t, ok)
		assert.Equal(t, 2, len(decls))

		for i, name := range []string{"read_file", "rm_rf"} {
			decl, ok := decls[i].(map[string]any)
			assert.True(t, ok)
			assert.Equal(t, name, decl["name"])
		}
	}
}
