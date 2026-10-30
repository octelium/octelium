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

package httputils

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newChecksummedLLMEventStreamMessage(t *testing.T, headers, payload []byte) []byte {
	t.Helper()
	frame := newLLMEventStreamMessage(t, headers, payload)
	binary.BigEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(frame[:8]))
	binary.BigEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
	return frame
}

func TestLLMEventStreamChecksumWireVectors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		frame   string
		payload []byte
	}{
		{name: "Empty", frame: "000000100000000005c248eb7d98c8ff"},
		{name: "Payload", frame: "0000001d00000000fd528c5a7b27666f6f273a27626172277dc3653936", payload: []byte("{'foo':'bar'}")},
		{name: "StringHeader", frame: "0000003d0000002007fd83960c636f6e74656e742d747970650700106170706c69636174696f6e2f6a736f6e7b27666f6f273a27626172277d8d9c08b1", payload: []byte("{'foo':'bar'}")},
		{name: "ZeroMessageCRC", frame: "0000001400000000f042ee2ba4b7197e00000000", payload: []byte{0xa4, 0xb7, 0x19, 0x7e}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := hex.DecodeString(tc.frame)
			require.Nil(t, err)
			original := bytes.Clone(frame)
			for size := range len(frame) {
				payload, n := NextLLMEventStreamMessage(frame[:size])
				assert.Zero(t, n, size)
				assert.Nil(t, payload, size)
				eventType, payload, n := NextLLMEventStreamEvent(frame[:size])
				assert.Zero(t, n, size)
				assert.Empty(t, eventType, size)
				assert.Nil(t, payload, size)
			}
			payload, n := NextLLMEventStreamMessage(frame)
			require.Equal(t, len(frame), n)
			assert.True(t, bytes.Equal(tc.payload, payload))
			if len(payload) > 0 {
				payload[0] ^= 1
			}
			eventType, payload, n := NextLLMEventStreamEvent(frame)
			require.Equal(t, len(frame), n)
			assert.Empty(t, eventType)
			assert.True(t, bytes.Equal(tc.payload, payload))
			if len(payload) > 0 {
				payload[0] ^= 1
			}
			assert.Equal(t, original, frame)
		})
	}
}

func TestLLMEventStreamChecksumsRejectEveryBitFlip(t *testing.T) {
	frame := EncodeLLMEventStreamEvent("contentBlockDelta", []byte(`{"delta":{"text":"hello"}}`))
	for pos := range frame {
		for bit := range 8 {
			corrupt := bytes.Clone(frame)
			corrupt[pos] ^= 1 << bit
			payload, n := NextLLMEventStreamMessage(corrupt)
			require.Equal(t, -1, n, "byte %d bit %d", pos, bit)
			assert.Nil(t, payload)
			eventType, payload, n := NextLLMEventStreamEvent(corrupt)
			require.Equal(t, -1, n, "byte %d bit %d", pos, bit)
			assert.Empty(t, eventType)
			assert.Nil(t, payload)
		}
	}
}

func TestLLMEventStreamChecksumLayers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "BadPreludeWithValidMessageCRC", mutate: func(frame []byte) {
			frame[8] ^= 1
			binary.BigEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
		}},
		{name: "ZeroPreludeWithValidMessageCRC", mutate: func(frame []byte) {
			binary.BigEndian.PutUint32(frame[8:12], 0)
			binary.BigEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
		}},
		{name: "LittleEndianPreludeWithValidMessageCRC", mutate: func(frame []byte) {
			binary.LittleEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(frame[:8]))
			binary.BigEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
		}},
		{name: "ZeroMessageCRC", mutate: func(frame []byte) {
			binary.BigEndian.PutUint32(frame[len(frame)-4:], 0)
		}},
		{name: "LittleEndianMessageCRC", mutate: func(frame []byte) {
			binary.LittleEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := EncodeLLMEventStreamEvent("contentBlockDelta", []byte(`{"delta":{"text":"hello"}}`))
			tc.mutate(frame)
			payload, n := NextLLMEventStreamMessage(frame)
			assert.Equal(t, -1, n)
			assert.Nil(t, payload)
			eventType, payload, n := NextLLMEventStreamEvent(frame)
			assert.Equal(t, -1, n)
			assert.Empty(t, eventType)
			assert.Nil(t, payload)
		})
	}
}

func TestLLMEventStreamPreludeValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		total   uint32
		headers uint32
		badCRC  bool
		want    int
	}{
		{name: "IncompleteMinimum", total: 16, want: 0},
		{name: "IncompleteMaximum", total: maxLLMEventStreamMessageLen, want: 0},
		{name: "IncompleteHeaders", total: 1024, headers: 1000, want: 0},
		{name: "TooShort", total: 15, want: -1},
		{name: "TooLarge", total: maxLLMEventStreamMessageLen + 1, want: -1},
		{name: "Uint32Total", total: 0xffffffff, want: -1},
		{name: "HeadersExceedFrame", total: 16, headers: 1, want: -1},
		{name: "Uint32Headers", total: 16, headers: 0xffffffff, want: -1},
		{name: "CorruptIncompletePrelude", total: 1024, badCRC: true, want: -1},
		{name: "CorruptMaximumPrelude", total: maxLLMEventStreamMessageLen, badCRC: true, want: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := binary.BigEndian.AppendUint32(nil, tc.total)
			frame = binary.BigEndian.AppendUint32(frame, tc.headers)
			checksum := crc32.ChecksumIEEE(frame)
			if tc.badCRC {
				checksum ^= 1
			}
			frame = binary.BigEndian.AppendUint32(frame, checksum)
			payload, n := NextLLMEventStreamMessage(frame)
			assert.Equal(t, tc.want, n)
			assert.Nil(t, payload)
			eventType, payload, n := NextLLMEventStreamEvent(frame)
			assert.Equal(t, tc.want, n)
			assert.Empty(t, eventType)
			assert.Nil(t, payload)
		})
	}
}

func TestLLMEventStreamChecksumFrameBoundaries(t *testing.T) {
	first := EncodeLLMEventStreamEvent("first", []byte("one"))
	second := EncodeLLMEventStreamEvent("second", []byte("two"))
	corrupt := bytes.Clone(second)
	corrupt[len(corrupt)-1] ^= 1
	for _, tail := range [][]byte{second, corrupt, second[:len(second)-1], []byte("arbitrary tail")} {
		joined := append(bytes.Clone(first), tail...)
		payload, n := NextLLMEventStreamMessage(joined)
		require.Equal(t, len(first), n)
		assert.Equal(t, "one", string(payload))
		eventType, payload, n := NextLLMEventStreamEvent(joined)
		require.Equal(t, len(first), n)
		assert.Equal(t, "first", eventType)
		assert.Equal(t, "one", string(payload))
	}
	for _, tc := range []struct {
		frame []byte
		want  int
	}{{second, len(second)}, {corrupt, -1}, {second[:len(second)-1], 0}} {
		joined := append(bytes.Clone(first), tc.frame...)
		_, n := NextLLMEventStreamMessage(joined[len(first):])
		assert.Equal(t, tc.want, n)
		_, _, n = NextLLMEventStreamEvent(joined[len(first):])
		assert.Equal(t, tc.want, n)
	}
	joined := append(corrupt, first...)
	_, n := NextLLMEventStreamMessage(joined)
	assert.Equal(t, -1, n)
	_, _, n = NextLLMEventStreamEvent(joined)
	assert.Equal(t, -1, n)
}

func TestLLMEventStreamMalformedHeadersWithValidChecksums(t *testing.T) {
	for _, headers := range [][]byte{
		{1},
		{10, 'a', llmEventStreamHeaderString},
		{1, 'a', 0},
		{1, 'a', llmEventStreamHeaderString, 0},
		{1, 'a', llmEventStreamHeaderString, 0, 10, 'x'},
	} {
		frame := newChecksummedLLMEventStreamMessage(t, headers, []byte("payload"))
		payload, n := NextLLMEventStreamMessage(frame)
		assert.Equal(t, len(frame), n)
		assert.Equal(t, "payload", string(payload))
		eventType, payload, n := NextLLMEventStreamEvent(frame)
		assert.Equal(t, -1, n)
		assert.Empty(t, eventType)
		assert.Nil(t, payload)
	}
}

func TestLLMEventStreamInvalidAndIncompleteAllocations(t *testing.T) {
	frame := EncodeLLMEventStreamEvent("contentBlockDelta", bytes.Repeat([]byte("x"), 64*1024))
	badPrelude := bytes.Clone(frame[:12])
	badPrelude[8] ^= 1
	badMessage := bytes.Clone(frame)
	badMessage[len(badMessage)-1] ^= 1
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{name: "ShortPrelude", frame: frame[:11]},
		{name: "PreludeOnly", frame: frame[:12]},
		{name: "IncompleteBody", frame: frame[:len(frame)-1]},
		{name: "BadPrelude", frame: badPrelude},
		{name: "BadMessage", frame: badMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Zero(t, testing.AllocsPerRun(100, func() {
				NextLLMEventStreamMessage(tc.frame)
			}))
			assert.Zero(t, testing.AllocsPerRun(100, func() {
				NextLLMEventStreamEvent(tc.frame)
			}))
		})
	}
}

func FuzzLLMEventStreamChecksums(f *testing.F) {
	f.Add("contentBlockDelta", []byte(`{"delta":{"text":"hello"}}`), uint32(8), byte(0))
	f.Add("metadata", []byte{}, uint32(0), byte(7))
	f.Add("", []byte{0, 1, 255}, uint32(12), byte(4))
	f.Fuzz(func(t *testing.T, eventType string, payload []byte, pos uint32, bit byte) {
		if len(eventType) > 256 || len(payload) > 16*1024 {
			t.Skip()
		}
		frame := EncodeLLMEventStreamEvent(eventType, payload)
		original := bytes.Clone(frame)
		decoded, n := NextLLMEventStreamMessage(frame)
		require.Equal(t, len(frame), n)
		assert.True(t, bytes.Equal(payload, decoded))
		kind, decoded, n := NextLLMEventStreamEvent(frame)
		require.Equal(t, len(frame), n)
		assert.Equal(t, eventType, kind)
		assert.True(t, bytes.Equal(payload, decoded))
		assert.Equal(t, original, frame)
		cut := int(pos % uint32(len(frame)))
		_, n = NextLLMEventStreamMessage(frame[:cut])
		assert.Zero(t, n)
		_, _, n = NextLLMEventStreamEvent(frame[:cut])
		assert.Zero(t, n)
		frame[cut] ^= 1 << (bit % 8)
		decoded, n = NextLLMEventStreamMessage(frame)
		assert.Equal(t, -1, n)
		assert.Nil(t, decoded)
		kind, decoded, n = NextLLMEventStreamEvent(frame)
		assert.Equal(t, -1, n)
		assert.Empty(t, kind)
		assert.Nil(t, decoded)
	})
}

func BenchmarkLLMEventStreamDecode(b *testing.B) {
	for _, size := range []int{0, 128, 4096, 65536, 1024 * 1024} {
		frame := EncodeLLMEventStreamEvent("contentBlockDelta", bytes.Repeat([]byte("x"), size))
		b.Run(fmt.Sprintf("Message/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(frame)))
			for b.Loop() {
				NextLLMEventStreamMessage(frame)
			}
		})
		b.Run(fmt.Sprintf("Event/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(frame)))
			for b.Loop() {
				NextLLMEventStreamEvent(frame)
			}
		})
	}
}

func BenchmarkLLMEventStreamPartialFrame(b *testing.B) {
	frame := EncodeLLMEventStreamEvent("contentBlockDelta", bytes.Repeat([]byte("x"), 1024*1024))
	for _, size := range []int{12, 65536, len(frame) - 1} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				NextLLMEventStreamMessage(frame[:size])
				NextLLMEventStreamEvent(frame[:size])
			}
		})
	}
}

func BenchmarkLLMEventStreamFrameValidation(b *testing.B) {
	for _, size := range []int{128, 4096, 65536, 1024 * 1024} {
		frame := EncodeLLMEventStreamEvent("contentBlockDelta", bytes.Repeat([]byte("x"), size))
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(frame)))
			for b.Loop() {
				nextLLMEventStreamFrame(frame)
			}
		})
	}
}

func parseLLM(t *testing.T, protocol corev1.Service_Spec_Config_LLM_Protocol,
	method, path, body string) *LLMRequest {

	req := httptest.NewRequest(method, "http://my-llm.example.com"+path,
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return ParseLLMRequest(req, protocol, []byte(body))
}

func TestMatchLLMRoute(t *testing.T) {

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodGet, "/v1/models")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_LIST, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodGet, "/v1/models/gpt-4o")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, operation)
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodGet, "/v1/chat/completions")
		assert.False(t, ok)
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/models/gpt-4o")
		assert.False(t, ok)
	}

	{
		for _, path := range []string{
			"/v1", "/v1/", "/v1/files", "/v1/chat", "/v1/chat/completions/x",
			"/v1/models/", "/v1/models/a/b", "/",
		} {
			_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
				http.MethodPost, path)
			assert.False(t, ok, path)
		}
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/messages")
		assert.False(t, ok)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/messages")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MESSAGES, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/messages/count_tokens")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_COUNT_TOKENS, operation)
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/chat/completions")
		assert.False(t, ok)
	}
}

func TestParseLLMRequestOpenAI(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello there"}]}`)

		assert.True(t, llmReq.IsKnownRoute)
		assert.True(t, llmReq.IsBodyValid)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS, llmReq.Route)
		assert.Equal(t, "gpt-4o", llmReq.Model)
		assert.False(t, llmReq.Stream)
		assert.Equal(t, uint32(1), llmReq.InputItemCount)
		assert.False(t, llmReq.HasTools)
		assert.Equal(t, corev1.RequestContext_Request_LLM_COMPLETE, llmReq.EstimateQuality)
		assert.True(t, llmReq.EstimatedInputTokens > 0)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","stream":true,"max_completion_tokens":512,
			"messages":[{"role":"system","content":"a"},{"role":"user","content":"b"}]}`)

		assert.True(t, llmReq.Stream)
		assert.Equal(t, uint64(512), llmReq.MaxOutputTokens)
		assert.Equal(t, uint32(2), llmReq.InputItemCount)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/responses",
			`{"model":"gpt-5","max_output_tokens":1024,"input":"Hello"}`)

		assert.Equal(t, corev1.RequestContext_Request_LLM_RESPONSES, llmReq.Route)
		assert.Equal(t, uint64(1024), llmReq.MaxOutputTokens)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],
			"tools":[
				{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}},
				{"type":"function","function":{"name":"add","parameters":{"type":"object"}}}]}`)

		assert.True(t, llmReq.HasTools)
		assert.Equal(t, uint32(2), llmReq.ToolCount)
		assert.Equal(t, []string{"add", "get_weather"}, llmReq.ToolNames)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],
			"some_brand_new_provider_option":{"a":1}}`)

		assert.True(t, llmReq.IsBodyValid)
		assert.Equal(t, "gpt-4o", llmReq.Model)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions", `[]`)
		assert.True(t, llmReq.IsKnownRoute)
		assert.True(t, llmReq.HasBody)
		assert.False(t, llmReq.IsBodyValid)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions", `not json`)
		assert.False(t, llmReq.IsBodyValid)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodGet, "/v1/models", "")
		assert.True(t, llmReq.IsKnownRoute)
		assert.False(t, llmReq.HasBody)
		assert.Equal(t, corev1.RequestContext_Request_LLM_UNAVAILABLE, llmReq.EstimateQuality)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/files", `{"model":"gpt-4o"}`)
		assert.False(t, llmReq.IsKnownRoute)
		assert.Empty(t, llmReq.Model)
	}
}

func TestParseLLMRequestAnthropic(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/messages",
			`{"model":"claude-sonnet-4","max_tokens":2048,"system":"Be brief",
			"messages":[{"role":"user","content":"Hello"}],
			"tools":[{"name":"bash","input_schema":{"type":"object"}}]}`)

		assert.True(t, llmReq.IsKnownRoute)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MESSAGES, llmReq.Route)
		assert.Equal(t, corev1.Service_Spec_Config_LLM_ANTHROPIC, llmReq.Protocol)
		assert.Equal(t, "claude-sonnet-4", llmReq.Model)
		assert.Equal(t, uint64(2048), llmReq.MaxOutputTokens)
		assert.Equal(t, uint32(1), llmReq.ToolCount)
		assert.Equal(t, []string{"bash"}, llmReq.ToolNames)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/messages",
			`{"model":"claude-sonnet-4","max_tokens":16,"messages":[{"role":"user",
			"content":[{"type":"image","source":{"type":"base64","media_type":"image/png",
			"data":"`+strings.Repeat("A", 64000)+`"}}]}]}`)

		assert.True(t, llmReq.HasImageInput)
		assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL, llmReq.EstimateQuality)

		assert.True(t, llmReq.EstimatedInputTokens < llmTokensPerImage+64)
		assert.True(t, llmReq.EstimatedInputTokens >= llmTokensPerImage)
	}
}

func TestLLMEstimate(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"`+
				strings.Repeat("a", 400)+`"}]}`)

		assert.True(t, llmReq.EstimatedInputTokens >= 100)
		assert.True(t, llmReq.EstimatedInputTokens < 130)
	}

	{
		ascii := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"m","messages":[{"role":"user","content":"`+
				strings.Repeat("a", 300)+`"}]}`)

		nonASCII := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"m","messages":[{"role":"user","content":"`+
				strings.Repeat("あ", 100)+`"}]}`)

		assert.True(t, nonASCII.EstimatedInputTokens > ascii.EstimatedInputTokens)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/embeddings",
			`{"model":"text-embedding-3-small","input":["a","b","c"]}`)

		assert.Equal(t, corev1.RequestContext_Request_LLM_EMBEDDINGS, llmReq.Route)
		assert.Equal(t, uint32(3), llmReq.InputItemCount)
	}
}

func TestParseLLMResponse(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-123","model":"gpt-4o-2024-11-20","object":"chat.completion",
			"choices":[{"finish_reason":"stop","message":{"content":"hi"}}],
			"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20,
			"prompt_tokens_details":{"cached_tokens":4}}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, "chatcmpl-123", msg.ResponseID)
		assert.Equal(t, "gpt-4o-2024-11-20", msg.Model)
		assert.Equal(t, "stop", msg.FinishReason)
		assert.True(t, msg.Usage.IsSet)
		assert.Equal(t, uint64(12), msg.Usage.InputTokens)
		assert.Equal(t, uint64(8), msg.Usage.OutputTokens)
		assert.Equal(t, uint64(20), msg.Usage.TotalTokens)
		assert.Equal(t, uint64(4), msg.Usage.CacheReadInputTokens)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-123","model":"gpt-4o","object":"chat.completion.chunk",
			"choices":[{"delta":{"content":"Hel"},"finish_reason":null}]}`))

		assert.NotNil(t, msg)
		assert.True(t, msg.HasContentDelta)
		assert.False(t, msg.Usage.IsSet)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5",
			"status":"completed","usage":{"input_tokens":30,"output_tokens":100,
			"total_tokens":130,"output_tokens_details":{"reasoning_tokens":64}}}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, "resp_1", msg.ResponseID)
		assert.Equal(t, "gpt-5", msg.Model)
		assert.Equal(t, "completed", msg.FinishReason)
		assert.Equal(t, uint64(30), msg.Usage.InputTokens)
		assert.Equal(t, uint64(100), msg.Usage.OutputTokens)
		assert.Equal(t, uint64(64), msg.Usage.ReasoningTokens)
	}

	{
		msg := ParseLLMResponse([]byte(`{"type":"response.output_text.delta","delta":"x"}`))
		assert.NotNil(t, msg)
		assert.True(t, msg.HasContentDelta)
	}

	{
		start := ParseLLMResponse([]byte(
			`{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4",
			"usage":{"input_tokens":25,"cache_read_input_tokens":10}}}`))

		assert.NotNil(t, start)
		assert.Equal(t, "msg_1", start.ResponseID)
		assert.Equal(t, "claude-sonnet-4", start.Model)
		assert.Equal(t, uint64(25), start.Usage.InputTokens)
		assert.Equal(t, uint64(10), start.Usage.CacheReadInputTokens)

		delta := ParseLLMResponse([]byte(
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},
			"usage":{"output_tokens":42}}`))

		assert.NotNil(t, delta)
		assert.Equal(t, "end_turn", delta.FinishReason)
		assert.Equal(t, uint64(42), delta.Usage.OutputTokens)
	}

	{
		msg := ParseLLMResponse([]byte(`{"type":"content_block_delta","index":0,
		"delta":{"type":"text_delta","text":"Hello"}}`))
		assert.NotNil(t, msg)
		assert.True(t, msg.HasContentDelta)
	}

	{
		assert.Nil(t, ParseLLMResponse([]byte("[DONE]")))
		assert.Nil(t, ParseLLMResponse([]byte("")))
		assert.Nil(t, ParseLLMResponse([]byte("not json")))
	}

	{
		assert.True(t, IsLLMStreamDone([]byte("[DONE]")))
		assert.True(t, IsLLMStreamDone([]byte(" [DONE] ")))
		assert.False(t, IsLLMStreamDone([]byte(`{"a":1}`)))
	}
}

func TestLLMUsageMerge(t *testing.T) {

	{
		usage := LLMUsage{}

		usage.Merge(ParseLLMResponse([]byte(
			`{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4",
			"usage":{"input_tokens":100,"cache_read_input_tokens":40,
			"cache_creation_input_tokens":25,"output_tokens":1}}}`)).Usage)

		usage.Merge(ParseLLMResponse([]byte(
			`{"type":"content_block_delta","index":0,
			"delta":{"type":"text_delta","text":"Hi"}}`)).Usage)

		usage.Merge(ParseLLMResponse([]byte(
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},
			"usage":{"output_tokens":50}}`)).Usage)

		assert.True(t, usage.IsSet)
		assert.Equal(t, uint64(100), usage.InputTokens)
		assert.Equal(t, uint64(50), usage.OutputTokens)
		assert.Equal(t, uint64(215), usage.TotalTokens)
		assert.Equal(t, uint64(40), usage.CacheReadInputTokens)
		assert.Equal(t, uint64(25), usage.CacheCreationInputTokens)
	}

	{
		usage := LLMUsage{}

		usage.Merge(ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"delta":{"content":"a"}}]}`)).Usage)

		assert.False(t, usage.IsSet)

		usage.Merge(ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}],
			"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`)).Usage)

		assert.True(t, usage.IsSet)
		assert.Equal(t, uint64(12), usage.InputTokens)
		assert.Equal(t, uint64(8), usage.OutputTokens)
		assert.Equal(t, uint64(20), usage.TotalTokens)
	}
}

func TestParseLLMRequestModelsGet(t *testing.T) {

	{
		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com/v1/models/gpt-4o", nil)

		llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_OPENAI, nil)

		assert.True(t, llmReq.IsKnownRoute)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, llmReq.Route)
		assert.Equal(t, "gpt-4o", llmReq.Model)
	}

	{
		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com/v1/models/claude-sonnet-4-20250514", nil)

		llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_ANTHROPIC, nil)

		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, llmReq.Route)
		assert.Equal(t, "claude-sonnet-4-20250514", llmReq.Model)
	}

	{
		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com/v1/models", nil)

		llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_OPENAI, nil)

		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_LIST, llmReq.Route)
		assert.Empty(t, llmReq.Model)
	}
}

func TestParseLLMRequestBounds(t *testing.T) {

	{
		model := strings.Repeat("a", maxLLMStringLen+1)
		body := fmt.Sprintf(`{"model":%q,"messages":[]}`, model)

		req := httptest.NewRequest(http.MethodPost,
			"http://my-llm.example.com/v1/chat/completions", strings.NewReader(body))

		llmReq := ParseLLMRequest(req,
			corev1.Service_Spec_Config_LLM_OPENAI, []byte(body))

		assert.True(t, llmReq.IsBodyValid)
		assert.Empty(t, llmReq.Model)
	}

	{
		name := strings.Repeat("b", maxLLMStringLen+1)
		body := fmt.Sprintf(
			`{"model":"gpt-4o","messages":[],"tools":[{"name":%q},{"name":"ok"}]}`, name)

		req := httptest.NewRequest(http.MethodPost,
			"http://my-llm.example.com/v1/chat/completions", strings.NewReader(body))

		llmReq := ParseLLMRequest(req,
			corev1.Service_Spec_Config_LLM_OPENAI, []byte(body))

		assert.Equal(t, uint32(2), llmReq.ToolCount)
		assert.Equal(t, []string{"ok"}, llmReq.ToolNames)
	}

	{
		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com"+llmModelsPrefix+strings.Repeat("c", maxLLMStringLen+1),
			nil)

		llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_OPENAI, nil)

		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, llmReq.Route)
		assert.Empty(t, llmReq.Model)
	}
}

func TestParseLLMResponseTerminalStatus(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"type":"response.in_progress","response":{"id":"resp_1","status":"in_progress"}}`))

		assert.NotNil(t, msg)
		assert.Empty(t, msg.FinishReason)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"type":"response.created","response":{"id":"resp_1","status":"queued"}}`))

		assert.NotNil(t, msg)
		assert.Empty(t, msg.FinishReason)
	}

	for _, status := range []string{"completed", "failed", "cancelled", "incomplete"} {
		msg := ParseLLMResponse([]byte(
			`{"type":"response.done","response":{"id":"resp_1","status":"` + status + `"}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, status, msg.FinishReason)
	}
}

func TestParseLLMRequestMaxOutputTokens(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[],"max_output_tokens":10,"max_tokens":100000}`)

		assert.Equal(t, uint64(100000), llmReq.MaxOutputTokens)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[],"max_completion_tokens":256}`)

		assert.Equal(t, uint64(256), llmReq.MaxOutputTokens)
	}
}

func TestLLMUsagePresence(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}],` +
				`"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`))

		assert.NotNil(t, msg)
		assert.True(t, msg.Usage.IsSet)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}]}`))

		assert.NotNil(t, msg)
		assert.False(t, msg.Usage.IsSet)
	}
}

func TestParseLLMResponseUsageNoProviderTotal(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","model":"llama-3","object":"chat.completion",
			"choices":[{"finish_reason":"stop","message":{"content":"hi"}}],
			"usage":{"prompt_tokens":100,"completion_tokens":50,
			"prompt_tokens_details":{"cached_tokens":40}}}`))

		assert.NotNil(t, msg)
		assert.True(t, msg.Usage.IsSet)
		assert.Equal(t, uint64(100), msg.Usage.InputTokens)
		assert.Equal(t, uint64(50), msg.Usage.OutputTokens)
		assert.Equal(t, uint64(40), msg.Usage.CacheReadInputTokens)
		assert.Equal(t, uint64(150), msg.Usage.TotalTokens)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"msg_1","model":"claude-sonnet-4","type":"message",
			"usage":{"input_tokens":100,"output_tokens":50,
			"cache_read_input_tokens":40,"cache_creation_input_tokens":25}}`))

		assert.NotNil(t, msg)
		assert.True(t, msg.Usage.IsSet)
		assert.Equal(t, uint64(215), msg.Usage.TotalTokens)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-2","model":"llama-3","object":"chat.completion",
			"choices":[{"finish_reason":"stop","message":{"content":"hi"}}],
			"usage":{"prompt_tokens":100,"completion_tokens":50,
			"completion_tokens_details":{"reasoning_tokens":30}}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, uint64(150), msg.Usage.TotalTokens)
	}
}

func TestMatchLLMRouteGemini(t *testing.T) {
	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_GENERATE_CONTENT, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:streamGenerateContent")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_GENERATE_CONTENT, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:countTokens")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_COUNT_TOKENS, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/text-embedding-004:embedContent")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_EMBED_CONTENT, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodGet, "/v1beta/models")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_LIST, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodGet, "/v1beta/models/gemini-2.5-pro")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, operation)
	}

	for _, path := range []string{
		"/v1/chat/completions",
		"/v1beta/models/gemini-2.5-pro:unknownVerb",
		"/v1beta/models/:generateContent",
		"/v1beta/models/nested/model:generateContent",
	} {
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, path)
		assert.False(t, ok, path)
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodGet, "/v1beta/models/gemini-2.5-pro:generateContent")
		assert.False(t, ok)
	}
}

func TestMatchLLMRouteBedrock(t *testing.T) {
	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost, "/model/anthropic.claude-sonnet-4-5-v1:0/converse")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CONVERSE, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost, "/model/anthropic.claude-sonnet-4-5-v1:0/converse-stream")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CONVERSE, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost, "/model/anthropic.claude-sonnet-4-5-v1:0/invoke")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_INVOKE_MODEL, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost,
			"/model/arn:aws:bedrock:us-east-1:1/inference-profile/us.anthropic.x/converse")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CONVERSE, operation)
	}

	for _, path := range []string{
		"/v1/chat/completions",
		"/model/anthropic.claude/unknown",
		"/model/converse",
	} {
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost, path)
		assert.False(t, ok, path)
	}
}

func TestParseLLMRequestGemini(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"Hello there"}]}],` +
		`"systemInstruction":{"parts":[{"text":"You are helpful"}]},` +
		`"generationConfig":{"maxOutputTokens":512},` +
		`"tools":[{"functionDeclarations":[` +
		`{"name":"get_weather","parameters":{"type":"object"}},` +
		`{"name":"send_email","parameters":{"type":"object"}}]}]}`

	req := httptest.NewRequest(http.MethodPost,
		"http://localhost/v1beta/models/gemini-2.5-pro:streamGenerateContent",
		strings.NewReader(body))

	llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_GEMINI, []byte(body))

	assert.True(t, llmReq.IsKnownRoute)
	assert.True(t, llmReq.IsBodyValid)
	assert.True(t, llmReq.Stream)
	assert.Equal(t, corev1.RequestContext_Request_LLM_GENERATE_CONTENT, llmReq.Route)
	assert.Equal(t, "gemini-2.5-pro", llmReq.Model)
	assert.Equal(t, uint64(512), llmReq.MaxOutputTokens)
	assert.True(t, llmReq.HasTools)
	assert.Equal(t, uint32(2), llmReq.ToolCount)
	assert.Equal(t, []string{"get_weather", "send_email"}, llmReq.ToolNames)
	assert.True(t, llmReq.EstimatedInputTokens > 0)
	assert.Equal(t, corev1.RequestContext_Request_LLM_COMPLETE, llmReq.EstimateQuality)
}

func TestParseLLMRequestInvalidMembers(t *testing.T) {

	tsts := []struct {
		protocol corev1.Service_Spec_Config_LLM_Protocol
		path     string
		body     string
	}{
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","MODEL":"gpt-small","messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"Model":"gpt-small","messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","model":"gpt-small","messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","model":"gpt-small","messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","max_tokens":100000,"MAX_TOKENS":10,"messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","stream":true,"Stream":false,"messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[],"TOOLS":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[{"role":"user","content":"a","content":"b"}]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			"{\"model\":\"gpt-big\xff\",\"messages\":[]}"},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[],"tools":[{"type":"function","function":{"name":"shell","NAME":"weather"}}]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[],"tools":[{"type":"function","Function":{"name":"shell"}}]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[],"tools":[{"type":"function","name":"weather","function":{"name":"shell"}}]}`},

		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":42,"messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","stream":"true","messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","max_tokens":"100000","messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","max_tokens":1e5,"messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","max_tokens":-1,"messages":[]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[],"tools":{"type":"function"}}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[],"tools":["shell"]}`},
		{corev1.Service_Spec_Config_LLM_OPENAI, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[],"tools":[{"name":5,"function":{"name":"shell"}}]}`},

		{corev1.Service_Spec_Config_LLM_ANTHROPIC, "/v1/messages",
			`{"model":"claude","max_tokens":10,"messages":[],"tools":[{"name":"web_search","Name":"x"}]}`},
		{corev1.Service_Spec_Config_LLM_GEMINI, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"contents":[],"generationConfig":{"maxOutputTokens":512,"MaxOutputTokens":10}}`},
		{corev1.Service_Spec_Config_LLM_GEMINI, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"contents":[],"tools":[{"FunctionDeclarations":[{"name":"shell"}]}]}`},
		{corev1.Service_Spec_Config_LLM_BEDROCK, "/model/anthropic.claude-sonnet-4-5-v1:0/converse",
			`{"messages":[],"inferenceConfig":{"maxTokens":900,"MAXTOKENS":10}}`},
		{corev1.Service_Spec_Config_LLM_BEDROCK, "/model/anthropic.claude-sonnet-4-5-v1:0/converse",
			`{"messages":[],"toolConfig":{"tools":[{"toolSpec":{"name":"shell","Name":"weather"}}]}}`},
	}

	for _, tst := range tsts {
		llmReq := parseLLM(t, tst.protocol, http.MethodPost, tst.path, tst.body)

		assert.True(t, llmReq.IsBodyValid, tst.body)
		assert.True(t, llmReq.HasInvalidMembers, tst.body)
	}
}

func TestParseLLMRequestExactMembers(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-big","messages":[{"role":"user","content":"Hello","Content":"x","MODEL":"y"}],`+
				`"metadata":{"Model":"z","model":"w"},`+
				`"tools":[{"type":"function","name":"shell","function":{"name":"shell",`+
				`"parameters":{"type":"object","properties":{"name":{},"Name":{}}}}}]}`)

		assert.True(t, llmReq.IsBodyValid)
		assert.False(t, llmReq.HasInvalidMembers)
		assert.Equal(t, "gpt-big", llmReq.Model)
		assert.Equal(t, []string{"shell"}, llmReq.ToolNames)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-big","stream":null,"max_tokens":null,"tools":null,"messages":[]}`)

		assert.False(t, llmReq.HasInvalidMembers)
		assert.Equal(t, "gpt-big", llmReq.Model)
		assert.False(t, llmReq.Stream)
		assert.Equal(t, uint64(0), llmReq.MaxOutputTokens)
		assert.False(t, llmReq.HasTools)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"model":42,"contents":[],"tools":[{"googleSearch":{}},{"functionDeclarations":[{"name":"get_weather"}]}]}`)

		assert.False(t, llmReq.HasInvalidMembers)
		assert.Equal(t, "gemini-2.5-pro", llmReq.Model)
		assert.Equal(t, uint32(2), llmReq.ToolCount)
		assert.Equal(t, []string{"get_weather"}, llmReq.ToolNames)
	}
}

func TestParseLLMRequestBedrock(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"text":"Hello there"}]}],` +
		`"system":[{"text":"You are helpful"}],` +
		`"inferenceConfig":{"maxTokens":900},` +
		`"toolConfig":{"tools":[{"toolSpec":{"name":"get_weather",` +
		`"inputSchema":{"json":{"type":"object"}}}}]}}`

	req := httptest.NewRequest(http.MethodPost,
		"http://localhost/model/anthropic.claude-sonnet-4-5-v1:0/converse-stream",
		strings.NewReader(body))

	llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_BEDROCK, []byte(body))

	assert.True(t, llmReq.IsKnownRoute)
	assert.True(t, llmReq.IsBodyValid)
	assert.True(t, llmReq.Stream)
	assert.Equal(t, corev1.RequestContext_Request_LLM_CONVERSE, llmReq.Route)
	assert.Equal(t, "anthropic.claude-sonnet-4-5-v1:0", llmReq.Model)
	assert.Equal(t, uint64(900), llmReq.MaxOutputTokens)
	assert.True(t, llmReq.HasTools)
	assert.Equal(t, uint32(1), llmReq.ToolCount)
	assert.Equal(t, []string{"get_weather"}, llmReq.ToolNames)
	assert.True(t, llmReq.EstimatedInputTokens > 0)
}

func TestParseLLMRequestInvokeModel(t *testing.T) {
	body := `{"anthropic_version":"bedrock-2023-05-31","messages":[]}`

	req := httptest.NewRequest(http.MethodPost,
		"http://localhost/model/anthropic.claude-sonnet-4-5-v1:0/invoke",
		strings.NewReader(body))

	llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_BEDROCK, []byte(body))

	assert.True(t, llmReq.IsKnownRoute)
	assert.False(t, llmReq.IsBodyValid)
	assert.Equal(t, corev1.RequestContext_Request_LLM_INVOKE_MODEL, llmReq.Route)
	assert.Equal(t, "anthropic.claude-sonnet-4-5-v1:0", llmReq.Model)
}

func TestParseLLMResponseGemini(t *testing.T) {
	body := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]},` +
		`"finishReason":"STOP"}],"modelVersion":"gemini-2.5-pro","responseId":"abc",` +
		`"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":22,` +
		`"thoughtsTokenCount":7,"totalTokenCount":40}}`

	res := ParseLLMResponse([]byte(body))
	assert.NotNil(t, res)
	assert.Equal(t, "gemini-2.5-pro", res.Model)
	assert.Equal(t, "abc", res.ResponseID)
	assert.Equal(t, "STOP", res.FinishReason)
	assert.True(t, res.HasContentDelta)
	assert.True(t, res.Usage.IsSet)
	assert.Equal(t, uint64(11), res.Usage.InputTokens)
	assert.Equal(t, uint64(29), res.Usage.OutputTokens)
	assert.Equal(t, uint64(7), res.Usage.ReasoningTokens)
	assert.Equal(t, uint64(40), res.Usage.TotalTokens)
}

func TestParseLLMResponseBedrock(t *testing.T) {
	{
		body := `{"output":{"message":{"role":"assistant","content":[{"text":"Hi"}]}},` +
			`"stopReason":"end_turn",` +
			`"usage":{"inputTokens":11,"outputTokens":22,"totalTokens":33}}`

		res := ParseLLMResponse([]byte(body))
		assert.NotNil(t, res)
		assert.Equal(t, "end_turn", res.FinishReason)
		assert.True(t, res.Usage.IsSet)
		assert.Equal(t, uint64(11), res.Usage.InputTokens)
		assert.Equal(t, uint64(22), res.Usage.OutputTokens)
		assert.Equal(t, uint64(33), res.Usage.TotalTokens)
	}

	{
		res := ParseLLMResponse([]byte(`{"delta":{"text":"Hello"}}`))
		assert.NotNil(t, res)
		assert.True(t, res.HasContentDelta)
	}

	{
		res := ParseLLMResponse([]byte(
			`{"usage":{"inputTokens":5,"outputTokens":6,"totalTokens":11}}`))
		assert.NotNil(t, res)
		assert.Equal(t, uint64(11), res.Usage.TotalTokens)
	}
}

func newLLMEventStreamMessage(t *testing.T, headers, payload []byte) []byte {
	total := 12 + len(headers) + len(payload) + 4
	ret := make([]byte, 0, total)

	ret = binary.BigEndian.AppendUint32(ret, uint32(total))
	ret = binary.BigEndian.AppendUint32(ret, uint32(len(headers)))
	ret = binary.BigEndian.AppendUint32(ret, crc32.ChecksumIEEE(ret))
	ret = append(ret, headers...)
	ret = append(ret, payload...)
	ret = binary.BigEndian.AppendUint32(ret, crc32.ChecksumIEEE(ret))

	assert.Equal(t, total, len(ret))

	return ret
}

func TestLLMEventStreamEventRoundTripAndFragmentation(t *testing.T) {
	payload := []byte(`{"delta":{"text":"hello"}}`)
	frame := EncodeLLMEventStreamEvent("contentBlockDelta", payload)
	assert.Equal(t, crc32.ChecksumIEEE(frame[:8]), binary.BigEndian.Uint32(frame[8:12]))
	assert.Equal(t, crc32.ChecksumIEEE(frame[:len(frame)-4]), binary.BigEndian.Uint32(frame[len(frame)-4:]))
	for size := range len(frame) {
		_, got, n := NextLLMEventStreamEvent(frame[:size])
		assert.Zero(t, n, size)
		assert.Nil(t, got)
	}
	joined := append(append([]byte(nil), frame...), frame...)
	for range 2 {
		eventType, got, n := NextLLMEventStreamEvent(joined)
		require.Equal(t, len(frame), n)
		assert.Equal(t, "contentBlockDelta", eventType)
		assert.Equal(t, payload, got)
		got[0] = '!'
		assert.Equal(t, byte('{'), joined[llmEventStreamPreludeLen+int(binary.BigEndian.Uint32(joined[4:8]))])
		joined = joined[n:]
	}
}

func TestLLMEventStreamMalformedHeaders(t *testing.T) {
	for _, headers := range [][]byte{
		{1},
		{10, 'a', llmEventStreamHeaderString},
		{1, 'a', 0},
		{1, 'a', llmEventStreamHeaderString, 0},
		{1, 'a', llmEventStreamHeaderString, 0, 10, 'x'},
	} {
		frame := newLLMEventStreamMessage(t, headers, []byte("payload"))
		_, _, n := NextLLMEventStreamEvent(frame)
		assert.Equal(t, -1, n)
	}
}

func TestLLMEventStreamHeaderCountLimit(t *testing.T) {
	var headers []byte
	for i := range maxLLMEventStreamHeaders + 1 {
		name := fmt.Sprintf("header-%d", i)
		headers = append(headers, byte(len(name)))
		headers = append(headers, name...)
		headers = append(headers, llmEventStreamHeaderString, 0, 1, 'x')
		_, ok := parseLLMEventStreamHeaders(headers)
		assert.Equal(t, i < maxLLMEventStreamHeaders, ok, "header count %d", i+1)
	}
}

func TestLLMEventStreamRejectsCorruptChecksums(t *testing.T) {
	for _, tc := range []struct {
		name string
		pos  func([]byte) int
	}{
		{"PreludeCRC", func(frame []byte) int { return 8 }},
		{"MessageCRC", func(frame []byte) int { return len(frame) - 1 }},
		{"Payload", func(frame []byte) int { return len(frame) - 5 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := EncodeLLMEventStreamEvent("contentBlockDelta", []byte(`{"text":"hi"}`))
			frame[tc.pos(frame)] ^= 1
			_, _, n := NextLLMEventStreamEvent(frame)
			assert.Equal(t, -1, n)
			_, n = NextLLMEventStreamMessage(frame)
			assert.Equal(t, -1, n)
		})
	}
}

func TestNextLLMEventStreamMessage(t *testing.T) {
	payload := []byte(`{"usage":{"inputTokens":5,"outputTokens":6,"totalTokens":11}}`)
	headers := []byte("\x0b:event-type")

	msg := newLLMEventStreamMessage(t, headers, payload)

	{
		out, n := NextLLMEventStreamMessage(msg)
		assert.Equal(t, len(msg), n)
		assert.Equal(t, string(payload), string(out))
	}

	{
		_, n := NextLLMEventStreamMessage(msg[:len(msg)-1])
		assert.Equal(t, 0, n)
	}

	{
		_, n := NextLLMEventStreamMessage(msg[:4])
		assert.Equal(t, 0, n)
	}

	{
		invalid := make([]byte, len(msg))
		copy(invalid, msg)
		binary.BigEndian.PutUint32(invalid[0:4], 3)
		_, n := NextLLMEventStreamMessage(invalid)
		assert.Equal(t, -1, n)
	}

	{
		invalid := make([]byte, len(msg))
		copy(invalid, msg)
		binary.BigEndian.PutUint32(invalid[4:8], uint32(len(msg)))
		_, n := NextLLMEventStreamMessage(invalid)
		assert.Equal(t, -1, n)
	}

	{
		two := append(append([]byte{}, msg...), msg...)
		out, n := NextLLMEventStreamMessage(two)
		assert.Equal(t, len(msg), n)
		assert.Equal(t, string(payload), string(out))

		out, n = NextLLMEventStreamMessage(two[n:])
		assert.Equal(t, len(msg), n)
		assert.Equal(t, string(payload), string(out))
	}
}

func TestSetLLMModelPath(t *testing.T) {

	{
		path, rawPath := SetLLMModelPath(corev1.Service_Spec_Config_LLM_GEMINI,
			"/v1beta/models/gemini-2.5-pro:generateContent", "gemini-2.5-flash")
		assert.Equal(t, "/v1beta/models/gemini-2.5-flash:generateContent", path)
		assert.Equal(t, path, rawPath)
	}

	{
		path, _ := SetLLMModelPath(corev1.Service_Spec_Config_LLM_GEMINI,
			"/v1beta/models/gemini-2.5-pro", "gemini-2.5-flash")
		assert.Equal(t, "", path)
	}

	{
		path, rawPath := SetLLMModelPath(corev1.Service_Spec_Config_LLM_BEDROCK,
			"/model/anthropic.claude-v1:0/converse-stream",
			"arn:aws:bedrock:us-east-1:1234:inference-profile/us.anthropic.claude")
		assert.Equal(t,
			"/model/arn:aws:bedrock:us-east-1:1234:inference-profile/"+
				"us.anthropic.claude/converse-stream", path)
		assert.Equal(t,
			"/model/arn:aws:bedrock:us-east-1:1234:inference-profile%2F"+
				"us.anthropic.claude/converse-stream", rawPath)
	}

	{
		path, _ := SetLLMModelPath(corev1.Service_Spec_Config_LLM_BEDROCK,
			"/model/anthropic.claude-v1:0", "anthropic.claude-v2:0")
		assert.Equal(t, "", path)
	}

	{
		path, _ := SetLLMModelPath(corev1.Service_Spec_Config_LLM_OPENAI,
			"/v1/chat/completions", "gpt-4o")
		assert.Equal(t, "", path)
	}
}

func TestNextLLMJSONArrayMessage(t *testing.T) {
	body := []byte(`[{"candidates":[{"content":{"parts":[{"text":"a]}"}]}}]},` +
		"\r\n" + `{"usageMetadata":{"totalTokenCount":11}}]`)

	var msgs []string
	for len(body) > 0 {
		payload, n := NextLLMJSONArrayMessage(body)
		assert.True(t, n > 0)
		body = body[n:]
		if len(payload) > 0 {
			msgs = append(msgs, string(payload))
		}
	}

	assert.Equal(t, 2, len(msgs))
	assert.Equal(t, `{"candidates":[{"content":{"parts":[{"text":"a]}"}]}}]}`, msgs[0])
	assert.Equal(t, `{"usageMetadata":{"totalTokenCount":11}}`, msgs[1])

	{
		_, n := NextLLMJSONArrayMessage([]byte(`[{"a":1`))
		assert.Equal(t, 0, n)
	}

	{
		_, n := NextLLMJSONArrayMessage([]byte(`data: {"a":1}`))
		assert.Equal(t, -1, n)
	}

	{
		_, n := NextLLMJSONArrayMessage([]byte("  \r\n"))
		assert.Equal(t, 4, n)
	}
}

func TestParseLLMRequestGeminiEmbed(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/text-embedding-004:embedContent",
			`{"content":{"parts":[{"text":"`+strings.Repeat("a", 400)+`"}]}}`)

		assert.True(t, llmReq.IsKnownRoute)
		assert.Equal(t, corev1.RequestContext_Request_LLM_EMBED_CONTENT,
			llmReq.Route)
		assert.Equal(t, "text-embedding-004", llmReq.Model)
		assert.True(t, llmReq.EstimatedInputTokens >= 100)
		assert.Equal(t, corev1.RequestContext_Request_LLM_COMPLETE,
			llmReq.EstimateQuality)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/text-embedding-004:batchEmbedContents",
			`{"requests":[{"model":"models/text-embedding-004","content":{"parts":`+
				`[{"text":"`+strings.Repeat("a", 400)+`"}]}}]}`)

		assert.Equal(t, uint32(1), llmReq.InputItemCount)
		assert.True(t, llmReq.EstimatedInputTokens >= 100)
	}
}

func TestParseLLMRequestGeminiOpaque(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"contents":[{"role":"user","parts":[{"text":"Hello"}]}],`+
				`"cachedContent":"cachedContents/abcd"}`)

		assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL,
			llmReq.EstimateQuality)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"contents":[{"role":"user","parts":[{"inline_data":`+
				`{"mime_type":"image/png","data":"`+strings.Repeat("A", 4000)+`"}}]}]}`)

		assert.True(t, llmReq.HasImageInput)
		assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL,
			llmReq.EstimateQuality)
		assert.True(t, llmReq.EstimatedInputTokens >= llmTokensPerImage)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"contents":[{"role":"user","parts":[{"fileData":`+
				`{"mimeType":"application/pdf","fileUri":"https://example.com/a.pdf"}}]}]}`)

		assert.False(t, llmReq.HasImageInput)
		assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL,
			llmReq.EstimateQuality)
	}
}

func TestParseLLMRequestBedrockDocument(t *testing.T) {
	llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_BEDROCK,
		http.MethodPost, "/model/anthropic.claude-v1:0/converse",
		`{"messages":[{"role":"user","content":[{"document":{"format":"pdf",`+
			`"name":"a","source":{"bytes":"`+strings.Repeat("A", 4000)+`"}}}]}]}`)

	assert.False(t, llmReq.HasImageInput)
	assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL, llmReq.EstimateQuality)
}

func TestParseLLMResponseToolNames(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"finish_reason":"tool_calls","message":
			{"tool_calls":[{"type":"function","function":{"name":"get_weather"}},
			{"type":"function","function":{"name":"get_time"}}]}}]}`))

		assert.NotNil(t, msg)
		assert.Equal(t, []string{"get_time", "get_weather"}, msg.ToolNames)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"type":"content_block_start","index":0,"content_block":
			{"type":"tool_use","id":"tu_1","name":"read_file"}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, []string{"read_file"}, msg.ToolNames)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"candidates":[{"content":{"parts":[{"functionCall":
			{"name":"lookup","args":{}}}]}}]}`))

		assert.NotNil(t, msg)
		assert.Equal(t, []string{"lookup"}, msg.ToolNames)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"output":{"message":{"content":[{"toolUse":
			{"toolUseId":"tu_1","name":"search"}}]}}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, []string{"search"}, msg.ToolNames)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"type":"response.output_item.added","item":
			{"type":"function_call","name":"run_query","call_id":"c1"}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, []string{"run_query"}, msg.ToolNames)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"finish_reason":"stop",
			"message":{"content":"hi"}}]}`))

		assert.NotNil(t, msg)
		assert.Empty(t, msg.ToolNames)
	}
}

func TestGetLLMOperation(t *testing.T) {
	for _, route := range []corev1.RequestContext_Request_LLM_Route{
		corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_RESPONSES,
		corev1.RequestContext_Request_LLM_COMPLETIONS,
		corev1.RequestContext_Request_LLM_MESSAGES,
		corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
		corev1.RequestContext_Request_LLM_CONVERSE,
	} {
		assert.Equal(t, corev1.Service_Spec_Config_LLM_GENERATE,
			GetLLMOperation(route))
	}

	for _, route := range []corev1.RequestContext_Request_LLM_Route{
		corev1.RequestContext_Request_LLM_EMBEDDINGS,
		corev1.RequestContext_Request_LLM_EMBED_CONTENT,
	} {
		assert.Equal(t, corev1.Service_Spec_Config_LLM_EMBED,
			GetLLMOperation(route))
	}

	assert.Equal(t, corev1.Service_Spec_Config_LLM_MODERATE,
		GetLLMOperation(corev1.RequestContext_Request_LLM_MODERATIONS))
	assert.Equal(t, corev1.Service_Spec_Config_LLM_COUNT_TOKENS,
		GetLLMOperation(corev1.RequestContext_Request_LLM_COUNT_TOKENS))
	assert.Equal(t, corev1.Service_Spec_Config_LLM_LIST_MODELS,
		GetLLMOperation(corev1.RequestContext_Request_LLM_MODELS_LIST))
	assert.Equal(t, corev1.Service_Spec_Config_LLM_GET_MODEL,
		GetLLMOperation(corev1.RequestContext_Request_LLM_MODELS_GET))
	assert.Equal(t, corev1.Service_Spec_Config_LLM_RAW_INFERENCE,
		GetLLMOperation(corev1.RequestContext_Request_LLM_INVOKE_MODEL))
	assert.Equal(t, corev1.Service_Spec_Config_LLM_OPERATION_UNSET,
		GetLLMOperation(corev1.RequestContext_Request_LLM_ROUTE_UNSET))
}

func TestGetLLMFinishReason(t *testing.T) {
	for _, arg := range []string{"stop", "end_turn", "STOP", "stop_sequence"} {
		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_STOP,
			GetLLMFinishReason(arg))
	}

	for _, arg := range []string{"length", "max_tokens", "MAX_TOKENS"} {
		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_LENGTH,
			GetLLMFinishReason(arg))
	}

	for _, arg := range []string{"tool_calls", "tool_use", "function_call"} {
		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_TOOL_CALL,
			GetLLMFinishReason(arg))
	}

	for _, arg := range []string{"content_filter", "SAFETY", "guardrail_intervened"} {
		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_CONTENT_FILTER,
			GetLLMFinishReason(arg))
	}

	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_ERROR,
		GetLLMFinishReason("error"))
	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_FINISH_REASON_UNSET,
		GetLLMFinishReason(""))
	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_OTHER,
		GetLLMFinishReason("something-new"))
}

func TestParseLLMResponseToolCallCount(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"message":{"tool_calls":[
			{"type":"function","function":{"name":"send_email"}},
			{"type":"function","function":{"name":"send_email"}},
			{"type":"function","function":{"name":"get_time"}}]}}]}`))

		assert.NotNil(t, msg)
		assert.Equal(t, []string{"get_time", "send_email"}, msg.ToolNames)
		assert.Equal(t, uint32(3), msg.ToolCallCount)
		assert.False(t, msg.IsToolNamesTruncated)
	}

	{
		var calls []string
		for i := range maxLLMToolNames + 4 {
			calls = append(calls, fmt.Sprintf(
				`{"type":"function","function":{"name":"tool_%d"}}`, i))
		}
		msg := ParseLLMResponse([]byte(fmt.Sprintf(
			`{"id":"chatcmpl-1","choices":[{"message":{"tool_calls":[%s]}}]}`,
			strings.Join(calls, ","))))

		assert.NotNil(t, msg)
		assert.Equal(t, maxLLMToolNames, len(msg.ToolNames))
		assert.Equal(t, uint32(maxLLMToolNames+4), msg.ToolCallCount)
		assert.True(t, msg.IsToolNamesTruncated)
	}
}
