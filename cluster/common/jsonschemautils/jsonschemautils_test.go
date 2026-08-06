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

package jsonschemautils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kaptinlin/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteRefIsNotFetched(t *testing.T) {
	var hits int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"type": "object"}`)
	}))
	defer srv.Close()

	schema := fmt.Sprintf(`{
		"type": "object",
		"properties": {"a": {"$ref": %q}}
	}`, srv.URL+"/evil.json")

	t.Run("loaderIsDenied", func(t *testing.T) {
		atomic.StoreInt64(&hits, 0)

		_, _ = NewCompiler().Compile([]byte(schema))

		assert.Equal(t, int64(0), atomic.LoadInt64(&hits))
	})

	t.Run("schemaIsRejected", func(t *testing.T) {
		atomic.StoreInt64(&hits, 0)

		_, err := Compile([]byte(schema))

		assert.ErrorContains(t, err, "points outside the schema")
		assert.Equal(t, int64(0), atomic.LoadInt64(&hits))
	})

	t.Run("unresolvedRefWouldOtherwiseAcceptAnything", func(t *testing.T) {
		compiled, err := NewCompiler().Compile([]byte(schema))
		require.Nil(t, err)

		assert.True(t, compiled.Validate(map[string]any{"a": "not-an-object"}).IsValid())
	})

	t.Run("upstreamStillFetches", func(t *testing.T) {
		atomic.StoreInt64(&hits, 0)

		_, _ = jsonschema.NewCompiler().Compile([]byte(schema))

		assert.Equal(t, int64(1), atomic.LoadInt64(&hits))
	})
}

func TestOversizedSchemaRejected(t *testing.T) {
	raw := []byte(`{"type":"object","description":"` +
		strings.Repeat("a", MaxSchemaBytes) + `"}`)

	_, err := NewCache().Compile(raw)

	assert.ErrorContains(t, err, "larger than")
}

func TestCacheReturnsSameSchema(t *testing.T) {
	raw := []byte(`{"type": "object", "required": ["a"]}`)

	c := NewCache()

	first, err := c.Compile(raw)
	require.Nil(t, err)

	second, err := c.Compile(raw)
	require.Nil(t, err)

	assert.Same(t, first, second)

	assert.True(t, first.Validate(map[string]any{"a": 1}).IsValid())
	assert.False(t, first.Validate(map[string]any{"b": 1}).IsValid())
}

func TestCacheMemoizesFailures(t *testing.T) {
	c := NewCache()

	_, first := c.Compile([]byte(`{"type": `))
	_, second := c.Compile([]byte(`{"type": `))

	assert.Error(t, first)
	assert.Equal(t, first, second)
}

func TestSchemaIDsDoNotLeakBetweenCompilations(t *testing.T) {
	c := NewCache()

	_, err := c.Compile([]byte(`{
		"$id": "https://octelium.example/shared",
		"type": "object",
		"properties": {"a": {"type": "string"}}
	}`))
	require.Nil(t, err)

	_, err = c.Compile([]byte(`{
		"type": "object",
		"properties": {"a": {"$ref": "https://octelium.example/shared"}}
	}`))

	assert.Error(t, err)
}

func TestSelfContainedRefsStillWork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		schema string
	}{
		{
			name: "localPointer",
			schema: `{
				"type": "object",
				"$defs": {"name": {"type": "string"}},
				"properties": {"a": {"$ref": "#/$defs/name"}},
				"required": ["a"]
			}`,
		},
		{
			name: "ownIDPointer",
			schema: `{
				"$id": "https://octelium.example/root",
				"type": "object",
				"$defs": {"name": {"type": "string"}},
				"properties": {"a": {"$ref": "https://octelium.example/root#/$defs/name"}},
				"required": ["a"]
			}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := Compile([]byte(tc.schema))
			require.Nil(t, err)

			assert.True(t, compiled.Validate(map[string]any{"a": "ok"}).IsValid())
			assert.False(t, compiled.Validate(map[string]any{"a": 1}).IsValid())
		})
	}
}
