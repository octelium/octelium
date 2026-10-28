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

package middlewares

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetRequestContextBody(t *testing.T) {

	{
		httpC := &corev1.RequestContext_Request_HTTP{}

		SetRequestContextBody(httpC, []byte(`{"model": "gpt"}`),
			map[string]any{"model": "gpt"})

		assert.Equal(t, []byte(`{"model": "gpt"}`), httpC.Body)
		assert.NotNil(t, httpC.BodyMap)
		assert.Equal(t, "gpt", httpC.BodyMap.GetFields()["model"].GetStringValue())
	}

	{
		httpC := &corev1.RequestContext_Request_HTTP{}

		SetRequestContextBody(httpC, []byte(`not json`), nil)

		assert.Equal(t, []byte(`not json`), httpC.Body)
		assert.Nil(t, httpC.BodyMap)
	}

	{
		httpC := &corev1.RequestContext_Request_HTTP{}

		SetRequestContextBody(httpC, nil, nil)

		assert.Nil(t, httpC.Body)
		assert.Nil(t, httpC.BodyMap)
	}

	{
		httpC := &corev1.RequestContext_Request_HTTP{}

		body := make([]byte, MaxReqCtxBodySize+1)

		SetRequestContextBody(httpC, body, map[string]any{"k": "v"})

		assert.Nil(t, httpC.Body)
		assert.Nil(t, httpC.BodyMap)
		assert.True(t, httpC.IsBodyOmitted)

		SetRequestContextBody(httpC, []byte(`{"k": "v"}`), map[string]any{"k": "v"})

		assert.Equal(t, []byte(`{"k": "v"}`), httpC.Body)
		assert.NotNil(t, httpC.BodyMap)
		assert.False(t, httpC.IsBodyOmitted)
	}

	{
		httpC := &corev1.RequestContext_Request_HTTP{}

		SetRequestContextBody(httpC, make([]byte, MaxReqCtxBodySize), nil)

		assert.NotNil(t, httpC.Body)
		assert.False(t, httpC.IsBodyOmitted)
	}

	{
		httpC := &corev1.RequestContext_Request_HTTP{
			Body:    []byte(`previous`),
			BodyMap: nil,
		}

		SetRequestContextBody(httpC, []byte(`[1, 2]`), nil)

		assert.Equal(t, []byte(`[1, 2]`), httpC.Body)
		assert.Nil(t, httpC.BodyMap)
	}
}

func TestChainOrderAndIsolation(t *testing.T) {
	var seen []string
	wrap := func(name string) Constructor {
		return func(next http.Handler) (http.Handler, error) {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = append(seen, name)
				next.ServeHTTP(w, r)
				seen = append(seen, name+"-done")
			}), nil
		}
	}
	base := New(wrap("first"))
	extended := base.Append(wrap("second")).Extend(New(wrap("third")))
	terminal := func(w http.ResponseWriter, r *http.Request) { seen = append(seen, "handler") }
	h, err := extended.ThenFunc(terminal)
	require.Nil(t, err)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, []string{"first", "second", "third", "handler", "third-done", "second-done", "first-done"}, seen)
	seen = nil
	h, err = base.ThenFunc(terminal)
	require.Nil(t, err)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, []string{"first", "handler", "first-done"}, seen)
}

func TestChainConstructorErrorAndDefault(t *testing.T) {
	wantErr := errors.New("constructor failed")
	h, err := New(func(next http.Handler) (http.Handler, error) { return nil, wantErr }).ThenFunc(nil)
	assert.ErrorIs(t, err, wantErr)
	assert.Nil(t, h)
	h, err = New().ThenFunc(nil)
	require.Nil(t, err)
	assert.Same(t, http.DefaultServeMux, h)
}

func TestRequestBodyDigestAndUpstreamOverride(t *testing.T) {
	r := &RequestContext{Body: []byte("original")}
	r.SetBodyDigest()
	assert.False(t, r.IsBodyChanged())
	assert.Equal(t, sha256.Sum256([]byte("original")), r.BodyDigest)
	r.Body = []byte("changed")
	assert.True(t, r.IsBodyChanged())
	assert.Equal(t, []byte("changed"), r.GetUpstreamBody())
	r.UpstreamBody = []byte{}
	assert.Empty(t, r.GetUpstreamBody())
	r.UpstreamBody = []byte("translated")
	assert.Equal(t, []byte("translated"), r.GetUpstreamBody())
}

func TestResponseCallbacksRunOnce(t *testing.T) {
	r := &RequestContext{}
	var seen []int
	r.AddOnResponse(func() { seen = append(seen, 1); r.RunOnResponse() })
	r.AddOnResponse(func() { seen = append(seen, 2) })
	r.RunOnResponse()
	r.RunOnResponse()
	assert.Equal(t, []int{1, 2}, seen)
}
