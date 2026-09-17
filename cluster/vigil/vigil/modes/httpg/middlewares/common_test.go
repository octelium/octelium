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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
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
