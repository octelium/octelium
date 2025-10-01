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

package jsonschema

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)
	mdlwr, err := New(ctx, next, celEngine, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	{
		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Body:      []byte(`"k1": "v1"`),
				BodyJSONMap: map[string]any{
					"k1": "v1",
				},
				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema{
										JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
												Inline: schema,
											},
										},
									},
								},
							},
						},
					},
				},
			}))

		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, http.StatusBadRequest, rw.Code)
	}

	assert.Equal(t, 1, len(mdlwr.(*middleware).cMap))

	{
		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Body:      []byte(`"k1": "v1"`),
				BodyJSONMap: map[string]any{
					"id":       utilrand.GetRandomStringCanonical(8),
					"username": utilrand.GetRandomStringCanonical(8),
					"email":    fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
				},
				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema{
										JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
												Inline: schema,
											},
										},
									},
								},
							},
						},
					},
				},
			}))

		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, http.StatusBadRequest, rw.Code)
	}

	assert.Equal(t, 1, len(mdlwr.(*middleware).cMap))

	{
		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Body:      []byte(`"k1": "v1"`),
				BodyJSONMap: map[string]any{
					"id":       utilrand.GetRandomRangeMath(10, 1000),
					"username": utilrand.GetRandomStringCanonical(8),
					"email":    fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
				},
				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema{
										JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
												Inline: schema,
											},
										},
									},
								},
							},
						},
					},
				},
			}))

		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, http.StatusOK, rw.Code)
	}

	assert.Equal(t, 1, len(mdlwr.(*middleware).cMap))
}

const schema = `
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "User",
  "description": "A user in the system",
  "type": "object",
  "properties": {
    "id": {
      "description": "The unique identifier for the user",
      "type": "integer"
    },
    "username": {
      "description": "The user's username",
      "type": "string",
      "minLength": 3,
      "maxLength": 20,
      "pattern": "^[a-zA-Z0-9_]+$"
    },
    "email": {
      "description": "The user's email address",
      "type": "string",
      "format": "email"
    },
    "age": {
      "description": "Age in years",
      "type": "integer",
      "minimum": 13,
      "maximum": 120
    },
    "isActive": {
      "description": "Whether the user account is active",
      "type": "boolean",
      "default": true
    },
    "roles": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["admin", "editor", "viewer"]
      },
      "minItems": 1,
      "uniqueItems": true
    },
    "address": {
      "type": "object",
      "properties": {
        "street": { "type": "string" },
        "city": { "type": "string" },
        "state": { "type": "string" },
        "zip": { "type": "string", "pattern": "^\\d{5}(-\\d{4})?$" }
      },
      "required": ["street", "city", "zip"]
    }
  },
  "required": ["id", "username", "email"],
  "additionalProperties": false
}`
