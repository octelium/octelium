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

package headers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/common/pbutils"
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
	fakeC := tst.C

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Response", "octelium")
	})

	celEngine, err := celengine.New(ctx, nil)
	assert.Nil(t, err)
	mdlwr, err := New(ctx, next, celEngine, secretMan)
	assert.Nil(t, err)

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec:   &corev1.Service_Spec{},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))
		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		assert.Equal(t, "octelium", rw.Header().Get("X-Response"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", utilrand.GetRandomString(32)))
		req.Header.Set("X-Octelium-Auth", utilrand.GetRandomString(32))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec:   &corev1.Service_Spec{},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))
		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, "", req.Header.Get("Authorization"))
		assert.Equal(t, "", req.Header.Get("X-Octelium-Auth"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", utilrand.GetRandomString(32)))
		req.AddCookie(&http.Cookie{
			Name:  "octelium_auth",
			Path:  "/",
			Value: utilrand.GetRandomString(32),
		})
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Path:  "/",
			Value: utilrand.GetRandomString(32),
		})

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec:   &corev1.Service_Spec{},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))
		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		{
			_, err = req.Cookie("octelium_auth")
			assert.NotNil(t, err)
			assert.Equal(t, http.ErrNoCookie, err)
		}
		{
			_, err = req.Cookie("octelium_rt")
			assert.NotNil(t, err)
			assert.Equal(t, http.ErrNoCookie, err)
		}
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		req.Header.Set("X-Del-1", fmt.Sprintf("Bearer %s", utilrand.GetRandomString(32)))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								AddRequestHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
									{
										Key: "X-Set-1",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
											Value: utilrand.GetRandomString(32),
										},
									},
									{
										Key: "X-Set-2",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
											Value: utilrand.GetRandomString(32),
										},
									},
									{
										Key: "X-Service-Name",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval{
											Eval: `ctx.service.metadata.name`,
										},
									},
								},

								RemoveRequestHeaders: []string{
									"X-Del-1",
								},

								AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
									{
										Key: "X-Set-3",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
											Value: utilrand.GetRandomString(32),
										},
									},
									{
										Key: "X-Set-4",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
											Value: utilrand.GetRandomString(32),
										},
									},
									{
										Key: "X-Service-Name",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval{
											Eval: `ctx.service.metadata.name`,
										},
									},
								},

								RemoveResponseHeaders: []string{
									"X-Response",
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
				ReqCtxMap: map[string]any{
					"ctx": map[string]any{
						"service": pbutils.MustConvertToMap(svc),
					},
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, "", req.Header.Get("X-Del-1"))

		assert.Equal(t, svc.Spec.Config.GetHttp().Header.AddRequestHeaders[0].GetValue(), req.Header.Get("X-Set-1"))
		assert.Equal(t, svc.Spec.Config.GetHttp().Header.AddRequestHeaders[1].GetValue(), req.Header.Get("X-Set-2"))
		assert.Equal(t, svc.Metadata.Name, req.Header.Get("X-Service-Name"))
		assert.Equal(t, svc.Spec.Config.GetHttp().Header.AddResponseHeaders[0].GetValue(), rw.Header().Get("X-Set-3"))
		assert.Equal(t, svc.Spec.Config.GetHttp().Header.AddResponseHeaders[1].GetValue(), rw.Header().Get("X-Set-4"))
		assert.Equal(t, svc.Metadata.Name, rw.Header().Get("X-Service-Name"))
		assert.Equal(t, "", rw.Header().Get("X-Response"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		sec, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec:   &corev1.Secret_Spec{},
			Status: &corev1.Secret_Status{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: utilrand.GetRandomString(32),
				},
			},
		})
		assert.Nil(t, err)

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Auth: &corev1.Service_Spec_Config_HTTP_Auth{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
									Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
										Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
											FromSecret: sec.Metadata.Name,
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))
		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, sec.Data.GetValue(), strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		sec, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec:   &corev1.Secret_Spec{},
			Status: &corev1.Secret_Status{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: utilrand.GetRandomString(32),
				},
			},
		})
		assert.Nil(t, err)

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Auth: &corev1.Service_Spec_Config_HTTP_Auth{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Custom_{
									Custom: &corev1.Service_Spec_Config_HTTP_Auth_Custom{
										Header: "X-Auth-Custom",
										Value: &corev1.Service_Spec_Config_HTTP_Auth_Custom_Value{
											Type: &corev1.Service_Spec_Config_HTTP_Auth_Custom_Value_FromSecret{
												FromSecret: sec.Metadata.Name,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))
		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, sec.Data.GetValue(), req.Header.Get("X-Auth-Custom"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		sec, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec:   &corev1.Secret_Spec{},
			Status: &corev1.Secret_Status{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: utilrand.GetRandomString(32),
				},
			},
		})
		assert.Nil(t, err)

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Auth: &corev1.Service_Spec_Config_HTTP_Auth{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
									Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
										Username: utilrand.GetRandomStringCanonical(12),
										Password: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password{
											Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password_FromSecret{
												FromSecret: sec.Metadata.Name,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))
		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		valBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
		assert.Nil(t, err)

		vals := strings.Split(string(valBytes), ":")
		assert.Equal(t, svc.Spec.Config.GetHttp().Auth.GetBasic().Username, vals[0])
		assert.Equal(t, sec.Data.GetValue(), vals[1])
	}
}
