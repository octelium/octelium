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
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
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

		tkn := fmt.Sprintf("Bearer %s", utilrand.GetRandomString(32))
		req.Header.Set("Authorization", tkn)

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				IsAnonymous: true,
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

		assert.Equal(t, tkn, req.Header.Get("Authorization"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		authHdr := fmt.Sprintf("Bearer %s", utilrand.GetRandomString(32))
		req.Header.Set("Authorization", authHdr)
		req.Header.Set("X-Octelium-Auth", utilrand.GetRandomString(32))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								AuthorizationMode: corev1.Service_Spec_Config_HTTP_Header_PASS,
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

		assert.Equal(t, authHdr, req.Header.Get("Authorization"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		authHdr := fmt.Sprintf("Bearer %s", utilrand.GetRandomString(32))
		req.Header.Set("Authorization", authHdr)
		req.Header.Set("X-Octelium-Auth", utilrand.GetRandomString(32))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								AuthorizationMode: corev1.Service_Spec_Config_HTTP_Header_DELETE,
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

		assert.Equal(t, "", req.Header.Get("Authorization"))
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
	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

		kubeCfg := &k8sutils.KubeConfig{
			Clusters: []k8sutils.KubeConfigCluster{
				{
					Name: "cluster-1",
				},
			},
			Users: []k8sutils.KubeConfigUser{
				{
					Name: "user-1",
					User: k8sutils.KubeConfigUserConfig{
						Token: utilrand.GetRandomString(32),
					},
				},
				{
					Name: "user-2",
					User: k8sutils.KubeConfigUserConfig{
						Token: utilrand.GetRandomString(32),
					},
				},
			},
			Contexts: []k8sutils.KubeConfigContext{
				{
					Name: "ctx-1",
					Context: k8sutils.KubeConfigContextConfig{
						Cluster: "cluster-1",
						User:    "user-1",
					},
				},
				{
					Name: "ctx-2",
					Context: k8sutils.KubeConfigContextConfig{
						Cluster: "cluster-1",
						User:    "user-2",
					},
				},
			},
		}

		kubeCfgYAML, err := kubeCfg.MarshalToYAML()
		assert.Nil(t, err)

		sec, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec:   &corev1.Secret_Spec{},
			Status: &corev1.Secret_Status{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: string(kubeCfgYAML),
				},
			},
		})
		assert.Nil(t, err)

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_KUBERNETES,
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Kubernetes_{
						Kubernetes: &corev1.Service_Spec_Config_Kubernetes{
							Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_{
								Kubeconfig: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig{
									Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_FromSecret{
										FromSecret: sec.Metadata.Name,
									},
									Context: "ctx-1",
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

		assert.Equal(t,
			kubeCfg.Users[0].User.Token,
			strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))

		{
			svc.Spec.Config.GetKubernetes().GetKubeconfig().Context = "ctx-2"
			req = req.WithContext(context.WithValue(context.Background(),
				middlewares.CtxRequestContext,
				&middlewares.RequestContext{
					CreatedAt:     time.Now(),
					Service:       svc,
					ServiceConfig: svc.Spec.Config,
				}))
			rw := httptest.NewRecorder()
			mdlwr.ServeHTTP(rw, req)

			assert.Equal(t,
				kubeCfg.Users[1].User.Token,
				strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
		}
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
				Mode: corev1.Service_Spec_KUBERNETES,
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Kubernetes_{
						Kubernetes: &corev1.Service_Spec_Config_Kubernetes{
							Type: &corev1.Service_Spec_Config_Kubernetes_BearerToken_{
								BearerToken: &corev1.Service_Spec_Config_Kubernetes_BearerToken{

									Type: &corev1.Service_Spec_Config_Kubernetes_BearerToken_FromSecret{
										FromSecret: sec.Metadata.Name,
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
}

func newScrubReqCtx(isManagedSvc bool, isAnonymous bool) *middlewares.RequestContext {
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "tst.default"},
		Spec:     &corev1.Service_Spec{IsAnonymous: isAnonymous},
		Status:   &corev1.Service_Status{},
	}
	if isManagedSvc {
		svc.Status.ManagedService = &corev1.Service_Status_ManagedService{Type: "authserver"}
	}

	return &middlewares.RequestContext{
		CreatedAt: time.Now(),
		Service:   svc,
		ReqCtxMap: map[string]any{},
	}
}

func newScrubRequest(t *testing.T, reqCtx *middlewares.RequestContext) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
	return req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext, reqCtx))
}

func TestOcteliumHeadersStrippedForOrdinaryServices(t *testing.T) {
	reqCtx := newScrubReqCtx(false, false)
	req := newScrubRequest(t, reqCtx)

	for _, name := range []string{
		"X-Octelium-Auth",
		"X-Octelium-Refresh-Token",
		"X-Octelium-Origin",
		"X-Octelium-Session-Ref",
		"X-Octelium-Session-Uid",
		"X-Octelium-Req-Path",
		"X-Octelium-Client-Address",
		"X-Octelium-Something-New",
	} {
		req.Header.Set(name, "downstream")
	}

	(&middleware{}).setRequestHeaders(req, reqCtx)

	for name := range req.Header {
		assert.False(t, isOcteliumHeader(name))
	}
}

func TestManagedServicesKeepOnlyAllowedHeaders(t *testing.T) {
	reqCtx := newScrubReqCtx(true, true)
	req := newScrubRequest(t, reqCtx)

	req.Header.Set("X-Octelium-Auth", "access-token")
	req.Header.Set("X-Octelium-Refresh-Token", "refresh-token")
	req.Header.Set(vutils.GetDownstreamIPHeaderCanonical(), "203.0.113.7")
	req.Header.Set("X-Octelium-Origin", "https://spoofed.example.com")
	req.Header.Set("X-Octelium-Session-Ref", `{"uid":"spoofed"}`)
	req.Header.Set("X-Octelium-Session-Uid", "spoofed")
	req.Header.Set("X-Octelium-Req-Path", "/spoofed")
	req.Header.Set("X-Octelium-Something-New", "spoofed")

	(&middleware{}).setRequestHeaders(req, reqCtx)

	assert.Equal(t, "access-token", req.Header.Get("X-Octelium-Auth"))
	assert.Equal(t, "refresh-token", req.Header.Get("X-Octelium-Refresh-Token"))
	assert.Equal(t, "203.0.113.7", req.Header.Get(vutils.GetDownstreamIPHeaderCanonical()))

	assert.Equal(t, "", req.Header.Get("X-Octelium-Origin"))
	assert.Equal(t, "", req.Header.Get("X-Octelium-Session-Ref"))
	assert.Equal(t, "", req.Header.Get("X-Octelium-Session-Uid"))
	assert.Equal(t, "", req.Header.Get("X-Octelium-Req-Path"))
	assert.Equal(t, "", req.Header.Get("X-Octelium-Something-New"))
}

func TestXOcteliumOriginNotForgeableWithoutOriginHeader(t *testing.T) {
	reqCtx := newScrubReqCtx(true, true)
	req := newScrubRequest(t, reqCtx)

	req.Header.Set("X-Octelium-Origin", "https://spoofed.example.com")

	(&middleware{}).setRequestHeaders(req, reqCtx)

	assert.Equal(t, "", req.Header.Get("X-Octelium-Origin"))
}

func TestXOcteliumOriginSetFromOriginHeader(t *testing.T) {
	reqCtx := newScrubReqCtx(true, true)
	req := newScrubRequest(t, reqCtx)

	req.Header.Set("X-Octelium-Origin", "https://spoofed.example.com")
	req.Header.Set("Origin", "https://real.example.com")

	(&middleware{}).setRequestHeaders(req, reqCtx)

	assert.Equal(t, "https://real.example.com", req.Header.Get("X-Octelium-Origin"))
}

func TestClientAddressStrippedForOrdinaryServices(t *testing.T) {
	reqCtx := newScrubReqCtx(false, false)
	req := newScrubRequest(t, reqCtx)
	req.Header.Set(vutils.GetDownstreamIPHeaderCanonical(), "203.0.113.7")

	(&middleware{}).setRequestHeaders(req, reqCtx)

	assert.Equal(t, "", req.Header.Get(vutils.GetDownstreamIPHeaderCanonical()))
}

func TestSessionHeadersAreSetByVigil(t *testing.T) {
	reqCtx := newScrubReqCtx(true, false)
	reqCtx.DownstreamInfo = &corev1.RequestContext{
		Session: &corev1.Session{
			Metadata: &metav1.Metadata{Uid: "real-session-uid", Name: "sess"},
		},
	}

	req := newScrubRequest(t, reqCtx)
	req.Header.Set("X-Octelium-Session-Uid", "spoofed")

	(&middleware{}).setRequestHeaders(req, reqCtx)

	assert.Equal(t, "real-session-uid", req.Header.Get("X-Octelium-Session-Uid"))
	assert.Equal(t, "/v1", req.Header.Get("X-Octelium-Req-Path"))
}

func TestScrubIsCaseInsensitive(t *testing.T) {
	reqCtx := newScrubReqCtx(false, false)
	req := newScrubRequest(t, reqCtx)

	req.Header["x-octelium-session-uid"] = []string{"spoofed"}
	req.Header["X-OCTELIUM-ORIGIN"] = []string{"spoofed"}

	(&middleware{}).setRequestHeaders(req, reqCtx)

	assert.Empty(t, req.Header["x-octelium-session-uid"])
	assert.Empty(t, req.Header["X-OCTELIUM-ORIGIN"])
}

func TestIsOcteliumHeader(t *testing.T) {
	for name, expected := range map[string]bool{
		"X-Octelium-Auth":    true,
		"x-octelium-auth":    true,
		"X-OCTELIUM-AUTH":    true,
		"X-Octelium-":        true,
		"X-Octelium":         false,
		"X-OcteliumFoo":      false,
		"Authorization":      false,
		"X-Forwarded-For":    false,
		"X-Octelium-Unknown": true,
	} {
		assert.Equal(t, expected, isOcteliumHeader(name), name)
	}
}

func newResponseHeaderCfg() *corev1.Service_Spec_Config {
	return &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Header: &corev1.Service_Spec_Config_HTTP_Header{
					AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
						{
							Key:  "X-Added",
							Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "yes"},
						},
					},
					RemoveResponseHeaders: []string{"X-Leak"},
				},
			},
		},
	}
}

func serveWithResponseCfg(t *testing.T, next http.Handler) *httptest.ResponseRecorder {
	t.Helper()

	reqCtx := newScrubReqCtx(false, false)
	reqCtx.ServiceConfig = newResponseHeaderCfg()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
	req = req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext, reqCtx))

	rw := httptest.NewRecorder()
	(&middleware{next: next}).ServeHTTP(rw, req)

	return rw
}

func TestResponseHeadersAppliedBeforeCommit(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Leak", "secret")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("body"))
	})

	res := serveWithResponseCfg(t, next).Result()

	assert.Equal(t, "yes", res.Header.Get("X-Added"))
	assert.Equal(t, "", res.Header.Get("X-Leak"))
	assert.Equal(t, "octelium", res.Header.Get("Server"))
}

func TestResponseHeadersAppliedOnImplicitWrite(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Leak", "secret")
		w.Write([]byte("body"))
	})

	res := serveWithResponseCfg(t, next).Result()

	assert.Equal(t, "yes", res.Header.Get("X-Added"))
	assert.Equal(t, "", res.Header.Get("X-Leak"))
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestResponseHeadersAppliedOnFlush(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Leak", "secret")
		w.(http.Flusher).Flush()
		w.Write([]byte("stream"))
	})

	res := serveWithResponseCfg(t, next).Result()

	assert.Equal(t, "yes", res.Header.Get("X-Added"))
	assert.Equal(t, "", res.Header.Get("X-Leak"))
}

func TestResponseHeadersAppliedWhenNothingWritten(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Leak", "secret")
	})

	rw := serveWithResponseCfg(t, next)

	assert.Equal(t, "yes", rw.Header().Get("X-Added"))
	assert.Equal(t, "", rw.Header().Get("X-Leak"))
}

func TestResponseStatusCodePreserved(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	res := serveWithResponseCfg(t, next).Result()

	assert.Equal(t, http.StatusTeapot, res.StatusCode)
	assert.Equal(t, "yes", res.Header.Get("X-Added"))
}

func TestRemoveOcteliumCookie(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		out     string
		present bool
	}{
		{
			name: "allOcteliumCookies",
			in:   "octelium_auth=a; octelium_rt=b",
		},
		{
			name:    "quotedValuePreserved",
			in:      `sess="quoted value"; octelium_auth=a`,
			out:     `sess="quoted value"`,
			present: true,
		},
		{
			name:    "unparseableCookieKept",
			in:      "a=1; bad name=2; b=3",
			out:     "a=1; bad name=2; b=3",
			present: true,
		},
		{
			name:    "octeliumRemovedOthersKept",
			in:      "a=1; octelium_auth=tkn; b=2; octelium_rt=rt; c=3",
			out:     "a=1; b=2; c=3",
			present: true,
		},
		{
			name:    "valueContainingEquals",
			in:      "a=1=2; octelium_auth=x",
			out:     "a=1=2",
			present: true,
		},
		{
			name:    "prefixNotMatched",
			in:      "octelium_auth_x=1; octelium_authy=2; octelium_auth=3",
			out:     "octelium_auth_x=1; octelium_authy=2",
			present: true,
		},
		{
			name:    "emptyValuePreserved",
			in:      "a=; octelium_rt=b",
			out:     "a=",
			present: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
			req.Header.Set("Cookie", tc.in)

			removeOcteliumCookie(req)

			got, present := req.Header["Cookie"]
			assert.Equal(t, tc.present, present)
			if tc.present {
				assert.Equal(t, []string{tc.out}, got)
			}
		})
	}
}

func TestRemoveOcteliumCookieNoCookieHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)

	removeOcteliumCookie(req)

	_, present := req.Header["Cookie"]
	assert.False(t, present)
}

func TestRemoveOcteliumCookieMultipleHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
	req.Header.Add("Cookie", "a=1; octelium_auth=x")
	req.Header.Add("Cookie", "octelium_rt=y")
	req.Header.Add("Cookie", "b=2")

	removeOcteliumCookie(req)

	assert.Equal(t, []string{"a=1", "b=2"}, req.Header["Cookie"])
}

func TestOcteliumCookiesKeptForManagedServices(t *testing.T) {
	reqCtx := newScrubReqCtx(true, true)
	req := newScrubRequest(t, reqCtx)
	req.Header.Set("Cookie", "a=1; octelium_auth=tkn")

	(&middleware{}).setRequestHeaders(req, reqCtx)

	assert.Equal(t, "a=1; octelium_auth=tkn", req.Header.Get("Cookie"))
}

func TestOcteliumCookiesRemovedForOrdinaryServices(t *testing.T) {
	reqCtx := newScrubReqCtx(false, false)
	req := newScrubRequest(t, reqCtx)
	req.Header.Set("Cookie", "a=1; octelium_auth=tkn")

	(&middleware{}).setRequestHeaders(req, reqCtx)

	assert.Equal(t, "a=1", req.Header.Get("Cookie"))
}

func TestMCPResponseHeaders(t *testing.T) {

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "my-mcp.default"},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_MCP,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}

	reqCtx := &middlewares.RequestContext{
		Service: svc,
		ServiceConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Mcp{
				Mcp: &corev1.Service_Spec_Config_MCP{
					Header: &corev1.Service_Spec_Config_HTTP_Header{
						AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
							{
								Key: "X-Octelium-Test",
								Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
									Value: "mcp",
								},
							},
						},
						RemoveResponseHeaders: []string{"X-Upstream-Internal"},
					},
				},
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://my-mcp.example.com/mcp", nil)
	req = req.WithContext(context.WithValue(
		req.Context(), middlewares.CtxRequestContext, reqCtx))

	hdr := http.Header{}
	hdr.Set("X-Upstream-Internal", "leak")

	md := &middleware{}
	md.modifyResponseHeaders(hdr, req, reqCtx)

	assert.Equal(t, "mcp", hdr.Get("X-Octelium-Test"))
	assert.Equal(t, "", hdr.Get("X-Upstream-Internal"))
}

func newLLMReqCtx(isAnonymous bool,
	cfg *corev1.Service_Spec_Config_LLM) *middlewares.RequestContext {

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "my-llm.default"},
		Spec: &corev1.Service_Spec{
			Mode:        corev1.Service_Spec_LLM,
			IsAnonymous: isAnonymous,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}

	svcCfg := &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Llm{Llm: cfg},
	}
	svc.Spec.Config = svcCfg

	return &middlewares.RequestContext{
		CreatedAt:     time.Now(),
		Service:       svc,
		ServiceConfig: svcCfg,
		ReqCtxMap:     map[string]any{},
	}
}

func TestLLMCredentialHeadersScrubbed(t *testing.T) {

	for _, isAnonymous := range []bool{false, true} {
		reqCtx := newLLMReqCtx(isAnonymous, &corev1.Service_Spec_Config_LLM{})
		req := newScrubRequest(t, reqCtx)

		req.Header.Set("Authorization", "Bearer sk-downstream")
		req.Header.Set("X-Api-Key", "sk-ant-downstream")
		req.Header.Set("api-key", "azure-downstream")
		req.Header.Set("User-Agent", "openai-python/1.0")

		assert.Nil(t, (&middleware{}).setRequestHeaders(req, reqCtx))

		assert.Empty(t, req.Header.Get("Authorization"))
		assert.Empty(t, req.Header.Get("X-Api-Key"))
		assert.Empty(t, req.Header.Get("Api-Key"))
		assert.Equal(t, "openai-python/1.0", req.Header.Get("User-Agent"))
	}

	{
		reqCtx := newLLMReqCtx(false, &corev1.Service_Spec_Config_LLM{
			Header: &corev1.Service_Spec_Config_HTTP_Header{
				AuthorizationMode: corev1.Service_Spec_Config_HTTP_Header_PASS,
			},
		})
		req := newScrubRequest(t, reqCtx)

		req.Header.Set("Authorization", "Bearer sk-downstream")
		req.Header.Set("X-Api-Key", "sk-ant-downstream")

		assert.Nil(t, (&middleware{}).setRequestHeaders(req, reqCtx))

		assert.Empty(t, req.Header.Get("Authorization"))
		assert.Empty(t, req.Header.Get("X-Api-Key"))
	}
}

func TestLLMUpstreamSecretFailsClosed(t *testing.T) {
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

	authS := &corev1.Service_Spec_Config_HTTP_Auth{
		Type: &corev1.Service_Spec_Config_HTTP_Auth_Custom_{
			Custom: &corev1.Service_Spec_Config_HTTP_Auth_Custom{
				Header: "X-Api-Key",
				Value: &corev1.Service_Spec_Config_HTTP_Auth_Custom_Value{
					Type: &corev1.Service_Spec_Config_HTTP_Auth_Custom_Value_FromSecret{
						FromSecret: "does-not-exist",
					},
				},
			},
		},
	}

	{
		reqCtx := newLLMReqCtx(false, &corev1.Service_Spec_Config_LLM{Auth: authS})
		req := newScrubRequest(t, reqCtx)
		req.Header.Set("X-Api-Key", "sk-ant-downstream")

		mdlwr := &middleware{secretMan: secretMan}
		assert.NotNil(t, mdlwr.setRequestHeaders(req, reqCtx))
		assert.Empty(t, req.Header.Get("X-Api-Key"))
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{Name: "my-http.default"},
			Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP},
			Status:   &corev1.Service_Status{},
		}
		svcCfg := &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{Auth: authS},
			},
		}
		svc.Spec.Config = svcCfg

		reqCtx := &middlewares.RequestContext{
			CreatedAt:     time.Now(),
			Service:       svc,
			ServiceConfig: svcCfg,
			ReqCtxMap:     map[string]any{},
		}
		req := newScrubRequest(t, reqCtx)

		mdlwr := &middleware{secretMan: secretMan}
		assert.Nil(t, mdlwr.setRequestHeaders(req, reqCtx))
	}
}
