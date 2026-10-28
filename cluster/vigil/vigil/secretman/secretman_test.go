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

package secretman

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tstOAuthSrv struct {
	srv         *http.Server
	port        int
	accessToken string
}

func TestNamedKubernetesSecrets(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	for _, tc := range []struct {
		name string
		cfg  func(string) *corev1.Service_Spec_Config_Kubernetes
	}{
		{"Bearer", func(name string) *corev1.Service_Spec_Config_Kubernetes {
			return &corev1.Service_Spec_Config_Kubernetes{Type: &corev1.Service_Spec_Config_Kubernetes_BearerToken_{
				BearerToken: &corev1.Service_Spec_Config_Kubernetes_BearerToken{Type: &corev1.Service_Spec_Config_Kubernetes_BearerToken_FromSecret{FromSecret: name}},
			}}
		}},
		{"Kubeconfig", func(name string) *corev1.Service_Spec_Config_Kubernetes {
			return &corev1.Service_Spec_Config_Kubernetes{Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_{
				Kubeconfig: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig{Type: &corev1.Service_Spec_Config_Kubernetes_Kubeconfig_FromSecret{FromSecret: name}},
			}}
		}},
		{"ClientCertificate", func(name string) *corev1.Service_Spec_Config_Kubernetes {
			return &corev1.Service_Spec_Config_Kubernetes{Type: &corev1.Service_Spec_Config_Kubernetes_ClientCertificate{
				ClientCertificate: &corev1.Service_Spec_Config_ClientCertificate{Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{FromSecret: name}},
			}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vc, err := vcache.NewCache(t.Context())
			require.Nil(t, err)
			vc.SetService(&corev1.Service{Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{Type: &corev1.Service_Spec_Config_Kubernetes_{Kubernetes: tc.cfg("default-secret")}},
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{
					{Name: "alternate", Type: &corev1.Service_Spec_Config_Kubernetes_{Kubernetes: tc.cfg("alternate-secret")}},
				}},
			}})
			sm, err := New(t.Context(), tst.C.OcteliumC, vc)
			require.Nil(t, err)
			require.Nil(t, sm.ApplyService(t.Context()))
			assert.ElementsMatch(t, []string{"default-secret", "alternate-secret"}, sm.secretNames)
		})
	}
}

func TestOAuth2CacheKeyIsolation(t *testing.T) {
	base := &GetOAuth2CCTokenReq{ClientID: "client", SecretName: "secret", TokenURL: "https://issuer.example.com/token", Scopes: []string{"read-write", "admin"}}
	for _, tc := range []struct {
		name string
		req  *GetOAuth2CCTokenReq
	}{
		{"Client", &GetOAuth2CCTokenReq{ClientID: "other", SecretName: base.SecretName, TokenURL: base.TokenURL, Scopes: base.Scopes}},
		{"Secret", &GetOAuth2CCTokenReq{ClientID: base.ClientID, SecretName: "other", TokenURL: base.TokenURL, Scopes: base.Scopes}},
		{"URL", &GetOAuth2CCTokenReq{ClientID: base.ClientID, SecretName: base.SecretName, TokenURL: "https://other.example.com/token", Scopes: base.Scopes}},
		{"ScopeBoundaries", &GetOAuth2CCTokenReq{ClientID: base.ClientID, SecretName: base.SecretName, TokenURL: base.TokenURL, Scopes: []string{"read", "write-admin"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, base.getID(), tc.req.getID())
		})
	}
	t.Run("TokenEndpoint", func(t *testing.T) {
		sm, err := New(t.Context(), nil, nil)
		require.Nil(t, err)
		sm.c.Set("secret", &corev1.Secret{
			Metadata: &metav1.Metadata{Name: "secret", ResourceVersion: "1"},
			Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "password"}},
		}, 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !assert.Nil(t, r.ParseForm()) {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"token_type": "Bearer", "access_token": strings.ReplaceAll(r.Form.Get("scope"), " ", "_"), "expires_in": 3600,
			})
		}))
		defer srv.Close()
		for _, tc := range []struct {
			scopes []string
			want   string
		}{
			{[]string{"read-write", "admin"}, "read-write_admin"},
			{[]string{"read", "write-admin"}, "read_write-admin"},
		} {
			token, err := sm.GetOAuth2CCToken(t.Context(), &GetOAuth2CCTokenReq{
				ClientID: "client", SecretName: "secret", TokenURL: srv.URL, Scopes: tc.scopes,
			})
			require.Nil(t, err)
			assert.Equal(t, tc.want, token)
		}
	})
}

func TestOAuth2TokenRequestCancellation(t *testing.T) {
	sm, err := New(t.Context(), nil, nil)
	require.Nil(t, err)
	sm.c.Set("secret", &corev1.Secret{
		Metadata: &metav1.Metadata{Name: "secret", ResourceVersion: "1"},
		Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "password"}},
	}, 0)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token_type":"Bearer","access_token":"token","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sm.GetOAuth2CCToken(ctx, &GetOAuth2CCTokenReq{ClientID: "client", SecretName: "secret", TokenURL: srv.URL})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("The token request did not start")
	}
	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(250 * time.Millisecond):
		t.Error("The OAuth2 request did not stop after its caller was canceled")
	}
}

func TestSecretGenerationLifecycle(t *testing.T) {
	sm, err := New(t.Context(), nil, nil)
	require.Nil(t, err)
	secret := &corev1.Secret{Metadata: &metav1.Metadata{Name: "tracked"}}
	assert.Zero(t, sm.Generation())
	sm.Set(secret)
	assert.Zero(t, sm.Generation())
	sm.secretNames = []string{"tracked", "tracked", "other"}
	sm.Set(secret)
	assert.Equal(t, uint64(1), sm.Generation())
	sm.Delete(secret)
	assert.Equal(t, uint64(2), sm.Generation())
	assert.Equal(t, []string{"other"}, sm.secretNames)
	_, cached := sm.c.Get("tracked")
	assert.False(t, cached)
	sm.Delete(secret)
	assert.Equal(t, uint64(2), sm.Generation())
}

func (s *tstOAuthSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ret := map[string]any{
		"token_type":   "Bearer",
		"access_token": s.accessToken,
		"expires_in":   3600,
	}
	respBytes, _ := json.Marshal(&ret)
	w.Write(respBytes)
}

func (s *tstOAuthSrv) run(t *testing.T) {
	s.srv = &http.Server{
		Addr:    net.JoinHostPort("localhost", fmt.Sprintf("%d", s.port)),
		Handler: s,
	}

	lis, err := net.Listen("tcp", net.JoinHostPort("localhost", fmt.Sprintf("%d", s.port)))
	assert.Nil(t, err)
	go s.srv.Serve(lis)
}

func (s *tstOAuthSrv) close() {
	s.srv.Close()
	time.Sleep(1 * time.Second)
}

func TestSecretManager(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)

	secretMan, err := New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	vCache.SetService(svcV)

	err = secretMan.ApplyService(ctx)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(secretMan.secretNames))

	sec1, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(10),
			},
		},
	})
	assert.Nil(t, err)

	sec2, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(10),
			},
		},
	})
	assert.Nil(t, err)

	/*
		{
			svc.Spec.Config = &corev1.Service_Spec_Config{
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Auth: &corev1.Service_Spec_Config_HTTP_Auth{
							Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
								Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
									Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
										FromSecret: sec1.Metadata.Name,
									},
								},
							},
						},
					},
				},
			}

			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)

			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vigil.GetCache().SetService(svcV)

			err = secretMan.ApplyService(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 1, len(secretMan.secretNames))
			sec1V, err := secretMan.GetByName(ctx, sec1.Metadata.Name)
			assert.Nil(t, err)
			assert.True(t, pbutils.IsEqual(sec1, sec1V))

			_, err = secretMan.GetOAuth2CCToken(ctx, &GetOAuth2CCTokenReq{
				ClientID:   svc.Spec.Config.GetHttp().GetAuth().GetOauth2ClientCredentials().ClientID,
				TokenURL:   svc.Spec.Config.GetHttp().GetAuth().GetOauth2ClientCredentials().TokenURL,
				SecretName: sec1.Metadata.Name,
			})
			assert.NotNil(t, err)
		}
	*/

	{
		tstSrv := &tstOAuthSrv{
			port:        utilrand.GetRandomRangeMath(40000, 50000),
			accessToken: utilrand.GetRandomString(12),
		}
		tstSrv.run(t)
		defer tstSrv.close()

		time.Sleep(2 * time.Second)

		svc.Spec.Mode = corev1.Service_Spec_HTTP
		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{
					Url: "https://example.com",
				},
			},
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Auth: &corev1.Service_Spec_Config_HTTP_Auth{
						Type: &corev1.Service_Spec_Config_HTTP_Auth_Oauth2ClientCredentials{
							Oauth2ClientCredentials: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials{
								ClientID: utilrand.GetRandomStringCanonical(8),
								TokenURL: fmt.Sprintf("http://localhost:%d/oauth2/token", tstSrv.port),
								ClientSecret: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials_ClientSecret{
									Type: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials_ClientSecret_FromSecret{
										FromSecret: sec1.Metadata.Name,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)

		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		err = secretMan.ApplyService(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(secretMan.secretNames))
		sec1V, err := secretMan.GetByName(ctx, sec1.Metadata.Name)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(sec1, sec1V))

		accessToken, err := secretMan.GetOAuth2CCToken(ctx, &GetOAuth2CCTokenReq{
			ClientID:   svc.Spec.Config.GetHttp().GetAuth().GetOauth2ClientCredentials().ClientID,
			TokenURL:   svc.Spec.Config.GetHttp().GetAuth().GetOauth2ClientCredentials().TokenURL,
			SecretName: sec1.Metadata.Name,
		})
		assert.Nil(t, err)

		assert.Equal(t, tstSrv.accessToken, accessToken)
	}

	{

		svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
			Configs: []*corev1.Service_Spec_Config{
				{
					Name: "cfg01",

					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Auth: &corev1.Service_Spec_Config_HTTP_Auth{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
									Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
										Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
											FromSecret: sec2.Metadata.Name,
										},
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)

		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		err = secretMan.ApplyService(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 2, len(secretMan.secretNames))
		sec2V, err := secretMan.GetByName(ctx, sec2.Metadata.Name)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(sec2, sec2V))
	}
}

func TestUntrackedSecretIsRefreshedAndEvicted(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	vCache.SetService(svcV)

	secretMan, err := New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	err = secretMan.ApplyService(ctx)
	assert.Nil(t, err)

	sec, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(10),
			},
		},
	})
	assert.Nil(t, err)

	secV, err := secretMan.GetByName(ctx, sec.Metadata.Name)
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sec, secV))
	assert.Equal(t, 0, len(secretMan.secretNames))

	rotated := pbutils.Clone(sec).(*corev1.Secret)
	rotated.Data = &corev1.Secret_Data{
		Type: &corev1.Secret_Data_Value{
			Value: utilrand.GetRandomString(10),
		},
	}

	secretMan.Set(rotated)

	secV, err = secretMan.GetByName(ctx, sec.Metadata.Name)
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(rotated, secV))

	secretMan.Delete(rotated)

	_, isCached := secretMan.c.Get(sec.Metadata.Name)
	assert.False(t, isCached)
}

func TestUnreferencedSecretIsNotCached(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	vCache.SetService(svcV)

	secretMan, err := New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	err = secretMan.ApplyService(ctx)
	assert.Nil(t, err)

	secretMan.Set(&corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(10),
			},
		},
	})

	assert.Equal(t, 0, secretMan.c.ItemCount())
}

func TestOAuth2TokenSourceIsRebuiltOnRotation(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	vCache.SetService(svcV)

	secretMan, err := New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	err = secretMan.ApplyService(ctx)
	assert.Nil(t, err)

	tstSrv := &tstOAuthSrv{
		port:        tests.GetPort(),
		accessToken: utilrand.GetRandomString(12),
	}
	tstSrv.run(t)
	t.Cleanup(func() {
		tstSrv.close()
	})

	sec, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(10),
			},
		},
	})
	assert.Nil(t, err)

	req := &GetOAuth2CCTokenReq{
		ClientID:   utilrand.GetRandomStringCanonical(8),
		TokenURL:   fmt.Sprintf("http://localhost:%d/token", tstSrv.port),
		SecretName: sec.Metadata.Name,
	}

	accessToken, err := secretMan.GetOAuth2CCToken(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, tstSrv.accessToken, accessToken)

	tstSrv.accessToken = utilrand.GetRandomString(12)

	accessToken, err = secretMan.GetOAuth2CCToken(ctx, req)
	assert.Nil(t, err)
	assert.NotEqual(t, tstSrv.accessToken, accessToken)

	sec.Data = &corev1.Secret_Data{
		Type: &corev1.Secret_Data_Value{
			Value: utilrand.GetRandomString(10),
		},
	}
	sec, err = fakeC.OcteliumC.CoreC().UpdateSecret(ctx, sec)
	assert.Nil(t, err)

	secretMan.Set(sec)

	accessToken, err = secretMan.GetOAuth2CCToken(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, tstSrv.accessToken, accessToken)
}

func TestApplyServiceSurvivesMissingSecret(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	newSecret := func() *corev1.Secret {
		ret, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: utilrand.GetRandomString(10),
				},
			},
		})
		assert.Nil(t, err)
		return ret
	}

	newBearerCfg := func(name, secretName string) *corev1.Service_Spec_Config {
		return &corev1.Service_Spec_Config{
			Name: name,
			Upstream: &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{
					Url: "https://example.com",
				},
			},
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Auth: &corev1.Service_Spec_Config_HTTP_Auth{
						Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
							Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
									FromSecret: secretName,
								},
							},
						},
					},
				},
			},
		}
	}

	sec1 := newSecret()
	sec2 := newSecret()

	svc := tests.GenService("")
	svc.Spec.Mode = corev1.Service_Spec_HTTP
	svc.Spec.Config = newBearerCfg("", sec1.Metadata.Name)
	svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
		Configs: []*corev1.Service_Spec_Config{
			newBearerCfg("cfg01", sec2.Metadata.Name),
		},
	}

	svc, err = adminSrv.CreateService(ctx, svc)
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	secretMan, err := New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	err = secretMan.ApplyService(ctx)
	assert.Nil(t, err)
	assert.Equal(t, 2, secretMan.c.ItemCount())

	_, err = fakeC.OcteliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{
		Uid: sec1.Metadata.Uid,
	})
	assert.Nil(t, err)

	err = secretMan.ApplyService(ctx)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(secretMan.secretNames))

	assert.Equal(t, 1, secretMan.c.ItemCount())
	sec2V, err := secretMan.GetByName(ctx, sec2.Metadata.Name)
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sec2, sec2V))
}
