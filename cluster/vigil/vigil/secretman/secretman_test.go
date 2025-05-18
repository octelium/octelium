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
)

type tstOAuthSrv struct {
	srv         *http.Server
	port        int
	accessToken string
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

	sec1, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
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

	sec2, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
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
