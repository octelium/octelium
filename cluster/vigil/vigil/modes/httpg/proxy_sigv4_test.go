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

package httpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type tstSigV4CoreClient struct {
	rcorev1.ResourceServiceClient
	secret *corev1.Secret
}

func (c *tstSigV4CoreClient) GetSecret(context.Context, *rmetav1.GetOptions, ...grpc.CallOption) (*corev1.Secret, error) {
	return c.secret, nil
}

type tstSigV4Client struct {
	octeliumc.ClientInterface
	core rcorev1.ResourceServiceClient
}

func (c *tstSigV4Client) CoreC() rcorev1.ResourceServiceClient { return c.core }

func TestProxySigV4EscapedPaths(t *testing.T) {
	for _, service := range []string{"s3", "lambda"} {
		t.Run(service, func(t *testing.T) {
			key := aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "example-secret"}
			body := []byte("binary\x00payload\xff")
			path := "/bucket/report%20a%2Bb%25.txt"
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, err := io.ReadAll(r.Body)
				assert.Nil(t, err)
				assert.Equal(t, body, got)
				assert.Equal(t, path, r.URL.EscapedPath())
				assert.Equal(t, service+".us-east-1.amazonaws.com", r.Host)
				hash := fmt.Sprintf("%x", sha256.Sum256(got))
				assert.Equal(t, hash, r.Header.Get("X-Amz-Content-Sha256"))
				authorization := r.Header.Get("Authorization")
				_, signed, ok := strings.Cut(authorization, "SignedHeaders=")
				if !assert.True(t, ok) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				signed, _, _ = strings.Cut(signed, ",")
				expected := r.Clone(r.Context())
				expected.Header = http.Header{}
				for _, name := range strings.Split(signed, ";") {
					if name != "host" {
						expected.Header.Set(name, r.Header.Get(name))
					}
				}
				date, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
				if !assert.Nil(t, err) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				err = v4.NewSigner().SignHTTP(r.Context(), key, expected, hash, service, "us-east-1", date,
					func(o *v4.SignerOptions) { o.DisableURIPathEscaping = service == "s3" })
				assert.Nil(t, err)
				if !assert.Equal(t, expected.Header.Get("Authorization"), authorization) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			cfg := &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: upstream.URL}},
				Type: &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
					Auth: &corev1.Service_Spec_Config_HTTP_Auth{Type: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4_{
						Sigv4: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4{
							AccessKeyID: key.AccessKeyID, Region: "us-east-1", Service: service,
							SecretAccessKey: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4_SecretAccessKey{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4_SecretAccessKey_FromSecret{FromSecret: "aws-key"},
							},
						},
					}},
					Header: &corev1.Service_Spec_Config_HTTP_Header{Host: &corev1.Service_Spec_Config_HTTP_Header_Host{
						Type: &corev1.Service_Spec_Config_HTTP_Header_Host_Value{Value: service + ".us-east-1.amazonaws.com"},
					}},
				}},
			}
			svc := newForwardedSvc(false)
			svc.Spec.Mode = corev1.Service_Spec_HTTP
			svc.Spec.Config = cfg
			cache, err := vcache.NewCache(t.Context())
			require.Nil(t, err)
			cache.SetService(svc)
			client := &tstSigV4Client{core: &tstSigV4CoreClient{secret: &corev1.Secret{
				Metadata: &metav1.Metadata{Name: "aws-key"},
				Data:     &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: key.SecretAccessKey}},
			}}}
			secrets, err := secretman.New(t.Context(), client, cache)
			require.Nil(t, err)
			require.Nil(t, secrets.ApplyService(t.Context()))
			s := &Server{secretMan: secrets, lbManager: loadbalancer.NewLbManager(client, cache), transports: newTransportCache()}
			defer s.transports.closeAll()
			reqCtx := &middlewares.RequestContext{
				Service: svc, ServiceConfig: cfg, Body: body,
				AuthResponse: &coctovigilv1.AuthenticateAndAuthorizeResponse{RequestContext: &corev1.RequestContext{Service: svc}, Config: cfg},
			}
			ctx := context.WithValue(t.Context(), middlewares.CtxRequestContext, reqCtx)
			proxy, err := s.getProxy(ctx)
			require.Nil(t, err)
			req := httptest.NewRequest(http.MethodPut, "https://public.example.com"+path+"?versionId=a%2Bb", bytes.NewReader(body)).WithContext(ctx)
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, "%s", rec.Body.String())
		})
	}
}
