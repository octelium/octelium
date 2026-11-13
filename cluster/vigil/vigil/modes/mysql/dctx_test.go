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

package mysql

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-mysql-org/go-mysql/server"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func newTestDctx(cfg *corev1.Service_Spec_Config_MySQL) *dctx {
	return &dctx{
		svcConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Mysql{
				Mysql: cfg,
			},
		},
	}
}

func TestGetLoggedQuery(t *testing.T) {
	{
		c := newTestDctx(&corev1.Service_Spec_Config_MySQL{})

		query, isTruncated := c.getLoggedQuery("SELECT 1")
		assert.Equal(t, "SELECT 1", query)
		assert.False(t, isTruncated)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_MySQL{
			Visibility: &corev1.Service_Spec_Config_MySQL_Visibility{
				DisableQuery: true,
			},
		})

		query, isTruncated := c.getLoggedQuery("SELECT 1")
		assert.Equal(t, "", query)
		assert.False(t, isTruncated)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_MySQL{})

		query, isTruncated := c.getLoggedQuery(strings.Repeat("a", maxLoggedQueryLen+100))
		assert.Len(t, query, maxLoggedQueryLen)
		assert.True(t, isTruncated)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_MySQL{
			Visibility: &corev1.Service_Spec_Config_MySQL_Visibility{
				DisableQuery: true,
			},
		})

		query, isTruncated := c.getLoggedQuery(strings.Repeat("a", maxLoggedQueryLen+100))
		assert.Equal(t, "", query)
		assert.False(t, isTruncated)
	}
}

func TestTruncateQuery(t *testing.T) {
	for _, arg := range []struct {
		query string
		out   string
	}{
		{"", ""},
		{"SELECT 1", "SELECT 1"},
		{strings.Repeat("a", maxLoggedQueryLen), strings.Repeat("a", maxLoggedQueryLen)},
		{strings.Repeat("a", maxLoggedQueryLen+1), strings.Repeat("a", maxLoggedQueryLen)},
	} {
		assert.Equal(t, arg.out, truncateQuery(arg.query))
	}

	{
		query := strings.Repeat("a", maxLoggedQueryLen-1) + "€"
		out := truncateQuery(query)
		assert.True(t, utf8.ValidString(out))
		assert.Equal(t, strings.Repeat("a", maxLoggedQueryLen-1), out)
	}
}

type tstSecretOcteliumC struct {
	octeliumc.ClientInterface
	rcorev1.ResourceServiceClient
	deadline time.Time
}

func (c *tstSecretOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c
}

func (c *tstSecretOcteliumC) GetSecret(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Secret, error) {
	c.deadline, _ = ctx.Deadline()
	return &corev1.Secret{
		Metadata: &metav1.Metadata{Name: in.Name},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{Value: "password"},
		},
	}, nil
}

func TestConnectUpstreamStalled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		canceled bool
	}{
		{"deadline", false},
		{"canceled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			timeout := time.Second
			if tc.canceled {
				timeout = time.Minute
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()

			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.Nil(t, err)
			defer lis.Close()

			acceptedCh := make(chan struct{})
			closedCh := make(chan struct{})
			go func() {
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				close(acceptedCh)
				io.Copy(io.Discard, conn)
				close(closedCh)
			}()

			if tc.canceled {
				go func() {
					select {
					case <-acceptedCh:
						cancel()
					case <-ctx.Done():
					}
				}()
			}

			octeliumC := &tstSecretOcteliumC{}
			secretMan, err := secretman.New(ctx, octeliumC, nil)
			require.Nil(t, err)

			c := newTestDctx(&corev1.Service_Spec_Config_MySQL{
				User:     "root",
				Database: "mysql",
				Auth: &corev1.Service_Spec_Config_MySQL_Auth{
					Type: &corev1.Service_Spec_Config_MySQL_Auth_Password_{
						Password: &corev1.Service_Spec_Config_MySQL_Auth_Password{
							Type: &corev1.Service_Spec_Config_MySQL_Auth_Password_FromSecret{
								FromSecret: "mysql-password",
							},
						},
					},
				},
			})
			c.svcConfig.Upstream = &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{
					Url: fmt.Sprintf("mysql://%s", lis.Addr().String()),
				},
			}
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Name: "mysql.default"},
				Spec:     &corev1.Service_Spec{Config: c.svcConfig},
				Status:   &corev1.Service_Status{},
			}
			c.secretMan = secretMan
			c.downstreamConnSQL = &server.Conn{}
			c.authResp = &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{Service: svc},
			}

			startedAt := time.Now()
			errCh := make(chan error, 1)
			go func() {
				errCh <- c.connect(ctx, loadbalancer.NewLbManager(nil, nil), svc, secretMan)
			}()

			select {
			case err := <-errCh:
				if tc.canceled {
					assert.ErrorIs(t, err, context.Canceled)
					assert.WithinRange(t, octeliumC.deadline,
						startedAt.Add(upstreamConnectTimeout), time.Now().Add(upstreamConnectTimeout))
				} else {
					assert.ErrorIs(t, err, context.DeadlineExceeded)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("connect did not return")
			}

			assert.Nil(t, c.upstreamConnSQL)

			select {
			case <-closedCh:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream conn was not closed")
			}
		})
	}
}
