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

package authserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestDoAuthenticateWithPasskeyBegin(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	clusterCfg.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
		EnablePasskeyLogin: true,
	}

	clusterCfg, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, clusterCfg)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{

		res, err := srv.doAuthenticateWithPasskeyBegin(
			metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
				"user-agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
				"origin":     srv.rootURL,
			})),
			&authv1.AuthenticateWithPasskeyBeginRequest{})
		assert.Nil(t, err, "%+v", err)

		response := &protocol.PublicKeyCredentialRequestOptions{}

		err = json.Unmarshal([]byte(res.Request), response)
		assert.Nil(t, err)

		state, err := srv.loadPasskeyState(ctx, response.Challenge.String())
		assert.Nil(t, err)

		assert.Equal(t, response.Challenge.String(), state.Session.Challenge)
		assert.Equal(t, 32, len(response.Challenge))

		_, err = srv.loadPasskeyState(ctx, response.Challenge.String())
		assert.NotNil(t, err)
	}
}

const testBrowserUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"

func newWebCtx(srv *server) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
		"user-agent": testBrowserUserAgent,
		"origin":     srv.rootURL,
	}))
}

func TestCheckGRPCRequestIsWeb(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{
		err := srv.checkGRPCRequestIsWeb(context.Background())
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		err := srv.checkGRPCRequestIsWeb(metadata.NewIncomingContext(context.Background(),
			metadata.New(map[string]string{
				"user-agent": testBrowserUserAgent,
			})))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		err := srv.checkGRPCRequestIsWeb(metadata.NewIncomingContext(context.Background(),
			metadata.New(map[string]string{
				"user-agent": testBrowserUserAgent,
				"origin":     "https://evil.example.com",
			})))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		err := srv.checkGRPCRequestIsWeb(metadata.NewIncomingContext(context.Background(),
			metadata.New(map[string]string{
				"user-agent": testBrowserUserAgent,
				"origin":     fmt.Sprintf("%s.evil.com", srv.rootURL),
			})))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		err := srv.checkGRPCRequestIsWeb(metadata.NewIncomingContext(context.Background(),
			metadata.New(map[string]string{
				"origin": srv.rootURL,
			})))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		err := srv.checkGRPCRequestIsWeb(metadata.NewIncomingContext(context.Background(),
			metadata.New(map[string]string{
				"user-agent": "curl/8.0.1",
				"origin":     srv.rootURL,
			})))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		assert.Nil(t, srv.checkGRPCRequestIsWeb(newWebCtx(srv)))
	}
}

func TestDoAuthenticateWithPasskeyDisabled(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{
		_, err := srv.doAuthenticateWithPasskeyBegin(newWebCtx(srv),
			&authv1.AuthenticateWithPasskeyBeginRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	}

	{
		_, err := srv.doAuthenticateWithPasskey(newWebCtx(srv),
			&authv1.AuthenticateWithPasskeyRequest{
				Response: utilrand.GetRandomStringCanonical(200),
			})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	}
}

func TestDoAuthenticateWithPasskeyBeginValidation(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	clusterCfg.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
		EnablePasskeyLogin: true,
	}

	clusterCfg, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, clusterCfg)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{
		_, err := srv.doAuthenticateWithPasskeyBegin(newWebCtx(srv),
			&authv1.AuthenticateWithPasskeyBeginRequest{
				Query: utilrand.GetRandomStringCanonical(1200),
			})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		_, err := srv.doAuthenticateWithPasskeyBegin(newWebCtx(srv),
			&authv1.AuthenticateWithPasskeyBeginRequest{
				Query: "octelium_req=invalid",
			})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		_, err := srv.doAuthenticateWithPasskeyBegin(context.Background(),
			&authv1.AuthenticateWithPasskeyBeginRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		res, err := srv.doAuthenticateWithPasskeyBegin(newWebCtx(srv),
			&authv1.AuthenticateWithPasskeyBeginRequest{
				Query: "redirect=https%3A%2F%2Fexample.com",
			})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, len(res.Request) > 0)
	}
}

func TestPasskeyState(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{
		assert.Equal(t, "octelium:passkey:abc", getPasskeyKey("abc"))
		assert.NotEqual(t, getPasskeyKey("abc"), getPasskeyKey("abd"))
	}

	{
		_, err := srv.loadPasskeyState(ctx, utilrand.GetRandomStringCanonical(31))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.loadPasskeyState(ctx, utilrand.GetRandomStringCanonical(65))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.loadPasskeyState(ctx, "")
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.loadPasskeyState(ctx, strings.Repeat("日", 20))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.loadPasskeyState(ctx, utilrand.GetRandomStringCanonical(40))
		assert.NotNil(t, err)
	}

	{
		challenge := utilrand.GetRandomStringCanonical(43)

		err := srv.savePasskeyState(ctx, &passkeyState{
			Session: &webauthn.SessionData{
				Challenge: challenge,
			},
			Query: "redirect=https%3A%2F%2Fexample.com",
		})
		assert.Nil(t, err)

		state, err := srv.loadPasskeyState(ctx, challenge)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, challenge, state.Session.Challenge)
		assert.Equal(t, "redirect=https%3A%2F%2Fexample.com", state.Query)

		_, err = srv.loadPasskeyState(ctx, challenge)
		assert.NotNil(t, err)
	}
}

func TestDoAuthenticationWithPasskeyValidation(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{
		_, _, _, _, err := srv.doAuthenticationWithPasskey(ctx, "")
		assert.NotNil(t, err)
	}

	{
		_, _, _, _, err := srv.doAuthenticationWithPasskey(ctx, utilrand.GetRandomStringCanonical(99))
		assert.NotNil(t, err)
	}

	{
		_, _, _, _, err := srv.doAuthenticationWithPasskey(ctx, utilrand.GetRandomStringCanonical(5001))
		assert.NotNil(t, err)
	}

	{
		_, _, _, _, err := srv.doAuthenticationWithPasskey(ctx, strings.Repeat("日", 200))
		assert.NotNil(t, err)
	}

	{
		_, _, _, _, err := srv.doAuthenticationWithPasskey(ctx, utilrand.GetRandomStringCanonical(200))
		assert.NotNil(t, err)
	}
}
