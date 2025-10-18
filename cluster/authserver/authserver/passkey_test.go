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
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
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
