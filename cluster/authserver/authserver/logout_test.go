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
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
)

func TestDoLogout(t *testing.T) {

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

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		_, err := srv.doLogout(ctx, &authv1.LogoutRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err), "%+v", err)
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		_, err = srv.doLogout(getCtxRT(usrT), &authv1.LogoutRequest{})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Metadata.Uid,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		_, err = srv.doLogout(getCtxRT(usrT), &authv1.LogoutRequest{})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Metadata.Uid,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		logoutCtx := getCtxRT(usrT)

		_, err = srv.doLogout(logoutCtx, &authv1.LogoutRequest{})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doLogout(logoutCtx, &authv1.LogoutRequest{})
		assert.NotNil(t, err)
	}
}
