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

package user

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestGetConnectionState(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	octeliumC := tst.C.OcteliumC

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	{
		sess := usrT.Session
		sess.Status.Connection = &corev1.Session_Status_Connection{}

		privateKey, err := wgtypes.GeneratePrivateKey()
		assert.Nil(t, err)

		_, ed25519Priv, err := ed25519.GenerateKey(nil)
		assert.Nil(t, err)

		resp, err := getConnectionState(ctx, tst.C.OcteliumC, sess, cc, privateKey, ed25519Priv)
		assert.Nil(t, err)

		zap.L().Debug("resp", zap.Any("resp", resp))
	}

}
