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

package wg

import (
	"context"
	"testing"

	osuser "os/user"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/gw"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func fakeNode(name string) *k8scorev1.Node {
	return &k8scorev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: name,
			UID:  types.UID(vutils.UUIDv4()),
		},

		Spec: k8scorev1.NodeSpec{},

		Status: k8scorev1.NodeStatus{},
	}
}

func TestWg(t *testing.T) {

	{
		usr, err := osuser.Current()
		assert.Nil(t, err)
		if usr.Uid != "0" {
			zap.L().Warn("Skipping this test since the running user is not root")
			return
		}
	}

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	node, err := fakeC.K8sC.CoreV1().Nodes().Create(ctx, fakeNode("node"), k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	privateKey, err := wgtypes.GeneratePrivateKey()
	assert.Nil(t, err)
	err = gw.InitGateway(ctx, []string{"1.2.3.4"}, node, fakeC.OcteliumC, 0, &metav1.ObjectReference{
		Name: "default",
		Uid:  vutils.UUIDv4(),
	}, privateKey)
	assert.NotNil(t, err, "%+v", err)

	wgC, err := New(ctx, node, fakeC.OcteliumC, privateKey)
	assert.Nil(t, err, "%+v", err)

	t.Run("basic", func(t *testing.T) {

		usrs := []*tstuser.User{}

		for i := 0; i < 5; i++ {
			usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
			assert.Nil(t, err)
			usrs = append(usrs, usr)
		}

		for j := 0; j < 5; j++ {
			usr := usrs[utilrand.GetRandomRangeMath(0, len(usrs)-1)]

			err = usr.Connect()
			assert.Nil(t, err)

			err = wgC.AddConnection(usr.Session)
			assert.Nil(t, err)

			device, err := wgC.client.Device(devName)
			assert.Nil(t, err)

			pubKey, err := wgtypes.NewKey(usr.Session.Status.Connection.X25519PublicKey)
			assert.Nil(t, err)

			peer := func() *wgtypes.Peer {
				for _, p := range device.Peers {
					if p.PublicKey.String() == pubKey.String() {
						return &p
					}
				}
				return nil
			}()

			assert.NotNil(t, peer)

			assert.Equal(t, pubKey.String(), peer.PublicKey.String())

		}

	})
}
