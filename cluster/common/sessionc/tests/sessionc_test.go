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

package sessionc

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/stretchr/testify/assert"
)

func TestCreateSession(t *testing.T) {

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
	usrSrv := user.NewServer(fakeC.OcteliumC)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	ccSpecs := []*corev1.ClusterConfig_Spec{
		{},
		{
			Session: &corev1.ClusterConfig_Spec_Session{
				Human: &corev1.ClusterConfig_Spec_Session_Human{
					ClientDuration: &metav1.Duration{
						Type: &metav1.Duration_Days{
							Days: 1,
						},
					},
				},
			},
		},
	}

	for _, ccSpec := range ccSpecs {
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		cc.Spec = ccSpec
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)

		{
			sess, err := sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
				OcteliumC: fakeC.OcteliumC,
				Usr:       usr.Usr,
				Device:    usr.Device,
				SessType:  corev1.Session_Status_CLIENT,
			})
			assert.Nil(t, err)

			assert.True(t, sess.Spec.ExpiresAt.IsValid())
			assert.True(t, sess.Spec.ExpiresAt.AsTime().After(time.Now()))
		}

	}

}
