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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestConnect(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)
	{
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
		assert.Nil(t, err)

		usrT.Resync()

		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		assert.Nil(t, err)

		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		assert.Nil(t, err, "%+v", err)

		usrT.Resync()

		svc1, err := adminSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},

						User: usrT.Usr.Metadata.Name,
					},
				},
			},
		})
		assert.Nil(t, err)

		svc2, err := adminSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com:8443",
						},

						User: usrT.Usr.Metadata.Name,
					},
				},
			},
		})
		assert.Nil(t, err)

		resp, err := usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				ServeAll: true,
			},
		})
		assert.Nil(t, err)

		assert.NotNil(t, resp.GetState())

		assert.Equal(t, 2, len(resp.GetState().ServiceOptions.Services))

		assert.Equal(t, svc1.Metadata.Name, resp.GetState().ServiceOptions.Services[0].Name)
		assert.Equal(t, svc2.Metadata.Name, resp.GetState().ServiceOptions.Services[1].Name)
	}

}
