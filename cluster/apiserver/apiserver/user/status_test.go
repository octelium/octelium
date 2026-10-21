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
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetStatus(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usr, err := tstuser.NewUser(usrSrv.octeliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	resp, err := usrSrv.GetStatus(usr.Ctx(), &userv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, usr.Usr.Metadata.Name, resp.User.Metadata.Name)
}

func TestStatusProjection(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s, _ := newFakeServers(tst.C)
	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.Nil(t, err)
	_, err = s.GetStatus(t.Context(), &userv1.GetStatusRequest{})
	assert.NotNil(t, err)
	for _, typ := range []corev1.User_Spec_Type{corev1.User_Spec_HUMAN, corev1.User_Spec_WORKLOAD, corev1.User_Spec_TYPE_UNKNOWN} {
		for _, picture := range []string{"", "https://example.com/session.png"} {
			usr := &corev1.User{
				Metadata: &metav1.Metadata{Name: "user", Uid: "user-uid", DisplayName: "User", Labels: map[string]string{"private": "value"}},
				Spec:     &corev1.User_Spec{Type: typ, Email: "user@example.com"},
			}
			sess := &corev1.Session{Metadata: &metav1.Metadata{Name: "session", Uid: "session-uid", PicURL: picture}, Status: &corev1.Session_Status{
				Type: corev1.Session_Status_CLIENT, IsConnected: true,
				Authentication: &corev1.Session_Status_Authentication{Info: &corev1.Session_Status_Authentication_Info{
					Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{PicURL: "https://example.com/provider.png"}},
				}},
			}}
			ctx := context.WithValue(t.Context(), "octelium-user-ctx", &userctx.UserCtx{User: usr, Session: sess})
			got, err := s.GetStatus(ctx, &userv1.GetStatusRequest{})
			require.Nil(t, err)
			assert.Equal(t, cc.Status.Domain, got.Domain)
			assert.Equal(t, cc.Metadata.DisplayName, got.Cluster.Metadata.DisplayName)
			assert.Equal(t, usr.Metadata.Uid, got.User.Metadata.Uid)
			assert.Equal(t, userv1.GetStatusResponse_User_Spec_Type(typ), got.User.Spec.Type)
			assert.Equal(t, usr.Spec.Email, got.User.Spec.Email)
			assert.Nil(t, got.User.Metadata.Labels)
			assert.Nil(t, got.User.Metadata.SystemLabels)
			assert.True(t, got.Session.Status.IsConnected)
			assert.Equal(t, userv1.GetStatusResponse_Session_Status_CLIENT, got.Session.Status.Type)
			if picture == "" {
				assert.Equal(t, "https://example.com/provider.png", got.Session.Metadata.PicURL)
			} else {
				assert.Equal(t, picture, got.Session.Metadata.PicURL)
			}
		}
	}
}
