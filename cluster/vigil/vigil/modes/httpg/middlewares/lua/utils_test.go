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

package lua

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

func TestLuaConversion(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	req := &corev1.RequestContext{
		Session: &corev1.Session{
			Metadata: &metav1.Metadata{
				Uid:       vutils.UUIDv4(),
				CreatedAt: pbutils.Now(),
				Tags:      []string{utilrand.GetRandomString(10), utilrand.GetRandomString(32)},
				Labels: map[string]string{
					utilrand.GetRandomString(10): utilrand.GetRandomString(10),
				},
				IsSystem: true,
			},
			Status: &corev1.Session_Status{
				TotalAuthentications: uint32(utilrand.GetRandomRangeMath(10, 10000)),
				Authentication: &corev1.Session_Status_Authentication{
					Info: &corev1.Session_Status_Authentication_Info{
						Type: corev1.Session_Status_Authentication_Info_AUTHENTICATOR,
						Details: &corev1.Session_Status_Authentication_Info_Authenticator_{
							Authenticator: &corev1.Session_Status_Authentication_Info_Authenticator{
								Type: corev1.Authenticator_Status_TOTP,
							},
						},
					},
				},
				Connection: &corev1.Session_Status_Connection{
					Ed25519PublicKey: utilrand.GetRandomBytesMust(32),
				},
			},
		},
	}

	reqMap := pbutils.MustConvertToMap(req)

	state := lua.NewState()
	lValue := toLuaValue(state, reqMap)

	resI := toGoValue(lValue)
	res, ok := resI.(map[string]any)
	assert.True(t, ok)

	req2 := &corev1.RequestContext{}
	err = pbutils.UnmarshalFromMap(res, req2)
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(req, req2))
}
