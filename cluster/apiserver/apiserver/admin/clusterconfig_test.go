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

package admin

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestClusterConfig(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv := NewServer(&Opts{
		OcteliumC: tst.C.OcteliumC,
	})

	cc, err := srv.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
	assert.Nil(t, err)

	assert.Nil(t, cc.Spec.Device)

	cc.Status = nil

	maxPerUser := uint32(utilrand.GetRandomRangeMath(1, 100))
	cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
		Human: &corev1.ClusterConfig_Spec_Device_Human{
			MaxPerUser: maxPerUser,
		},
	}

	assert.Equal(t, "default", cc.Metadata.Name)

	cc, err = srv.UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err)

	assert.Equal(t, maxPerUser, cc.Spec.Device.Human.MaxPerUser)
	assert.Equal(t, "default", cc.Metadata.Name)

	/*
		{
			cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{
				WebIdentityProviders: []string{
					utilrand.GetRandomStringCanonical(8),
				},
			}

			_, err = srv.UpdateClusterConfig(ctx, cc)
			assert.NotNil(t, err)
		}
	*/
}
