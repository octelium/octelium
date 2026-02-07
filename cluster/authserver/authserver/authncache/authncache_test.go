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

package authncache

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	c, err := NewCache()
	assert.Nil(t, err)

	{
		_, err := c.GetAuthenticatorByCredID(nil)
		assert.NotNil(t, err)
		assert.Equal(t, err, ErrNotFound)
	}

	{
		_, err := c.GetAuthenticatorByCredID(utilrand.GetRandomBytesMust(32))
		assert.NotNil(t, err)
		assert.Equal(t, err, ErrNotFound)
	}
	{
		_, err := c.GetAuthenticatorByCredID(utilrand.GetRandomBytesMust(32000))
		assert.NotNil(t, err)
		assert.Equal(t, err, ErrNotFound)
	}

	{
		id := utilrand.GetRandomBytesMust(1000)
		authn := &corev1.Authenticator{
			Status: &corev1.Authenticator_Status{
				IsRegistered: true,
				Type:         corev1.Authenticator_Status_FIDO,
				Info: &corev1.Authenticator_Status_Info{
					Type: &corev1.Authenticator_Status_Info_Fido{
						Fido: &corev1.Authenticator_Status_Info_FIDO{
							Id:     id,
							IdHash: vutils.Sha256Sum(id),
						},
					},
				},
			},
		}

		err = c.SetAuthenticator(authn)
		assert.Nil(t, err)

		res, err := c.GetAuthenticatorByCredID(id)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(authn, res))

		err = c.DeleteAuthenticator(authn)
		assert.Nil(t, err)

		_, err = c.GetAuthenticatorByCredID(id)
		assert.NotNil(t, err)
		assert.Equal(t, err, ErrNotFound)
	}

	{
		id := utilrand.GetRandomBytesMust(1000)
		authn := &corev1.Authenticator{
			Status: &corev1.Authenticator_Status{
				IsRegistered: false,
				Type:         corev1.Authenticator_Status_FIDO,
				Info: &corev1.Authenticator_Status_Info{
					Type: &corev1.Authenticator_Status_Info_Fido{
						Fido: &corev1.Authenticator_Status_Info_FIDO{
							Id:     id,
							IdHash: vutils.Sha256Sum(id),
						},
					},
				},
			},
		}

		err = c.SetAuthenticator(authn)
		assert.Nil(t, err)

		_, err = c.GetAuthenticatorByCredID(id)
		assert.NotNil(t, err)
		assert.Equal(t, err, ErrNotFound)
	}

}
