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
	"fmt"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
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

		{
			res1, err := c.GetAuthenticatorByCredID(id)
			assert.Nil(t, err)
			res2, err := c.GetAuthenticatorByCredID(id)
			assert.Nil(t, err)

			assert.True(t, res1 != res2)
			assert.True(t, res1 != authn)

			res1.Status.GetInfo().GetFido().SignCount = 1337
			res1.Status.IsRegistered = false

			res3, err := c.GetAuthenticatorByCredID(id)
			assert.Nil(t, err)
			assert.Equal(t, uint32(0), res3.Status.GetInfo().GetFido().SignCount)
			assert.True(t, res3.Status.IsRegistered)
			assert.True(t, pbutils.IsEqual(authn, res3))
		}

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

func TestCacheConcurrentIsolation(t *testing.T) {
	c, err := NewCache()
	assert.Nil(t, err)
	t.Cleanup(func() {
		assert.Nil(t, c.Close())
	})

	const workers = 32
	errs := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id := []byte(fmt.Sprintf("credential-%d", worker))
			authn := &corev1.Authenticator{
				Spec: &corev1.Authenticator_Spec{DisplayName: string(id)},
				Status: &corev1.Authenticator_Status{
					IsRegistered: true,
					Type:         corev1.Authenticator_Status_FIDO,
					Info: &corev1.Authenticator_Status_Info{
						Type: &corev1.Authenticator_Status_Info_Fido{
							Fido: &corev1.Authenticator_Status_Info_FIDO{Id: id, IdHash: vutils.Sha256Sum(id)},
						},
					},
				},
			}
			if err := c.SetAuthenticator(authn); err != nil {
				errs <- err
				return
			}
			original := pbutils.Clone(authn)
			authn.Spec.DisplayName = "changed by caller"
			for range 20 {
				got, err := c.GetAuthenticatorByCredID(id)
				if err != nil {
					errs <- err
					return
				}
				if !pbutils.IsEqual(original, got) {
					errs <- errors.New("Cached Authenticator was modified by a caller")
					return
				}
				got.Spec.DisplayName = "changed by reader"
				got.Status.GetInfo().GetFido().SignCount++
			}
			if err := c.DeleteAuthenticator(authn); err != nil {
				errs <- err
				return
			}
			_, err := c.GetAuthenticatorByCredID(id)
			if !c.IsErrNotFound(err) {
				errs <- errors.Errorf("Deleted Authenticator returned unexpected error: %v", err)
				return
			}
			errs <- nil
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.Nil(t, err)
	}
}

func TestCacheInvalidAuthenticators(t *testing.T) {
	c, err := NewCache()
	assert.Nil(t, err)
	assert.False(t, c.IsErrNotFound(nil))
	assert.False(t, c.IsErrNotFound(errors.New("unrelated")))
	assert.True(t, c.IsErrNotFound(errors.Wrap(ErrNotFound, "lookup")))

	for _, authn := range []*corev1.Authenticator{
		{Status: &corev1.Authenticator_Status{IsRegistered: true, Type: corev1.Authenticator_Status_TOTP}},
		{Status: &corev1.Authenticator_Status{IsRegistered: true, Type: corev1.Authenticator_Status_FIDO}},
		{Status: &corev1.Authenticator_Status{IsRegistered: true, Type: corev1.Authenticator_Status_FIDO, Info: &corev1.Authenticator_Status_Info{}}},
		{Status: &corev1.Authenticator_Status{
			IsRegistered: true, Type: corev1.Authenticator_Status_FIDO,
			Info: &corev1.Authenticator_Status_Info{Type: &corev1.Authenticator_Status_Info_Fido{
				Fido: &corev1.Authenticator_Status_Info_FIDO{IdHash: make([]byte, 31)},
			}},
		}},
	} {
		assert.Nil(t, c.SetAuthenticator(authn))
		assert.Nil(t, c.DeleteAuthenticator(authn))
		assert.Empty(t, c.cMap)
	}
}
