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
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestSecret(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{
		secretName := fmt.Sprintf("secret-%s", utilrand.GetRandomStringLowercase(4))
		secretValue := []byte("topsecret")
		_, err = srv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: secretName,
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_ValueBytes{
					ValueBytes: []byte(secretValue),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		secret, err := srv.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: secretName})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, secretValue, ucorev1.ToSecret(secret).GetValueBytes())

		secI, err := srv.GetSecret(ctx, &metav1.GetOptions{Uid: secret.Metadata.Uid})
		assert.Nil(t, err)
		assert.Equal(t, secretName, secI.Metadata.Name)
		assert.Nil(t, secI.Data)

		secList, err := srv.ListSecret(ctx, &corev1.ListSecretOptions{})
		assert.Nil(t, err)

		for _, sec := range secList.Items {
			assert.Nil(t, sec.Data)
		}

		_, err = srv.DeleteSecret(ctx, &metav1.DeleteOptions{Name: secretName})
		assert.Nil(t, err)
	}

}
