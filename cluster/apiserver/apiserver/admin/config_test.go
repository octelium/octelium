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
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{

		val := utilrand.GetRandomBytesMust(20 * 1024 * 1024)
		cfg, err := srv.CreateConfig(ctx, &corev1.Config{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("cfg-%s", utilrand.GetRandomStringLowercase(4)),
			},
			Spec: &corev1.Config_Spec{},
			Data: &corev1.Config_Data{
				Type: &corev1.Config_Data_ValueBytes{
					ValueBytes: []byte(val),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, cfg.Data)

		cfg, err = srv.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: cfg.Metadata.Name})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, val, cfg.Data.GetValueBytes())

		secI, err := srv.GetConfig(ctx, &metav1.GetOptions{Uid: cfg.Metadata.Uid})
		assert.Nil(t, err)
		assert.Equal(t, cfg.Metadata.Name, secI.Metadata.Name)
		assert.Nil(t, secI.Data)

		secList, err := srv.ListConfig(ctx, &corev1.ListConfigOptions{})
		assert.Nil(t, err)

		for _, sec := range secList.Items {
			assert.Nil(t, sec.Data)
		}

		_, err = srv.DeleteConfig(ctx, &metav1.DeleteOptions{Name: cfg.Metadata.Name})
		assert.Nil(t, err)
	}

}
