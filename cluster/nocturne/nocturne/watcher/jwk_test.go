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

package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/jwkctl/jwkutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestJWK(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	_, err = jwkutils.CreateJWKSecret(ctx, fakeC.OcteliumC)
	assert.Nil(t, err)

	w := InitWatcher(fakeC.OcteliumC)
	secrets, err := w.octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{
		SystemLabels: map[string]string{
			"octelium-root-secret": "true",
		},
	})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(secrets.Items))
	err = w.doProcessJWKSecret(ctx, secrets.Items[0])
	assert.Nil(t, err)

	sec := secrets.Items[0]
	{
		assert.False(t, w.needsRotation(sec))
		assert.False(t, w.needsDeletion(sec))
	}

	sec.Metadata.CreatedAt = pbutils.Timestamp(time.Now().Add(-2 * durationMonth))

	{
		assert.True(t, w.needsRotation(sec))
		assert.False(t, w.needsDeletion(sec))
	}

	sec.Metadata.CreatedAt = pbutils.Timestamp(time.Now().Add(-13 * durationMonth))
	{
		assert.True(t, w.needsRotation(sec))
		assert.True(t, w.needsDeletion(sec))
	}
}
