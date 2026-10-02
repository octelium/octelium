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

package watchers

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func newTstUUIDv7(t time.Time) string {
	ret, _ := uuid.NewV7()
	ms := t.UnixMilli()

	ret[0] = byte(ms >> 40)
	ret[1] = byte(ms >> 32)
	ret[2] = byte(ms >> 24)
	ret[3] = byte(ms >> 16)
	ret[4] = byte(ms >> 8)
	ret[5] = byte(ms)

	return ret.String()
}

func TestIsNewerResourceVersion(t *testing.T) {

	now := time.Now()

	older := newTstUUIDv7(now.Add(-1 * time.Second))
	newer := newTstUUIDv7(now)

	{
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{}, ""))
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{}, newer))
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: newer}, ""))
		assert.True(t, isNewerResourceVersion(nil, newer))
	}

	{
		assert.False(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: newer}, newer))
		assert.False(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: older}, older))
	}

	{
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: newer}, older))
		assert.False(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: older}, newer))
	}

	{
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{
			ResourceVersion:     older,
			LastResourceVersion: newer,
		}, newer))
	}

	{
		assert.False(t, isNewerResourceVersion(&metav1.Metadata{
			ResourceVersion:     older,
			LastResourceVersion: newTstUUIDv7(now.Add(-2 * time.Second)),
		}, newer))
	}

	{
		var prev string
		for range 1000 {
			cur := vutils.UUIDv7()
			if prev != "" {
				assert.True(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: cur}, prev))
				assert.False(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: prev}, cur))
			}
			prev = cur
		}
	}

	{
		v4 := vutils.UUIDv4()
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: v4}, newer))
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: older}, v4))
		assert.False(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: v4}, v4))
	}

	{
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: "invalid"}, newer))
		assert.True(t, isNewerResourceVersion(&metav1.Metadata{ResourceVersion: older}, "invalid"))
	}
}

func TestItemStore(t *testing.T) {

	newItem := func(md *metav1.Metadata) (*metav1.Metadata, *corev1.Service) {
		return md, &corev1.Service{
			Metadata: md,
		}
	}

	now := time.Now()

	uid := vutils.UUIDv4()
	rv1 := newTstUUIDv7(now.Add(-3 * time.Second))
	rv2 := newTstUUIDv7(now.Add(-2 * time.Second))
	rv3 := newTstUUIDv7(now.Add(-1 * time.Second))

	{
		s := &itemStore{}

		md1, svc1 := newItem(&metav1.Metadata{Uid: uid, ResourceVersion: rv1})
		prev, ok := s.set(md1, pbutils.MessageToAnyMust(svc1))
		assert.True(t, ok)
		assert.Nil(t, prev)

		prev, ok = s.set(md1, pbutils.MessageToAnyMust(svc1))
		assert.False(t, ok)
		assert.Nil(t, prev)

		md3, svc3 := newItem(&metav1.Metadata{Uid: uid, ResourceVersion: rv3, LastResourceVersion: rv2})
		prev, ok = s.set(md3, pbutils.MessageToAnyMust(svc3))
		assert.True(t, ok)
		assert.NotNil(t, prev)
		assert.Equal(t, rv1, prev.resourceVersion)

		md2, svc2 := newItem(&metav1.Metadata{Uid: uid, ResourceVersion: rv2, LastResourceVersion: rv1})
		_, ok = s.set(md2, pbutils.MessageToAnyMust(svc2))
		assert.False(t, ok)
		assert.Equal(t, rv3, s.items[uid].resourceVersion)

		res := &corev1.Service{}
		assert.Nil(t, pbutils.AnyToMessage(s.items[uid].item, res))
		assert.Equal(t, rv3, res.Metadata.ResourceVersion)
	}

	{
		s := &itemStore{}

		for range 3 {
			md, svc := newItem(&metav1.Metadata{})
			prev, ok := s.set(md, pbutils.MessageToAnyMust(svc))
			assert.True(t, ok)
			assert.Nil(t, prev)
		}

		assert.Equal(t, 0, len(s.items))
		assert.True(t, s.delete(&metav1.Metadata{}))
		assert.Equal(t, 0, len(s.tombstones))
	}

	{
		s := &itemStore{}

		md1, svc1 := newItem(&metav1.Metadata{Uid: uid, ResourceVersion: rv1})
		_, ok := s.set(md1, pbutils.MessageToAnyMust(svc1))
		assert.True(t, ok)

		assert.True(t, s.delete(&metav1.Metadata{Uid: uid, ResourceVersion: rv2, LastResourceVersion: rv1}))
		assert.Equal(t, 0, len(s.items))
		assert.Equal(t, 1, len(s.tombstones))

		assert.False(t, s.delete(&metav1.Metadata{Uid: uid, ResourceVersion: rv2, LastResourceVersion: rv1}))

		md3, svc3 := newItem(&metav1.Metadata{Uid: uid, ResourceVersion: rv3, LastResourceVersion: rv2})
		_, ok = s.set(md3, pbutils.MessageToAnyMust(svc3))
		assert.False(t, ok)
		assert.Equal(t, 0, len(s.items))
	}

	{
		s := &itemStore{}

		otherUID := vutils.UUIDv4()
		assert.True(t, s.delete(&metav1.Metadata{Uid: otherUID, ResourceVersion: rv1}))
		assert.False(t, s.delete(&metav1.Metadata{Uid: otherUID, ResourceVersion: rv1}))
	}

	{
		s := &itemStore{}

		md1, svc1 := newItem(&metav1.Metadata{Uid: uid, ResourceVersion: rv1})
		_, ok := s.set(md1, pbutils.MessageToAnyMust(svc1))
		assert.True(t, ok)

		s.forget(uid, rv2)
		assert.Equal(t, 1, len(s.items))

		s.forget(vutils.UUIDv4(), rv1)
		assert.Equal(t, 1, len(s.items))

		s.forget(uid, rv1)
		assert.Equal(t, 0, len(s.items))

		prev, ok := s.set(md1, pbutils.MessageToAnyMust(svc1))
		assert.True(t, ok)
		assert.Nil(t, prev)
	}

	{
		s := &itemStore{}

		oldUID := vutils.UUIDv4()
		freshUID := vutils.UUIDv4()

		assert.True(t, s.delete(&metav1.Metadata{Uid: oldUID}))
		assert.True(t, s.delete(&metav1.Metadata{Uid: freshUID}))

		s.tombstones[oldUID] = now.Add(-tombstoneTTL - time.Minute)

		s.pruneTombstones(now)
		assert.Equal(t, 2, len(s.tombstones))

		s.lastPrunedAt = now.Add(-tombstonePruneInterval - time.Second)
		s.pruneTombstones(now)
		assert.Equal(t, 1, len(s.tombstones))

		_, ok := s.tombstones[freshUID]
		assert.True(t, ok)
		_, ok = s.tombstones[oldUID]
		assert.False(t, ok)

		md, svc := newItem(&metav1.Metadata{Uid: oldUID, ResourceVersion: rv1})
		_, ok = s.set(md, pbutils.MessageToAnyMust(svc))
		assert.True(t, ok)
	}
}
