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
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestDoProcess(t *testing.T) {

	ctx := context.Background()

	rscUid := vutils.UUIDv4()

	watchObjList := []*rmetav1.WatchEvent{
		{
			Event: &rmetav1.WatchEvent_Event{
				ApiVersion: "core/v1",
				Kind:       "Service",
				Type: &rmetav1.WatchEvent_Event_Create_{
					Create: &rmetav1.WatchEvent_Event_Create{
						Item: pbutils.MessageToAnyMust(&corev1.Service{
							Metadata: &metav1.Metadata{
								Uid: rscUid,
							},
						}),
					},
				},
			},
		},
		{
			Event: &rmetav1.WatchEvent_Event{
				ApiVersion: "core/v1",
				Kind:       "Service",
				Type: &rmetav1.WatchEvent_Event_Delete_{
					Delete: &rmetav1.WatchEvent_Event_Delete{
						Item: pbutils.MessageToAnyMust(&corev1.Service{
							Metadata: &metav1.Metadata{
								Uid: rscUid,
							},
						}),
					},
				},
			},
		},
		{
			Event: &rmetav1.WatchEvent_Event{
				ApiVersion: "core/v1",
				Kind:       "Service",
				Type: &rmetav1.WatchEvent_Event_Update_{
					Update: &rmetav1.WatchEvent_Event_Update{
						NewItem: pbutils.MessageToAnyMust(&corev1.Service{
							Metadata: &metav1.Metadata{
								Uid: rscUid,
							},
						}),
						OldItem: pbutils.MessageToAnyMust(&corev1.Service{
							Metadata: &metav1.Metadata{
								Uid: rscUid,
							},
						}),
					},
				},
			},
		},
	}

	watcher := &Watcher{
		api:     "core",
		version: "v1",
		kind:    ucorev1.KindService,
		onCreate: func(ctx context.Context, item umetav1.ResourceObjectI) error {
			fmt.Printf("Create: %+v", item.(*corev1.Service))
			assert.Equal(t, item.GetMetadata().Uid, rscUid)
			return nil
		},
		onUpdate: func(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error {
			fmt.Printf("Update new: %+v", newItem.(*corev1.Service))
			fmt.Printf("Update old: %+v", oldItem.(*corev1.Service))
			assert.Equal(t, newItem.GetMetadata().Uid, oldItem.GetMetadata().Uid)
			return nil
		},
		onDelete: func(ctx context.Context, item umetav1.ResourceObjectI) error {
			assert.Equal(t, item.GetMetadata().Uid, rscUid)
			fmt.Printf("Delete: %+v", item.(*corev1.Service))
			return nil
		},
		newObjFn: func() (umetav1.ResourceObjectI, error) {
			return ucorev1.NewObject(ucorev1.KindService)
		},
	}

	for _, watchObj := range watchObjList {
		err := watcher.doProcess(ctx, watchObj)
		assert.Nil(t, err)
	}
}
