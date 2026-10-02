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

package tests

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestWatcherCore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	watcher := watchers.NewCoreV1(fakeC.OcteliumC)

	req := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec:   &corev1.Service_Spec{},
		Status: &corev1.Service_Status{},
	}

	didCreate := false
	didUpdate := false
	didDelete := false

	err = watcher.Service(ctx, nil, func(ctx context.Context, item *corev1.Service) error {

		if item.Metadata.Name == req.Metadata.Name {
			didCreate = true
		}
		return nil
	},
		func(ctx context.Context, new, old *corev1.Service) error {
			if new.Metadata.Name == req.Metadata.Name {
				assert.Equal(t, new.Metadata.Uid, old.Metadata.Uid)
				didUpdate = true
			}

			return nil
		},
		func(ctx context.Context, item *corev1.Service) error {
			if item.Metadata.Name == req.Metadata.Name {
				assert.Equal(t, item.Metadata.Name, req.Metadata.Name)
				didDelete = true
			}

			return nil
		})
	assert.Nil(t, err)

	svc, err := fakeC.OcteliumC.CoreC().CreateService(ctx, req)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	svc.Spec.Port = uint32(utilrand.GetRandomRangeMath(0, 40000))
	svc, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svc)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)
	_, err = fakeC.OcteliumC.CoreC().DeleteService(ctx, &rmetav1.DeleteOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)
	time.Sleep(3 * time.Second)

	assert.True(t, didCreate && didUpdate && didDelete)
	cancel()
}

/*
func TestWatcherCluster(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	watcher := watchers.NewClusterV1(fakeC.OcteliumC)

	req := &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec:   &corev1.IdentityProvider_Spec{},
		Status: &corev1.IdentityProvider_Status{},
	}

	didCreate := false
	didUpdate := false
	didDelete := false

	err = watcher.IdentityProvider(ctx, nil, func(ctx context.Context, item *corev1.IdentityProvider) error {

		if item.Metadata.Name == req.Metadata.Name {
			didCreate = true
		}
		return nil
	},
		func(ctx context.Context, new, old *corev1.IdentityProvider) error {
			if new.Metadata.Name == req.Metadata.Name {
				assert.Equal(t, new.Metadata.Uid, old.Metadata.Uid)
				didUpdate = true
			}
			return nil
		},
		func(ctx context.Context, item *corev1.IdentityProvider) error {
			if item.Metadata.Name == req.Metadata.Name {
				assert.Equal(t, item.Metadata.Name, req.Metadata.Name)
				didDelete = true
			}
			return nil
		})
	assert.Nil(t, err)

	svc, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, req)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	svc.Spec.AllowUserEmail = true
	svc, err = fakeC.OcteliumC.CoreC().UpdateIdentityProvider(ctx, svc)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)
	_, err = fakeC.OcteliumC.CoreC().DeleteIdentityProvider(ctx, &rmetav1.DeleteOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	time.Sleep(3 * time.Second)

	assert.True(t, didCreate && didUpdate && didDelete)
	cancel()
}
*/

func TestWatcherClusterConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	watcher := watchers.NewCoreV1(fakeC.OcteliumC)

	cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	maxPerUser := uint32(utilrand.GetRandomRangeMath(1, 100))
	err = watcher.ClusterConfig(ctx, nil, func(ctx context.Context, new, old *corev1.ClusterConfig) error {

		assert.Equal(t, maxPerUser, cc.Spec.Device.Human.MaxPerUser)
		return nil
	})

	assert.Nil(t, err)

	time.Sleep(1 * time.Second)
	cc, err = fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
		Human: &corev1.ClusterConfig_Spec_Device_Human{
			MaxPerUser: maxPerUser,
		},
	}
	cc, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err, "%+v", err)
	time.Sleep(3 * time.Second)
	cancel()
}

func TestWatcherResyncAfterLostEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Setenv("OCTELIUM_REDIS_DATABASE", fmt.Sprintf("%d", utilrand.GetRandomRangeMath(1, 15)))

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	type update struct {
		newPort uint32
		oldPort uint32
	}

	var mu sync.Mutex
	creates := make(map[string]int)
	updates := make(map[string][]update)

	err = watchers.NewCoreV1(fakeC.OcteliumC).Service(ctx, nil,
		func(ctx context.Context, item *corev1.Service) error {
			mu.Lock()
			creates[item.Metadata.Uid] = creates[item.Metadata.Uid] + 1
			mu.Unlock()
			return nil
		},
		func(ctx context.Context, new, old *corev1.Service) error {
			mu.Lock()
			updates[new.Metadata.Uid] = append(updates[new.Metadata.Uid], update{
				newPort: new.Spec.Port,
				oldPort: old.Spec.Port,
			})
			mu.Unlock()
			return nil
		}, nil)
	assert.Nil(t, err)

	svc, err := fakeC.OcteliumC.CoreC().CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: 1000,
		},
		Status: &corev1.Service_Status{},
	})
	assert.Nil(t, err)

	svcList, err := fakeC.OcteliumC.CoreC().ListService(ctx, &rmetav1.ListOptions{})
	assert.Nil(t, err)

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, itm := range svcList.Items {
			if creates[itm.Metadata.Uid] != 1 {
				return false
			}
		}
		return true
	}, 30*time.Second, 50*time.Millisecond)

	db, err := postgresutils.NewDB()
	assert.Nil(t, err)
	defer db.Close()

	_, err = db.ExecContext(ctx, `UPDATE octelium_resources SET resource =
		jsonb_set(jsonb_set(jsonb_set(resource,
		'{spec,port}', '2000'::jsonb),
		'{metadata,resourceVersion}', to_jsonb($1::text)),
		'{metadata,lastResourceVersion}', to_jsonb($2::text))
		WHERE uid = $3`, vutils.UUIDv7(), svc.Metadata.ResourceVersion, svc.Metadata.Uid)
	assert.Nil(t, err, "%+v", err)

	assert.Nil(t, redisutils.NewClient().Del(ctx, "octelium:rsc:stream:core:v1:Service").Err())

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(updates[svc.Metadata.Uid]) == 1
	}, 60*time.Second, 100*time.Millisecond)

	time.Sleep(1 * time.Second)

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, []update{{newPort: 2000, oldPort: 1000}}, updates[svc.Metadata.Uid])

	for _, itm := range svcList.Items {
		assert.Equal(t, 1, creates[itm.Metadata.Uid], itm.Metadata.Name)
		if itm.Metadata.Uid != svc.Metadata.Uid {
			assert.Equal(t, 0, len(updates[itm.Metadata.Uid]), itm.Metadata.Name)
		}
	}
}
