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

package devcontroller

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestOnDelete(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	c := NewController(fakeC.OcteliumC)

	usr, err := fakeC.OcteliumC.CoreC().CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err, "%+v", err)

	dev, err := fakeC.OcteliumC.CoreC().CreateDevice(ctx, &corev1.Device{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Device_Spec{
			State: corev1.Device_Spec_ACTIVE,
		},
		Status: &corev1.Device_Status{
			UserRef:  umetav1.GetObjectReference(usr),
			OsType:   corev1.Device_Status_LINUX,
			Hostname: utilrand.GetRandomStringLowercase(10),
			Id:       utilrand.GetRandomStringCanonical(12),
		},
	})
	assert.Nil(t, err, "%+v", err)

	otherDev, err := fakeC.OcteliumC.CoreC().CreateDevice(ctx, &corev1.Device{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Device_Spec{
			State: corev1.Device_Spec_ACTIVE,
		},
		Status: &corev1.Device_Status{
			UserRef:  umetav1.GetObjectReference(usr),
			OsType:   corev1.Device_Status_LINUX,
			Hostname: utilrand.GetRandomStringLowercase(10),
			Id:       utilrand.GetRandomStringCanonical(12),
		},
	})
	assert.Nil(t, err, "%+v", err)

	createSession := func(deviceRef *metav1.ObjectReference) *corev1.Session {
		sess, err := fakeC.OcteliumC.CoreC().CreateSession(ctx, &corev1.Session{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Session_Spec{
				State:     corev1.Session_Spec_ACTIVE,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
			},
			Status: &corev1.Session_Status{
				UserRef:   umetav1.GetObjectReference(usr),
				DeviceRef: deviceRef,
				Type:      corev1.Session_Status_CLIENT,
			},
		})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	sess1 := createSession(umetav1.GetObjectReference(dev))
	sess2 := createSession(umetav1.GetObjectReference(dev))
	sessOther := createSession(umetav1.GetObjectReference(otherDev))

	err = c.OnDelete(ctx, dev)
	assert.Nil(t, err, "%+v", err)

	{
		_, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess1.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		_, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess2.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		res, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sessOther.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, sessOther.Metadata.Uid, res.Metadata.Uid)
	}

	{
		sessList, err := fakeC.OcteliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.deviceRef.uid", dev.Metadata.Uid),
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(sessList.Items))
	}
}

func TestOnAddOnUpdateNoop(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	c := NewController(fakeC.OcteliumC)

	dev := &corev1.Device{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec:   &corev1.Device_Spec{},
		Status: &corev1.Device_Status{},
	}

	assert.Nil(t, c.OnAdd(ctx, dev))
	assert.Nil(t, c.OnUpdate(ctx, dev, dev))
}
