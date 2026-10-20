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

package usrcontroller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
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

	otherUsr, err := fakeC.OcteliumC.CoreC().CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err, "%+v", err)

	_, err = fakeC.OcteliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef: umetav1.GetObjectReference(usr),
			Type:    corev1.Authenticator_Status_TPM,
		},
	})
	assert.Nil(t, err, "%+v", err)

	_, err = fakeC.OcteliumC.CoreC().CreateDevice(ctx, &corev1.Device{
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

	_, err = fakeC.OcteliumC.CoreC().CreateSession(ctx, &corev1.Session{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Session_Spec{
			State:     corev1.Session_Spec_ACTIVE,
			ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
		},
		Status: &corev1.Session_Status{
			UserRef: umetav1.GetObjectReference(usr),
			Type:    corev1.Session_Status_CLIENT,
		},
	})
	assert.Nil(t, err, "%+v", err)

	otherSess, err := fakeC.OcteliumC.CoreC().CreateSession(ctx, &corev1.Session{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Session_Spec{
			State:     corev1.Session_Spec_ACTIVE,
			ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
		},
		Status: &corev1.Session_Status{
			UserRef: umetav1.GetObjectReference(otherUsr),
			Type:    corev1.Session_Status_CLIENT,
		},
	})
	assert.Nil(t, err, "%+v", err)

	err = c.OnDelete(ctx, usr)
	assert.Nil(t, err, "%+v", err)

	{
		authnList, err := fakeC.OcteliumC.CoreC().ListAuthenticator(ctx, urscsrv.FilterByUser(usr))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(authnList.Items))
	}

	{
		devList, err := fakeC.OcteliumC.CoreC().ListDevice(ctx, urscsrv.FilterByUser(usr))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(devList.Items))
	}

	{
		sessList, err := fakeC.OcteliumC.CoreC().ListSession(ctx, urscsrv.FilterByUser(usr))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(sessList.Items))
	}

	{
		sessList, err := fakeC.OcteliumC.CoreC().ListSession(ctx, urscsrv.FilterByUser(otherUsr))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(sessList.Items))
		assert.Equal(t, otherSess.Metadata.Uid, sessList.Items[0].Metadata.Uid)
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

	usr, err := fakeC.OcteliumC.CoreC().CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err, "%+v", err)

	assert.Nil(t, c.OnAdd(ctx, usr))
	assert.Nil(t, c.OnUpdate(ctx, usr, usr))
}

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *fakeOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

type fakeCoreC struct {
	rcorev1.ResourceServiceClient
	err   error
	errAt int
	calls int
}

func (c *fakeCoreC) next() error {
	c.calls++
	if c.calls == c.errAt {
		return c.err
	}
	return nil
}

func (c *fakeCoreC) ListAuthenticator(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.AuthenticatorList, error) {
	return &corev1.AuthenticatorList{}, c.next()
}

func (c *fakeCoreC) ListDevice(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.DeviceList, error) {
	return &corev1.DeviceList{}, c.next()
}

func (c *fakeCoreC) ListSession(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.SessionList, error) {
	return &corev1.SessionList{}, c.next()
}

func TestOnDeleteListErrors(t *testing.T) {
	errTst := errors.New("could not list owned resources")
	usr := &corev1.User{Metadata: &metav1.Metadata{Uid: "user-uid"}}
	for _, errAt := range []int{1, 2, 3} {
		coreC := &fakeCoreC{err: errTst, errAt: errAt}
		c := NewController(&fakeOcteliumC{coreC: coreC})
		assert.ErrorIs(t, c.OnDelete(context.Background(), usr), errTst)
		assert.Equal(t, errAt, coreC.calls)
	}
}
