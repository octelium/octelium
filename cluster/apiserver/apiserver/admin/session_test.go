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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestSession(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr, err := srv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err)

	usr2, err := srv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err)

	createSession := func(userRef *metav1.ObjectReference) *corev1.Session {
		sess, err := srv.octeliumC.CoreC().CreateSession(ctx, &corev1.Session{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Session_Spec{
				State:     corev1.Session_Spec_ACTIVE,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
			},
			Status: &corev1.Session_Status{
				UserRef: userRef,
				Type:    corev1.Session_Status_CLIENT,
			},
		})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	{
		sess := createSession(umetav1.GetObjectReference(usr))

		res, err := srv.GetSession(ctx, &metav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, sess.Metadata.Uid, res.Metadata.Uid)
		assert.True(t, pbutils.IsEqual(sess.Spec, res.Spec))
		assert.Equal(t, usr.Metadata.Uid, res.Status.UserRef.Uid)
	}

	{
		res, err := srv.GetSession(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
		assert.Nil(t, res)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		sess := createSession(umetav1.GetObjectReference(usr))

		sessClone := pbutils.Clone(sess).(*corev1.Session)
		sessClone.Spec.State = corev1.Session_Spec_PENDING

		out, err := srv.UpdateSession(ctx, sessClone)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, corev1.Session_Spec_PENDING, out.Spec.State)

		res, err := srv.GetSession(ctx, &metav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, corev1.Session_Spec_PENDING, res.Spec.State)
		assert.Equal(t, usr.Metadata.Uid, res.Status.UserRef.Uid)
	}

	{
		_, err := srv.UpdateSession(ctx, &corev1.Session{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateSession(ctx, &corev1.Session{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Session_Spec{
				State:     corev1.Session_Spec_STATE_UNKNOWN,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateSession(ctx, &corev1.Session{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Session_Spec{
				State:     corev1.Session_Spec_ACTIVE,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(-time.Hour)),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateSession(ctx, &corev1.Session{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Session_Spec{
				State:     corev1.Session_Spec_ACTIVE,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		sess := createSession(umetav1.GetObjectReference(usr))

		list, err := srv.ListSession(ctx, &corev1.ListSessionOptions{})
		assert.Nil(t, err, "%+v", err)

		found := false
		for _, itm := range list.Items {
			if itm.Metadata.Uid == sess.Metadata.Uid {
				found = true
			}
		}
		assert.True(t, found)
	}

	{
		sessUsr := createSession(umetav1.GetObjectReference(usr))
		sessUsr2 := createSession(umetav1.GetObjectReference(usr2))

		list, err := srv.ListSession(ctx, &corev1.ListSessionOptions{
			UserRef: umetav1.GetObjectReference(usr),
		})
		assert.Nil(t, err, "%+v", err)

		foundUsr := false
		for _, itm := range list.Items {
			assert.Equal(t, usr.Metadata.Uid, itm.Status.UserRef.Uid)
			assert.NotEqual(t, sessUsr2.Metadata.Uid, itm.Metadata.Uid)
			if itm.Metadata.Uid == sessUsr.Metadata.Uid {
				foundUsr = true
			}
		}
		assert.True(t, foundUsr)

		listUsr2, err := srv.ListSession(ctx, &corev1.ListSessionOptions{
			UserRef: umetav1.GetObjectReference(usr2),
		})
		assert.Nil(t, err, "%+v", err)

		foundUsr2 := false
		for _, itm := range listUsr2.Items {
			assert.Equal(t, usr2.Metadata.Uid, itm.Status.UserRef.Uid)
			if itm.Metadata.Uid == sessUsr2.Metadata.Uid {
				foundUsr2 = true
			}
		}
		assert.True(t, foundUsr2)
	}

	{
		_, err := srv.ListSession(ctx, &corev1.ListSessionOptions{
			UserRef: &metav1.ObjectReference{},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.DeleteSession(ctx, &metav1.DeleteOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		callerT, err := tstuser.NewUserWithType(tst.C.OcteliumC, srv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		sess := createSession(umetav1.GetObjectReference(usr))

		_, err = srv.DeleteSession(callerT.Ctx(), &metav1.DeleteOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.GetSession(ctx, &metav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))

		_, err = srv.DeleteSession(callerT.Ctx(), &metav1.DeleteOptions{Uid: callerT.Session.Metadata.Uid})
		assert.NotNil(t, err)
	}
}
