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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestDoCheckSession(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	w := InitWatcher(fakeC.OcteliumC)

	usr, err := fakeC.OcteliumC.CoreC().CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err, "%+v", err)

	createSession := func() *corev1.Session {
		sess, err := fakeC.OcteliumC.CoreC().CreateSession(ctx, &corev1.Session{
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
		return sess
	}

	{
		sess := createSession()

		err = w.doCheckSession(ctx, sess)
		assert.Nil(t, err, "%+v", err)

		res, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, sess.Metadata.Uid, res.Metadata.Uid)
	}

	{
		sess := createSession()
		sess.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(-time.Hour))

		err = w.doCheckSession(ctx, sess)
		assert.Nil(t, err, "%+v", err)

		_, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		sess := createSession()
		sess.Status.Authentication = &corev1.Session_Status_Authentication{
			SetAt: pbutils.Timestamp(time.Now().Add(-2 * time.Hour)),
			RefreshTokenDuration: &metav1.Duration{
				Type: &metav1.Duration_Hours{
					Hours: 1,
				},
			},
		}

		err = w.doCheckSession(ctx, sess)
		assert.Nil(t, err, "%+v", err)

		_, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		sess := createSession()
		sess.Status.Authentication = &corev1.Session_Status_Authentication{
			SetAt: pbutils.Timestamp(time.Now()),
			RefreshTokenDuration: &metav1.Duration{
				Type: &metav1.Duration_Hours{
					Hours: 24,
				},
			},
		}

		err = w.doCheckSession(ctx, sess)
		assert.Nil(t, err, "%+v", err)

		res, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, sess.Metadata.Uid, res.Metadata.Uid)
	}
}

func TestDoCheckAuthenticator(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	w := InitWatcher(fakeC.OcteliumC)

	usr, err := fakeC.OcteliumC.CoreC().CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err, "%+v", err)

	createAuthenticator := func() *corev1.Authenticator {
		authn, err := fakeC.OcteliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
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
		return authn
	}

	{
		authn := createAuthenticator()
		authn.Status.IsRegistered = false
		authn.Metadata.CreatedAt = pbutils.Timestamp(time.Now().Add(-2 * time.Hour))

		err = w.doCheckAuthenticator(ctx, authn)
		assert.Nil(t, err, "%+v", err)

		_, err := fakeC.OcteliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{Uid: authn.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		authn := createAuthenticator()
		authn.Status.IsRegistered = false
		authn.Metadata.CreatedAt = pbutils.Timestamp(time.Now())

		err = w.doCheckAuthenticator(ctx, authn)
		assert.Nil(t, err, "%+v", err)

		res, err := fakeC.OcteliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{Uid: authn.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authn.Metadata.Uid, res.Metadata.Uid)
	}

	{
		authn := createAuthenticator()
		authn.Status.IsRegistered = true
		authn.Metadata.CreatedAt = pbutils.Timestamp(time.Now().Add(-2 * time.Hour))

		err = w.doCheckAuthenticator(ctx, authn)
		assert.Nil(t, err, "%+v", err)

		res, err := fakeC.OcteliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{Uid: authn.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authn.Metadata.Uid, res.Metadata.Uid)
	}
}
