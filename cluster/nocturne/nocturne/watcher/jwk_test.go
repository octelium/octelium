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
	"errors"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/jwkctl/jwkutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func listRootSecrets(ctx context.Context, w *Watcher) (int, error) {
	secrets, err := w.octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{
		SystemLabels: map[string]string{
			"octelium-root-secret": "true",
		},
	})
	if err != nil {
		return 0, err
	}
	return len(secrets.Items), nil
}

func TestDoRunJWKSecret(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	w := InitWatcher(fakeC.OcteliumC)

	_, err = jwkutils.CreateJWKSecret(ctx, fakeC.OcteliumC)
	assert.Nil(t, err, "%+v", err)

	err = w.doRunJWKSecret(ctx)
	assert.Nil(t, err, "%+v", err)

	cnt, err := listRootSecrets(ctx, w)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, cnt)

	secrets, err := w.octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{
		SystemLabels: map[string]string{
			"octelium-root-secret": "true",
		},
	})
	assert.Nil(t, err, "%+v", err)
	assert.False(t, secretHasBeenRotated(secrets.Items[0]))
}

func TestDoProcessJWKSecretRotation(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	w := InitWatcher(fakeC.OcteliumC)

	sec, err := jwkutils.CreateJWKSecret(ctx, fakeC.OcteliumC)
	assert.Nil(t, err, "%+v", err)

	sec.Metadata.CreatedAt = pbutils.Timestamp(time.Now().Add(-2 * durationMonth))
	assert.True(t, w.needsRotation(sec))
	assert.False(t, w.needsDeletion(sec))

	err = w.doProcessJWKSecret(ctx, sec)
	assert.Nil(t, err, "%+v", err)

	cnt, err := listRootSecrets(ctx, w)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 2, cnt)

	res, err := w.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Uid: sec.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)
	assert.True(t, secretHasBeenRotated(res))
	assert.False(t, w.needsRotation(res))
}

func TestDoProcessJWKSecretDeletion(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	w := InitWatcher(fakeC.OcteliumC)

	sec, err := jwkutils.CreateJWKSecret(ctx, fakeC.OcteliumC)
	assert.Nil(t, err, "%+v", err)

	sec.Metadata.CreatedAt = pbutils.Timestamp(time.Now().Add(-13 * durationMonth))
	assert.True(t, w.needsRotation(sec))
	assert.True(t, w.needsDeletion(sec))

	err = w.doProcessJWKSecret(ctx, sec)
	assert.Nil(t, err, "%+v", err)

	_, err = w.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Uid: sec.Metadata.Uid})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsNotFound(err))

	cnt, err := listRootSecrets(ctx, w)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, cnt)
}

type fakeJWKCoreC struct {
	rcorev1.ResourceServiceClient
	createErr error
	updateErr error
	deleteErr error
	creates   int
	updates   int
	deletes   int
}

func (c *fakeJWKCoreC) CreateSecret(ctx context.Context,
	in *corev1.Secret, opts ...grpc.CallOption) (*corev1.Secret, error) {
	c.creates++
	return in, c.createErr
}

func (c *fakeJWKCoreC) UpdateSecret(ctx context.Context,
	in *corev1.Secret, opts ...grpc.CallOption) (*corev1.Secret, error) {
	c.updates++
	return in, c.updateErr
}

func (c *fakeJWKCoreC) DeleteSecret(ctx context.Context,
	in *rmetav1.DeleteOptions, opts ...grpc.CallOption) (*rmetav1.OperationResult, error) {
	c.deletes++
	return nil, c.deleteErr
}

func TestJWKSecretErrors(t *testing.T) {
	errTst := errors.New("could not reconcile root Secret")
	for _, tc := range []struct {
		name      string
		coreC     *fakeJWKCoreC
		rotated   bool
		wantErr   bool
		wantCalls []int
	}{
		{"Create", &fakeJWKCoreC{createErr: errTst}, false, true, []int{1, 0, 0}},
		{"Update", &fakeJWKCoreC{updateErr: errTst}, false, true, []int{1, 1, 0}},
		{"Delete", &fakeJWKCoreC{deleteErr: errTst}, true, true, []int{0, 0, 1}},
		{"AlreadyDeleted", &fakeJWKCoreC{deleteErr: status.Error(codes.NotFound, "not found")}, true, false, []int{0, 0, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := &corev1.Secret{
				Metadata: &metav1.Metadata{
					Name: "sys:root-secret-test", Uid: "secret-uid",
					CreatedAt:    pbutils.Timestamp(time.Now().Add(-2 * durationYear)),
					SystemLabels: map[string]string{"octelium-root-secret": "true"},
				},
			}
			if tc.rotated {
				secret.Metadata.SystemLabels["key-rotated"] = "true"
			}
			w := InitWatcher(&fakeOcteliumC{coreC: tc.coreC})
			err := w.doProcessJWKSecret(context.Background(), secret)
			if tc.wantErr {
				assert.ErrorIs(t, err, errTst)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tc.wantCalls, []int{tc.coreC.creates, tc.coreC.updates, tc.coreC.deletes})
		})
	}

	{
		coreC := &fakeJWKCoreC{
			createErr: errTst,
			ResourceServiceClient: &fakeCoreC{
				listSecret: func(in *rmetav1.ListOptions) (*corev1.SecretList, error) {
					return &corev1.SecretList{
						Items: []*corev1.Secret{
							{Metadata: &metav1.Metadata{
								CreatedAt:    pbutils.Timestamp(time.Now().Add(-2 * durationMonth)),
								SystemLabels: map[string]string{"octelium-root-secret": "true"},
							}},
							{Metadata: &metav1.Metadata{}},
						},
					}, nil
				},
			},
		}
		w := InitWatcher(&fakeOcteliumC{coreC: coreC})
		assert.Nil(t, w.doRunJWKSecret(context.Background()))
		assert.Equal(t, 1, coreC.creates)
	}
}
