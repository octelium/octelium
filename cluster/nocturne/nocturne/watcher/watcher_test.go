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
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *fakeOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

type fakeCoreC struct {
	rcorev1.ResourceServiceClient
	listSession       func(*rmetav1.ListOptions) (*corev1.SessionList, error)
	listCredential    func(*rmetav1.ListOptions) (*corev1.CredentialList, error)
	listAuthenticator func(*rmetav1.ListOptions) (*corev1.AuthenticatorList, error)
	listSecret        func(*rmetav1.ListOptions) (*corev1.SecretList, error)
	deleteSession     func(*rmetav1.DeleteOptions) (*rmetav1.OperationResult, error)
	deleteCredential  func(*rmetav1.DeleteOptions) (*rmetav1.OperationResult, error)
	deleteAuthn       func(*rmetav1.DeleteOptions) (*rmetav1.OperationResult, error)
}

func (c *fakeCoreC) ListSession(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.SessionList, error) {
	return c.listSession(in)
}

func (c *fakeCoreC) ListCredential(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.CredentialList, error) {
	return c.listCredential(in)
}

func (c *fakeCoreC) ListAuthenticator(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.AuthenticatorList, error) {
	return c.listAuthenticator(in)
}

func (c *fakeCoreC) ListSecret(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.SecretList, error) {
	return c.listSecret(in)
}

func (c *fakeCoreC) DeleteSession(ctx context.Context,
	in *rmetav1.DeleteOptions, opts ...grpc.CallOption) (*rmetav1.OperationResult, error) {
	return c.deleteSession(in)
}

func (c *fakeCoreC) DeleteCredential(ctx context.Context,
	in *rmetav1.DeleteOptions, opts ...grpc.CallOption) (*rmetav1.OperationResult, error) {
	return c.deleteCredential(in)
}

func (c *fakeCoreC) DeleteAuthenticator(ctx context.Context,
	in *rmetav1.DeleteOptions, opts ...grpc.CallOption) (*rmetav1.OperationResult, error) {
	return c.deleteAuthn(in)
}

func TestWatcherLoops(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		run      func(*Watcher, context.Context)
	}{
		{"Session", 5 * time.Minute, (*Watcher).runSessions},
		{"Credential", 7 * time.Minute, (*Watcher).runCredentials},
		{"Authenticator", 15 * time.Minute, (*Watcher).runAuthenticator},
		{"JWK", 10 * time.Minute, (*Watcher).runJWKSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var pages []uint32
				var deleted []string
				var mu sync.Mutex
				getPages := func() []uint32 {
					mu.Lock()
					defer mu.Unlock()
					return append([]uint32(nil), pages...)
				}
				getDeleted := func() []string {
					mu.Lock()
					defer mu.Unlock()
					return append([]string(nil), deleted...)
				}
				list := func(in *rmetav1.ListOptions) error {
					mu.Lock()
					defer mu.Unlock()
					pages = append(pages, in.Page)
					assert.True(t, in.Paginate)
					assert.Equal(t, uint32(500), in.ItemsPerPage)
					if len(pages) == 1 {
						return errors.New("could not list resources")
					}
					return nil
				}
				coreC := &fakeCoreC{
					listSession: func(in *rmetav1.ListOptions) (*corev1.SessionList, error) {
						if err := list(in); err != nil {
							return nil, err
						}
						if in.Page == 0 {
							return &corev1.SessionList{
								Items: []*corev1.Session{{
									Metadata: &metav1.Metadata{Uid: "expired"},
									Spec:     &corev1.Session_Spec{ExpiresAt: pbutils.Timestamp(time.Now().Add(-time.Hour))},
									Status:   &corev1.Session_Status{},
								}},
								ListResponseMeta: &metav1.ListResponseMeta{HasMore: true},
							}, nil
						}
						return &corev1.SessionList{
							Items: []*corev1.Session{{
								Spec:   &corev1.Session_Spec{ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour))},
								Status: &corev1.Session_Status{},
							}},
						}, nil
					},
					deleteSession: func(in *rmetav1.DeleteOptions) (*rmetav1.OperationResult, error) {
						mu.Lock()
						defer mu.Unlock()
						deleted = append(deleted, in.Uid)
						return &rmetav1.OperationResult{}, nil
					},
					listCredential: func(in *rmetav1.ListOptions) (*corev1.CredentialList, error) {
						if err := list(in); err != nil {
							return nil, err
						}
						if in.Page == 0 {
							return &corev1.CredentialList{
								Items: []*corev1.Credential{{
									Metadata: &metav1.Metadata{Uid: "expired"},
									Spec:     &corev1.Credential_Spec{ExpiresAt: pbutils.Timestamp(time.Now().Add(-time.Hour))},
								}},
								ListResponseMeta: &metav1.ListResponseMeta{HasMore: true},
							}, nil
						}
						return &corev1.CredentialList{
							Items: []*corev1.Credential{
								{Spec: &corev1.Credential_Spec{}},
								{Spec: &corev1.Credential_Spec{ExpiresAt: &timestamppb.Timestamp{Seconds: 253402300800}}},
								{Spec: &corev1.Credential_Spec{ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour))}},
							},
						}, nil
					},
					deleteCredential: func(in *rmetav1.DeleteOptions) (*rmetav1.OperationResult, error) {
						mu.Lock()
						defer mu.Unlock()
						deleted = append(deleted, in.Uid)
						return nil, errors.New("could not delete Credential")
					},
					listAuthenticator: func(in *rmetav1.ListOptions) (*corev1.AuthenticatorList, error) {
						if err := list(in); err != nil {
							return nil, err
						}
						if in.Page == 0 {
							return &corev1.AuthenticatorList{
								Items: []*corev1.Authenticator{{
									Metadata: &metav1.Metadata{Uid: "expired", CreatedAt: pbutils.Timestamp(time.Now().Add(-2 * time.Hour))},
									Status:   &corev1.Authenticator_Status{},
								}},
								ListResponseMeta: &metav1.ListResponseMeta{HasMore: true},
							}, nil
						}
						return &corev1.AuthenticatorList{
							Items: []*corev1.Authenticator{{
								Metadata: &metav1.Metadata{CreatedAt: pbutils.Timestamp(time.Now())},
								Status:   &corev1.Authenticator_Status{},
							}},
						}, nil
					},
					deleteAuthn: func(in *rmetav1.DeleteOptions) (*rmetav1.OperationResult, error) {
						mu.Lock()
						defer mu.Unlock()
						deleted = append(deleted, in.Uid)
						return nil, errors.New("could not delete Authenticator")
					},
					listSecret: func(in *rmetav1.ListOptions) (*corev1.SecretList, error) {
						mu.Lock()
						defer mu.Unlock()
						assert.Equal(t, map[string]string{"octelium-root-secret": "true"}, in.SystemLabels)
						pages = append(pages, 0)
						if len(pages) == 1 {
							return nil, errors.New("could not list Secrets")
						}
						return &corev1.SecretList{}, nil
					},
				}
				w := InitWatcher(&fakeOcteliumC{coreC: coreC})
				done := make(chan struct{})
				go func() {
					tc.run(w, ctx)
					close(done)
				}()
				synctest.Wait()
				assert.Empty(t, getPages())
				time.Sleep(tc.interval)
				synctest.Wait()
				assert.Equal(t, []uint32{0}, getPages())
				time.Sleep(tc.interval)
				synctest.Wait()
				if tc.name == "JWK" {
					assert.Equal(t, []uint32{0, 0}, getPages())
					assert.Empty(t, getDeleted())
				} else {
					assert.Equal(t, []uint32{0, 0, 1}, getPages())
					assert.Equal(t, []string{"expired"}, getDeleted())
				}
				cancel()
				<-done
			})
		})
	}
}

func TestWatcherRunCancelled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		w := InitWatcher(nil)
		w.Run(ctx)
		synctest.Wait()
	})
}

func TestAuthenticatorCleanupErrors(t *testing.T) {
	ctx := context.Background()
	authn := &corev1.Authenticator{
		Metadata: &metav1.Metadata{Uid: "expired", CreatedAt: pbutils.Timestamp(time.Now().Add(-2 * time.Hour))},
		Status:   &corev1.Authenticator_Status{},
	}
	for _, errDel := range []error{status.Error(codes.NotFound, "not found"), errors.New("could not delete")} {
		coreC := &fakeCoreC{
			deleteAuthn: func(in *rmetav1.DeleteOptions) (*rmetav1.OperationResult, error) {
				assert.Equal(t, authn.Metadata.Uid, in.Uid)
				return nil, errDel
			},
		}
		w := InitWatcher(&fakeOcteliumC{coreC: coreC})
		err := w.doCheckAuthenticator(ctx, authn)
		if status.Code(errDel) == codes.NotFound {
			assert.Nil(t, err)
		} else {
			assert.ErrorIs(t, err, errDel)
		}
	}
}

func TestSessionCleanupErrors(t *testing.T) {
	sess := &corev1.Session{
		Metadata: &metav1.Metadata{Uid: "expired"},
		Spec:     &corev1.Session_Spec{ExpiresAt: pbutils.Timestamp(time.Now().Add(-time.Hour))},
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{
				SetAt:                pbutils.Timestamp(time.Now().Add(-2 * time.Hour)),
				RefreshTokenDuration: &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 1}},
			},
		},
	}
	var calls int
	coreC := &fakeCoreC{
		deleteSession: func(in *rmetav1.DeleteOptions) (*rmetav1.OperationResult, error) {
			calls++
			assert.Equal(t, sess.Metadata.Uid, in.Uid)
			return nil, errors.New("could not delete Session")
		},
	}
	w := InitWatcher(&fakeOcteliumC{coreC: coreC})
	assert.Nil(t, w.doCheckSession(context.Background(), sess))
	assert.Equal(t, 2, calls)
}
