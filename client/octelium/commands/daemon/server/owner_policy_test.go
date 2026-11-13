// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newOwnerPolicyTestServer(t *testing.T, o *Opts) *Server {
	o.StateDir = t.TempDir()

	srv, err := New(o)
	require.NoError(t, err)

	srv.ctx, srv.cancelFn = context.WithCancel(context.Background())
	t.Cleanup(func() {
		srv.Close()
	})

	return srv
}

func getTestSystemPrincipalID() string {
	if runtime.GOOS == "windows" {
		return "S-1-5-18"
	}

	return "0"
}

func TestNewOwnerPolicy(t *testing.T) {
	for _, policy := range []string{"", OwnerPolicyFirstCaller, OwnerPolicyLoginSession} {
		_, err := New(&Opts{
			OwnerPolicy: policy,
		})
		assert.Nil(t, err, "policy=%s", policy)
	}

	for _, policy := range []string{"invalid", "Login-Session", " first-caller"} {
		_, err := New(&Opts{
			OwnerPolicy: policy,
		})
		assert.NotNil(t, err, "policy=%s", policy)
	}
}

func TestOwnerPolicyLoginSession(t *testing.T) {
	srv := newOwnerPolicyTestServer(t, &Opts{
		OwnerPolicy: OwnerPolicyLoginSession,
	})

	var calls atomic.Int32
	srv.hasLoginSession = func(ctx context.Context, pr *ipc.Principal) (bool, error) {
		calls.Add(1)
		_, ok := ctx.Deadline()
		assert.True(t, ok)
		return pr.ID == "1001", nil
	}

	{
		_, err := srv.bindPrincipal(&ipc.Principal{ID: "1002"})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.False(t, srv.isBound())
		assert.Equal(t, int32(1), calls.Load())
	}

	{
		ret, err := srv.bindPrincipal(&ipc.Principal{ID: "1001"})
		require.NoError(t, err)
		assert.Equal(t, "1001", ret.id)
		assert.Equal(t, int32(2), calls.Load())
	}

	{
		ret, err := srv.bindPrincipal(&ipc.Principal{ID: "1001"})
		require.NoError(t, err)
		assert.Equal(t, "1001", ret.id)
	}

	{
		_, err := srv.bindPrincipal(&ipc.Principal{ID: "1002"})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "is owned by the OS user 1001")
	}

	{
		_, err := srv.bindPrincipal(&ipc.Principal{ID: getTestSystemPrincipalID()})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	}

	assert.Equal(t, int32(2), calls.Load())
}

func TestOwnerPolicyLoginSessionSystemPrincipal(t *testing.T) {
	srv := newOwnerPolicyTestServer(t, &Opts{
		OwnerPolicy: OwnerPolicyLoginSession,
	})

	srv.hasLoginSession = func(ctx context.Context, pr *ipc.Principal) (bool, error) {
		t.Errorf("The login session of the system principal must not be checked")
		return false, nil
	}

	ret, err := srv.bindPrincipal(&ipc.Principal{ID: getTestSystemPrincipalID()})
	require.NoError(t, err)
	assert.Equal(t, getTestSystemPrincipalID(), ret.id)
}

func TestOwnerPolicyLoginSessionCheckError(t *testing.T) {
	srv := newOwnerPolicyTestServer(t, &Opts{
		OwnerPolicy: OwnerPolicyLoginSession,
	})

	srv.hasLoginSession = func(ctx context.Context, pr *ipc.Principal) (bool, error) {
		return false, errors.Errorf("logind is not available")
	}

	ret, err := srv.bindPrincipal(&ipc.Principal{ID: "1002"})
	require.NoError(t, err)
	assert.Equal(t, "1002", ret.id)

	_, err = srv.bindPrincipal(&ipc.Principal{ID: "1001"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestOwnerPolicyLoginSessionCheckTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv, err := New(&Opts{
			OwnerPolicy: OwnerPolicyLoginSession,
			StateDir:    t.TempDir(),
		})
		require.NoError(t, err)
		srv.ctx, srv.cancelFn = context.WithCancel(context.Background())
		defer srv.Close()

		srv.hasLoginSession = func(ctx context.Context, pr *ipc.Principal) (bool, error) {
			<-ctx.Done()
			return false, ctx.Err()
		}

		_, err = srv.bindPrincipal(&ipc.Principal{ID: "1001"})
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.False(t, srv.isBound())
	})
}

func TestOwnerPolicyLoginSessionClosed(t *testing.T) {
	srv := newOwnerPolicyTestServer(t, &Opts{
		OwnerPolicy: OwnerPolicyLoginSession,
	})

	srv.hasLoginSession = func(ctx context.Context, pr *ipc.Principal) (bool, error) {
		return false, ctx.Err()
	}

	srv.Close()

	_, err := srv.bindPrincipal(&ipc.Principal{ID: "1001"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.False(t, srv.isBound())
}

func TestOwnerPolicyFirstCaller(t *testing.T) {
	for _, policy := range []string{"", OwnerPolicyFirstCaller} {
		srv := newOwnerPolicyTestServer(t, &Opts{
			OwnerPolicy: policy,
		})

		srv.hasLoginSession = func(ctx context.Context, pr *ipc.Principal) (bool, error) {
			t.Errorf("The login session must not be checked with the policy %q", policy)
			return false, nil
		}

		ret, err := srv.bindPrincipal(&ipc.Principal{ID: "1002"})
		require.NoError(t, err)
		assert.Equal(t, "1002", ret.id)

		_, err = srv.bindPrincipal(&ipc.Principal{ID: "1001"})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	}
}

func TestOwnerPolicyOwnerID(t *testing.T) {
	srv := newOwnerPolicyTestServer(t, &Opts{
		OwnerPolicy: OwnerPolicyLoginSession,
		OwnerID:     "1002",
	})

	srv.hasLoginSession = func(ctx context.Context, pr *ipc.Principal) (bool, error) {
		t.Errorf("The login session must not be checked when the owner is set")
		return false, nil
	}

	ret, err := srv.bindPrincipal(&ipc.Principal{ID: "1002"})
	require.NoError(t, err)
	assert.Equal(t, "1002", ret.id)

	_, err = srv.bindPrincipal(&ipc.Principal{ID: "1001"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
