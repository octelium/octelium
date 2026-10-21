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

package suite

import (
	"context"
	"fmt"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/octelium-go"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func testAdminAPI(t *testing.T, h *harness.H) {
	ctx := t.Context()
	c := h.CoreC()

	t.Run("Read", func(t *testing.T) {
		_, err := c.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		assert.Nil(t, err)

		_, err = c.GetService(ctx, &metav1.GetOptions{Name: "demo-nginx.default"})
		assert.Nil(t, err)

		itmList, err := c.ListService(ctx, &corev1.ListServiceOptions{})
		require.Nil(t, err)
		assert.True(t, len(itmList.Items) > 0)

		for _, svc := range itmList.Items {
			assert.NotNil(t, svc.Status.RegionRef)
			assert.NotNil(t, svc.Status.NamespaceRef)
			assert.True(t, len(svc.Status.Addresses) > 0)
			assert.True(t, svc.Status.Port > 0)
		}
	})

	t.Run("SystemResourcesProtected", func(t *testing.T) {
		for _, name := range []string{
			"default.octelium-api",
			"auth.octelium-api",
			"default.default",
			"dns.octelium",
			"portal.default",
		} {
			_, err := c.DeleteService(ctx, &metav1.DeleteOptions{Name: name})
			assert.True(t, grpcerr.IsUnauthorized(err),
				"deleting the system Service %s should be unauthorized, got: %+v", name, err)
		}

		for _, name := range []string{"default", "octelium", "octelium-api"} {
			_, err := c.DeleteNamespace(ctx, &metav1.DeleteOptions{Name: name})
			assert.True(t, grpcerr.IsUnauthorized(err),
				"deleting the system Namespace %s should be unauthorized, got: %+v", name, err)
		}

		_, err := c.DeleteUser(ctx, &metav1.DeleteOptions{Name: "octelium"})
		assert.True(t, grpcerr.IsUnauthorized(err),
			"deleting the system User should be unauthorized, got: %+v", err)
	})

	t.Run("DeleteInitCredential", func(t *testing.T) {
		_, err := c.DeleteCredential(ctx, &metav1.DeleteOptions{Name: "root-init"})
		assert.Nil(t, err)
	})
}

func testAPIValidationLoad(t *testing.T, h *harness.H) {
	ns := h.EnsureTestNamespace(t)
	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{Name: fmt.Sprintf("%s.%s", h.Name(), ns.Metadata.Name)},
		Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Config: &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://127.0.0.1:8080"}},
		}},
	})
	usr := h.CreateWorkloadUser(t, nil)
	badPort := proto.Clone(svc).(*corev1.Service)
	badPort.Spec.Port = 65536
	badAuth := proto.Clone(svc).(*corev1.Service)
	badAuth.Spec.Config.Type = &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
		Auth: &corev1.Service_Spec_Config_HTTP_Auth{Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{}}},
	}}
	badPolicy := proto.Clone(svc).(*corev1.Service)
	badPolicy.Spec.Authorization = &corev1.Service_Spec_Authorization{InlinePolicies: []*corev1.InlinePolicy{{
		Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Effect: corev1.Policy_Spec_Rule_ALLOW, Priority: 5, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}}}},
	}}}
	badUser := proto.Clone(usr).(*corev1.User)
	badUser.Spec.Type = corev1.User_Spec_TYPE_UNKNOWN
	c := h.CoreC()
	cases := []struct {
		name string
		call func(context.Context) error
	}{
		{"ReadService", func(ctx context.Context) error {
			got, err := c.GetService(ctx, &metav1.GetOptions{Uid: svc.Metadata.Uid})
			if err != nil {
				return err
			}
			if !proto.Equal(svc.Spec, got.Spec) {
				return fmt.Errorf("a rejected request changed the Service spec")
			}
			return nil
		}},
		{"ReadUser", func(ctx context.Context) error {
			got, err := c.GetUser(ctx, &metav1.GetOptions{Uid: usr.Metadata.Uid})
			if err != nil {
				return err
			}
			if !proto.Equal(usr.Spec, got.Spec) {
				return fmt.Errorf("a rejected request changed the User spec")
			}
			return nil
		}},
		{"CreateUser", func(ctx context.Context) error { _, err := c.CreateUser(ctx, &corev1.User{}); return err }},
		{"CreatePolicy", func(ctx context.Context) error { _, err := c.CreatePolicy(ctx, &corev1.Policy{}); return err }},
		{"CreateSecret", func(ctx context.Context) error { _, err := c.CreateSecret(ctx, &corev1.Secret{}); return err }},
		{"CreateCredential", func(ctx context.Context) error { _, err := c.CreateCredential(ctx, &corev1.Credential{}); return err }},
		{"GetService", func(ctx context.Context) error {
			_, err := c.GetService(ctx, &metav1.GetOptions{Name: "service' OR '1'='1"})
			return err
		}},
		{"UpdateServicePort", func(ctx context.Context) error { _, err := c.UpdateService(ctx, badPort); return err }},
		{"UpdateServiceAuth", func(ctx context.Context) error { _, err := c.UpdateService(ctx, badAuth); return err }},
		{"UpdateServicePolicy", func(ctx context.Context) error { _, err := c.UpdateService(ctx, badPolicy); return err }},
		{"UpdateUser", func(ctx context.Context) error { _, err := c.UpdateUser(ctx, badUser); return err }},
	}
	check := func(ctx context.Context, idx int) error {
		want := codes.InvalidArgument
		if idx < 2 {
			want = codes.OK
		}
		err := cases[idx].call(ctx)
		if status.Code(err) != want {
			return fmt.Errorf("%s: got %s, want %s: %v", cases[idx].name, status.Code(err), want, err)
		}
		return nil
	}
	for i := range cases {
		require.Nil(t, check(t.Context(), i), cases[i].name)
	}
	completed := make([]atomic.Int64, len(cases))
	result := harness.RunFor(t.Context(), 3*time.Second, 16, func(ctx context.Context, worker, iteration int) error {
		idx := (worker + iteration) % len(cases)
		if err := check(ctx, idx); err != nil {
			return err
		}
		completed[idx].Add(1)
		return nil
	})
	assert.Zero(t, result.Failed(), "%s", result.Errors.String())
	for i := range cases {
		assert.Positive(t, completed[i].Load(), cases[i].name)
	}
	require.Nil(t, check(t.Context(), 0))
	require.Nil(t, check(t.Context(), 1))
	harness.LogPool("API validation and resource isolation under load", result)
}

func testAPIUserSelfProtection(t *testing.T, h *harness.H) {
	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{Policies: []string{"octelium-api-full-access"}})
	cred := h.CreateCredential(t, harness.CredentialOpts{User: usr.Metadata.Name, Type: corev1.Credential_Spec_AUTH_TOKEN, SessionType: corev1.Session_Status_CLIENTLESS})
	token := h.CredentialToken(t, cred)
	client, err := octelium.NewClient(t.Context(), octelium.WithDomain(h.Domain), octelium.WithAuthenticator(octelium.AuthenticationToken(token.GetAuthenticationToken().AuthenticationToken)))
	require.Nil(t, err)
	t.Cleanup(func() { client.Close() })
	conn, err := client.Conn(t.Context())
	require.Nil(t, err)
	c := corev1.NewMainServiceClient(conn)
	h.Eventually(t, "the isolated administrator to have API access", authzBudget, func(ctx context.Context) error {
		_, err := c.GetUser(ctx, &metav1.GetOptions{Uid: usr.Metadata.Uid})
		return err
	})
	info, err := userv1.NewMainServiceClient(conn).GetStatus(t.Context(), &userv1.GetStatusRequest{})
	require.Nil(t, err)
	sess, err := c.GetSession(t.Context(), &metav1.GetOptions{Uid: info.Session.Metadata.Uid})
	require.Nil(t, err)
	badUser := proto.Clone(usr).(*corev1.User)
	badUser.Spec.IsDisabled = true
	badSession := proto.Clone(sess).(*corev1.Session)
	badSession.Spec.State = corev1.Session_Spec_REJECTED
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"DisableOwnUser", func() error { _, err := c.UpdateUser(t.Context(), badUser); return err }},
		{"DeleteOwnUser", func() error {
			_, err := c.DeleteUser(t.Context(), &metav1.DeleteOptions{Uid: usr.Metadata.Uid})
			return err
		}},
		{"RejectOwnSession", func() error { _, err := c.UpdateSession(t.Context(), badSession); return err }},
		{"DeleteOwnSession", func() error {
			_, err := c.DeleteSession(t.Context(), &metav1.DeleteOptions{Uid: sess.Metadata.Uid})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, codes.PermissionDenied, status.Code(tc.call()))
		})
	}
	storedUser, err := h.CoreC().GetUser(t.Context(), &metav1.GetOptions{Uid: usr.Metadata.Uid})
	require.Nil(t, err)
	assert.False(t, storedUser.Spec.IsDisabled)
	storedSession, err := h.CoreC().GetSession(t.Context(), &metav1.GetOptions{Uid: sess.Metadata.Uid})
	require.Nil(t, err)
	assert.Equal(t, corev1.Session_Spec_ACTIVE, storedSession.Spec.State)
}

func testAPIEnumValidation(t *testing.T, h *harness.H) {
	owner := newHumanSession(t, h)
	deviceRef := registerDevice(t, owner)
	authn := createTOTPAuthenticator(t, owner, "e2e enum validation")
	c := h.CoreC()
	authenticator, err := c.GetAuthenticator(t.Context(), &metav1.GetOptions{Uid: authn.Metadata.Uid})
	require.Nil(t, err)
	device, err := c.GetDevice(t.Context(), &metav1.GetOptions{Uid: deviceRef.Uid})
	require.Nil(t, err)
	session := owner.Session(t)

	for _, state := range []int32{0, -1, 4, 1000, math.MinInt32, math.MaxInt32} {
		t.Run(fmt.Sprintf("State%d", state), func(t *testing.T) {
			t.Run("Authenticator", func(t *testing.T) {
				req := proto.Clone(authenticator).(*corev1.Authenticator)
				req.Spec.State = corev1.Authenticator_Spec_State(state)
				_, err := c.UpdateAuthenticator(t.Context(), req)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				stored, err := c.GetAuthenticator(t.Context(), &metav1.GetOptions{Uid: authenticator.Metadata.Uid})
				require.Nil(t, err)
				assert.True(t, proto.Equal(authenticator.Spec, stored.Spec))
			})
			t.Run("Device", func(t *testing.T) {
				req := proto.Clone(device).(*corev1.Device)
				req.Spec.State = corev1.Device_Spec_State(state)
				_, err := c.UpdateDevice(t.Context(), req)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				stored, err := c.GetDevice(t.Context(), &metav1.GetOptions{Uid: device.Metadata.Uid})
				require.Nil(t, err)
				assert.True(t, proto.Equal(device.Spec, stored.Spec))
			})
			t.Run("Session", func(t *testing.T) {
				req := proto.Clone(session).(*corev1.Session)
				req.Spec.State = corev1.Session_Spec_State(state)
				_, err := c.UpdateSession(t.Context(), req)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				stored, err := c.GetSession(t.Context(), &metav1.GetOptions{Uid: session.Metadata.Uid})
				require.Nil(t, err)
				assert.True(t, proto.Equal(session.Spec, stored.Spec))
			})
		})
	}

	ns := h.EnsureTestNamespace(t)
	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{Name: fmt.Sprintf("%s.%s", h.Name(), ns.Metadata.Name)},
		Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Config: &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://127.0.0.1:8080"}},
		}},
	})
	for _, mode := range []corev1.Service_Spec_Mode{corev1.Service_Spec_MODE_UNSET, -1, 16, 1000, math.MinInt32, math.MaxInt32} {
		t.Run(fmt.Sprintf("Mode%d", mode), func(t *testing.T) {
			t.Run("Create", func(t *testing.T) {
				req := proto.Clone(svc).(*corev1.Service)
				req.Metadata = &metav1.Metadata{Name: fmt.Sprintf("%s.%s", h.Name(), ns.Metadata.Name)}
				req.Status = nil
				req.Spec.Mode = mode
				_, err := c.CreateService(t.Context(), req)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				_, err = c.GetService(t.Context(), &metav1.GetOptions{Name: req.Metadata.Name})
				assert.Equal(t, codes.NotFound, status.Code(err))
			})
			t.Run("Update", func(t *testing.T) {
				req := proto.Clone(svc).(*corev1.Service)
				req.Spec.Mode = mode
				_, err := c.UpdateService(t.Context(), req)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				stored, err := c.GetService(t.Context(), &metav1.GetOptions{Uid: svc.Metadata.Uid})
				require.Nil(t, err)
				assert.True(t, proto.Equal(svc.Spec, stored.Spec))
			})
		})
	}
}
