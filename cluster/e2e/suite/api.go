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
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
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
	const requestsPerCase = 128
	completed := make([]atomic.Int64, len(cases))
	result := harness.ForEach(t.Context(), requestsPerCase*len(cases), 16, func(ctx context.Context, i int) error {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		idx := i % len(cases)
		if err := check(ctx, idx); err != nil {
			return err
		}
		completed[idx].Add(1)
		return nil
	})
	assert.Zero(t, result.Failed(), "%s", result.Errors.String())
	for i := range cases {
		assert.Equal(t, int64(requestsPerCase), completed[i].Load(), cases[i].name)
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

func testAPIHeaderValidation(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)
	token := h.Name()
	secret := h.CreateSecret(t, "", token)
	response := h.Name()
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x_e2e-auth") != token || r.Header.Get("X-E2E-Remove") != "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-E2E-Remove", "upstream")
		w.Write([]byte(response))
	})
	v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
		Header: &corev1.Service_Spec_Config_HTTP_Header{
			AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
				{Key: "X-E2E-Safe", Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "safe value"}},
			},
			RemoveRequestHeaders:  []string{"X-E2E-Remove"},
			RemoveResponseHeaders: []string{"X-E2E-Remove"},
		},
		Auth: &corev1.Service_Spec_Config_HTTP_Auth{
			Type: &corev1.Service_Spec_Config_HTTP_Auth_Custom_{
				Custom: &corev1.Service_Spec_Config_HTTP_Auth_Custom{
					Header: "x_e2e-auth",
					Value: &corev1.Service_Spec_Config_HTTP_Auth_Custom_Value{
						Type: &corev1.Service_Spec_Config_HTTP_Auth_Custom_Value_FromSecret{FromSecret: secret.Metadata.Name},
					},
				},
			},
		},
	})
	c := h.HTTPNoRetry().SetBaseURL(v.url("")).SetHeader("X-E2E-Remove", "downstream")
	t.Cleanup(c.GetClient().CloseIdleConnections)
	check := func(ctx context.Context) error {
		res, err := c.R().SetContext(ctx).Get("/")
		if err != nil {
			return err
		}
		if res.StatusCode() != http.StatusOK {
			return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}
		if res.String() != response || res.Header().Get("X-E2E-Safe") != "safe value" ||
			res.Header().Get("X-E2E-Remove") != "" || res.Header().Get("X-E2E-Injected") != "" {
			return fmt.Errorf("the Service did not preserve its valid header configuration")
		}
		return nil
	}
	h.Eventually(t, "the Service to apply its valid header configuration", harness.DecisionBudget, check)
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Service_Spec_Config_HTTP)
	}{
		{"ResponseCRLF", func(cfg *corev1.Service_Spec_Config_HTTP) {
			cfg.Header.AddResponseHeaders[0].Type = &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "value\r\nX-E2E-Injected: true"}
		}},
		{"ResponseLF", func(cfg *corev1.Service_Spec_Config_HTTP) {
			cfg.Header.AddResponseHeaders[0].Type = &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "value\nX-E2E-Injected: true"}
		}},
		{"ResponseControl", func(cfg *corev1.Service_Spec_Config_HTTP) {
			cfg.Header.AddResponseHeaders[0].Type = &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "value\x00"}
		}},
		{"CustomAuthName", func(cfg *corev1.Service_Spec_Config_HTTP) {
			cfg.Auth.GetCustom().Header = "Bad Header"
		}},
		{"RemoveRequestName", func(cfg *corev1.Service_Spec_Config_HTTP) {
			cfg.Header.RemoveRequestHeaders = []string{"Bad Header"}
		}},
		{"RemoveResponseName", func(cfg *corev1.Service_Spec_Config_HTTP) {
			cfg.Header.RemoveResponseHeaders = []string{"X-E2E-Remove:"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(v.svc).(*corev1.Service)
			tc.mutate(req.Spec.Config.GetHttp())
			create := proto.Clone(req).(*corev1.Service)
			create.Metadata = &metav1.Metadata{Name: fmt.Sprintf("%s.default", h.Name())}
			create.Status = nil
			_, err := h.CoreC().CreateService(t.Context(), create)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			_, err = h.CoreC().GetService(t.Context(), &metav1.GetOptions{Name: create.Metadata.Name})
			assert.Equal(t, codes.NotFound, status.Code(err))
			_, err = h.CoreC().UpdateService(t.Context(), req)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			stored, err := h.CoreC().GetService(t.Context(), &metav1.GetOptions{Uid: v.svc.Metadata.Uid})
			require.Nil(t, err)
			assert.True(t, proto.Equal(v.svc.Spec, stored.Spec))
			h.Eventually(t, "the Service to retain its header configuration after rejected writes", harness.DecisionBudget, check)
		})
	}
}

func testAPIDynamicConfigTargets(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)
	response := h.Name()
	v.record(t, http.StatusOK, response)
	v.svc.Spec.Config.Type = &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
		Header: &corev1.Service_Spec_Config_HTTP_Header{
			AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{{
				Key:  "X-E2E-Config",
				Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "default"},
			}},
		},
	}}
	selected := proto.Clone(v.svc.Spec.Config).(*corev1.Service_Spec_Config)
	selected.Name = "selected"
	selected.GetHttp().Header.AddResponseHeaders[0].Type = &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "selected"}
	other := proto.Clone(v.svc.Spec.Config).(*corev1.Service_Spec_Config)
	other.Name = "other"
	v.svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
		Configs: []*corev1.Service_Spec_Config{selected, other},
		Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
			{
				Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: `ctx.request.http.path.startsWith("/selected")`}},
				Type:      &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "selected"},
			},
			{
				Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
				Type:      &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "default"},
			},
		},
	}
	v.svc = h.UpdateService(t, v.svc)
	c := h.HTTPNoRetry()
	t.Cleanup(c.GetClient().CloseIdleConnections)
	selectedHeader := "selected"
	check := func(ctx context.Context) error {
		for _, tc := range []struct {
			path   string
			header string
		}{
			{"/selected", selectedHeader},
			{"/", "default"},
		} {
			res, err := c.R().SetContext(ctx).Get(v.url(tc.path))
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
			}
			if res.String() != response || res.Header().Get("X-E2E-Config") != tc.header {
				return fmt.Errorf("the request to %s did not use the expected %s config", tc.path, tc.header)
			}
		}
		return nil
	}
	h.Eventually(t, "requests to select the named and default configs", harness.DecisionBudget, check)
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Service)
	}{
		{"MissingTarget", func(svc *corev1.Service) {
			svc.Spec.DynamicConfig.Rules[0].Type = &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "missing"}
		}},
		{"RenamedTarget", func(svc *corev1.Service) { svc.Spec.DynamicConfig.Configs[0].Name = "renamed" }},
		{"RemovedTarget", func(svc *corev1.Service) { svc.Spec.DynamicConfig.Configs = svc.Spec.DynamicConfig.Configs[1:] }},
		{"MissingDefault", func(svc *corev1.Service) { svc.Spec.Config = nil }},
		{"UnmatchedMissingTarget", func(svc *corev1.Service) {
			svc.Spec.DynamicConfig.Rules = append(svc.Spec.DynamicConfig.Rules, &corev1.Service_Spec_DynamicConfig_Rule{
				Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: false}},
				Type:      &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "missing"},
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(v.svc).(*corev1.Service)
			tc.mutate(req)
			create := proto.Clone(req).(*corev1.Service)
			create.Metadata = &metav1.Metadata{Name: fmt.Sprintf("%s.default", h.Name())}
			create.Status = nil
			_, err := h.CoreC().CreateService(t.Context(), create)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			_, err = h.CoreC().GetService(t.Context(), &metav1.GetOptions{Name: create.Metadata.Name})
			assert.Equal(t, codes.NotFound, status.Code(err))
			_, err = h.CoreC().UpdateService(t.Context(), req)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			stored, err := h.CoreC().GetService(t.Context(), &metav1.GetOptions{Uid: v.svc.Metadata.Uid})
			require.Nil(t, err)
			assert.True(t, proto.Equal(v.svc.Spec, stored.Spec))
			h.Eventually(t, "rejected writes to preserve dynamic config routing", harness.DecisionBudget, check)
		})
	}

	v.svc.Spec.DynamicConfig.Configs[0].Name = "renamed"
	v.svc.Spec.DynamicConfig.Configs[0].GetHttp().Header.AddResponseHeaders[0].Type = &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "renamed"}
	v.svc.Spec.DynamicConfig.Rules[0].Type = &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "renamed"}
	v.svc = h.UpdateService(t, v.svc)
	selectedHeader = "renamed"
	h.Eventually(t, "a renamed config and its updated rule to keep routing requests", harness.DecisionBudget, check)

	v.svc.Spec.DynamicConfig.Configs = v.svc.Spec.DynamicConfig.Configs[1:]
	v.svc.Spec.DynamicConfig.Rules[0].Type = &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "default"}
	v.svc = h.UpdateService(t, v.svc)
	selectedHeader = "default"
	h.Eventually(t, "an updated rule to use the default after removing its previous config", harness.DecisionBudget, check)
}

func testAPIContainerValidation(t *testing.T, h *harness.H) {
	response := h.Name()
	svc := h.CreateService(t, &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Container_{
						Container: &corev1.Service_Spec_Config_Upstream_Container{
							Image:   "nginx",
							Port:    80,
							Command: []string{"/bin/sh", "-c"},
							Args:    []string{`mkdir -p /data/html && printf '%s' "$OCTELIUM_E2E_RESPONSE" > /data/html/index.html && exec nginx -g 'daemon off;'`},
							Env: []*corev1.Service_Spec_Config_Upstream_Container_Env{
								{Name: "OCTELIUM_E2E_RESPONSE", Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: response}},
							},
							Volumes: []*corev1.Service_Spec_Config_Upstream_Container_Volume{{
								Name: "data",
								Type: &corev1.Service_Spec_Config_Upstream_Container_Volume_EmptyDir_{EmptyDir: &corev1.Service_Spec_Config_Upstream_Container_Volume_EmptyDir{}},
							}},
							VolumeMounts: []*corev1.Service_Spec_Config_Upstream_Container_VolumeMount{
								{Name: "data", MountPath: "/data"},
								{Name: "data", MountPath: "/usr/share/nginx/html", SubPath: "html", ReadOnly: true},
							},
							ReadinessProbe: &corev1.Service_Spec_Config_Upstream_Container_Probe{
								Type: &corev1.Service_Spec_Config_Upstream_Container_Probe_HttpGet{HttpGet: &corev1.Service_Spec_Config_Upstream_Container_Probe_HTTPGet{
									Path: "/", Port: 80,
								}},
								PeriodSeconds: 1, SuccessThreshold: 2,
							},
							LivenessProbe: &corev1.Service_Spec_Config_Upstream_Container_Probe{
								Type: &corev1.Service_Spec_Config_Upstream_Container_Probe_TcpSocket{TcpSocket: &corev1.Service_Spec_Config_Upstream_Container_Probe_TCPSocket{Port: 80}},
							},
						},
					},
				},
			},
		},
	})
	h.MustWaitServiceUpstream(t, svc.Metadata.Name)
	h.MustWaitService(t, svc.Metadata.Name)
	upstream := k8sutils.GetSvcK8sUpstreamHostname(svc, "")
	conn := h.Connect(t, harness.ConnectOpts{Publish: map[string]int{svc.Metadata.Name: h.Port()}})
	c := h.HTTPNoRetry().SetBaseURL(conn.URL(svc.Metadata.Name))
	t.Cleanup(c.GetClient().CloseIdleConnections)
	livenessPeriod := int32(10)
	readinessSuccess := int32(2)
	check := func(ctx context.Context) error {
		dep, err := h.K8sDeployment(ctx, upstream)
		if err != nil {
			return err
		}
		if dep.Status.ObservedGeneration < dep.Generation || dep.Status.ReadyReplicas != 1 ||
			dep.Status.UpdatedReplicas != 1 || dep.Status.Replicas != 1 {
			return fmt.Errorf("the managed container has not completed its rollout")
		}
		pod := dep.Spec.Template.Spec
		if len(pod.Volumes) != 1 || pod.Volumes[0].Name != "data" || pod.Volumes[0].EmptyDir == nil || len(pod.Containers) != 1 {
			return fmt.Errorf("the managed container does not have the expected volume")
		}
		container := pod.Containers[0]
		if len(container.VolumeMounts) != 2 || container.VolumeMounts[0].Name != "data" || container.VolumeMounts[0].MountPath != "/data" ||
			container.VolumeMounts[1].Name != "data" || container.VolumeMounts[1].MountPath != "/usr/share/nginx/html" ||
			container.VolumeMounts[1].SubPath != "html" || !container.VolumeMounts[1].ReadOnly {
			return fmt.Errorf("the managed container does not have the expected volume mounts")
		}
		liveness, readiness := container.LivenessProbe, container.ReadinessProbe
		if liveness == nil || liveness.TCPSocket == nil || liveness.TCPSocket.Port.IntVal != 80 || liveness.InitialDelaySeconds != 0 ||
			liveness.TimeoutSeconds != 1 || liveness.PeriodSeconds != livenessPeriod || liveness.SuccessThreshold != 1 || liveness.FailureThreshold != 3 {
			return fmt.Errorf("the managed container does not have the expected liveness probe")
		}
		if readiness == nil || readiness.HTTPGet == nil || readiness.HTTPGet.Path != "/" || readiness.HTTPGet.Port.IntVal != 80 ||
			readiness.InitialDelaySeconds != 0 || readiness.TimeoutSeconds != 1 || readiness.PeriodSeconds != 1 ||
			readiness.SuccessThreshold != readinessSuccess || readiness.FailureThreshold != 3 {
			return fmt.Errorf("the managed container does not have the expected readiness probe")
		}
		res, err := c.R().SetContext(ctx).Get("/")
		if err != nil {
			return err
		}
		if res.StatusCode() != http.StatusOK {
			return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}
		if res.String() != response {
			return fmt.Errorf("the managed container returned %q, want %q", res.String(), response)
		}
		return nil
	}
	h.Eventually(t, "the valid mounts and defaulted probes to serve requests", harness.DeploymentBudget, check)
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Service_Spec_Config_Upstream_Container)
	}{
		{"EmptyMountPath", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.VolumeMounts[0].MountPath = "" }},
		{"MissingVolume", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.VolumeMounts[0].Name = "missing" }},
		{"DuplicateVolume", func(c *corev1.Service_Spec_Config_Upstream_Container) {
			c.Volumes = append(c.Volumes, proto.Clone(c.Volumes[0]).(*corev1.Service_Spec_Config_Upstream_Container_Volume))
		}},
		{"DuplicateMountPath", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.VolumeMounts[1].MountPath = "/data" }},
		{"AbsoluteSubPath", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.VolumeMounts[1].SubPath = "/html" }},
		{"ParentSubPath", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.VolumeMounts[1].SubPath = "nested/../html" }},
		{"NULSubPath", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.VolumeMounts[1].SubPath = "html\x00" }},
		{"ReadinessTiming", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.ReadinessProbe.TimeoutSeconds = -1 }},
		{"LivenessTiming", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.LivenessProbe.InitialDelaySeconds = -1 }},
		{"ReadinessThreshold", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.ReadinessProbe.FailureThreshold = -1 }},
		{"LivenessSuccessThreshold", func(c *corev1.Service_Spec_Config_Upstream_Container) { c.LivenessProbe.SuccessThreshold = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(svc).(*corev1.Service)
			tc.mutate(req.Spec.Config.Upstream.GetContainer())
			create := proto.Clone(req).(*corev1.Service)
			create.Metadata = &metav1.Metadata{Name: fmt.Sprintf("%s.default", h.Name())}
			create.Status = nil
			_, err := h.CoreC().CreateService(t.Context(), create)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			_, err = h.CoreC().GetService(t.Context(), &metav1.GetOptions{Name: create.Metadata.Name})
			assert.Equal(t, codes.NotFound, status.Code(err))
			_, err = h.CoreC().UpdateService(t.Context(), req)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			stored, err := h.CoreC().GetService(t.Context(), &metav1.GetOptions{Uid: svc.Metadata.Uid})
			require.Nil(t, err)
			assert.True(t, proto.Equal(svc.Spec, stored.Spec))
			h.Eventually(t, "rejected container settings to preserve the healthy upstream", harness.DecisionBudget, check)
		})
	}
	container := svc.Spec.Config.Upstream.GetContainer()
	container.LivenessProbe.PeriodSeconds = 1
	container.LivenessProbe.SuccessThreshold = 1
	container.ReadinessProbe.SuccessThreshold = 0
	response = h.Name()
	container.Env[0].Type = &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: response}
	svc = h.UpdateService(t, svc)
	livenessPeriod, readinessSuccess = 1, 1
	h.Eventually(t, "valid probe updates and defaulting to complete a healthy rollout", harness.DeploymentBudget, check)
}

func testAPILLMToolDefinitions(t *testing.T, h *harness.H) {
	upstream := h.StartLLMUpstream(t, nil)
	const object = `{"type":"function","function":{"name":"service_tool","description":null}}`
	svc := h.CreateService(t, &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_LLM,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: fmt.Sprintf("http://localhost:%d", upstream.Port)},
					User: "root",
				},
				Type: &corev1.Service_Spec_Config_Llm{Llm: &corev1.Service_Spec_Config_LLM{
					Protocol: corev1.Service_Spec_Config_LLM_OPENAI,
					Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{{
						Name: "tools", Condition: llmMatchAny(),
						Type: &corev1.Service_Spec_Config_LLM_Plugin_Tools_{Tools: &corev1.Service_Spec_Config_LLM_Plugin_Tools{
							Tools: []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool{{
								Type: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_Value{Value: object},
							}},
						}},
					}},
				}},
			},
		},
	})
	h.MustWaitService(t, svc.Metadata.Name)
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: h.Port()},
		Serve:   []string{svc.Metadata.Name},
	})
	c := h.HTTPNoRetry().SetBaseURL(conn.URL(svc.Metadata.Name))
	t.Cleanup(c.GetClient().CloseIdleConnections)
	request := func(ctx context.Context, definition string) (int, []byte, error) {
		res, err := c.R().SetContext(ctx).SetBody(map[string]any{
			"model":    "e2e-model",
			"messages": []any{map[string]any{"role": "user", "content": definition}},
			"tools":    []any{map[string]any{"type": "function", "function": map[string]any{"name": "client_tool"}}},
		}).Post("/v1/chat/completions")
		if err != nil {
			return 0, nil, err
		}
		return res.StatusCode(), res.Body(), nil
	}
	check := func(ctx context.Context, definition string, replacement bool) error {
		before := upstream.ReqCount()
		code, body, err := request(ctx, definition)
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("got status %d: %s", code, body)
		}
		if upstream.ReqCount() == before {
			return fmt.Errorf("the valid request did not reach the LLM upstream")
		}
		entries, _ := upstream.LastBody()["tools"].([]any)
		count := 2
		if replacement {
			count = 1
		}
		if len(entries) != count {
			return fmt.Errorf("got %d tools, want %d", len(entries), count)
		}
		var expected map[string]any
		if err := json.Unmarshal([]byte(definition), &expected); err != nil {
			return err
		}
		want, err := json.Marshal(expected)
		if err != nil {
			return err
		}
		got, err := json.Marshal(entries[len(entries)-1])
		if err != nil {
			return err
		}
		if string(got) != string(want) {
			return fmt.Errorf("got tool %s, want %s", got, want)
		}
		return nil
	}
	h.Eventually(t, "the valid static tool object to reach the upstream", harness.DecisionBudget,
		func(ctx context.Context) error { return check(ctx, object, false) })
	for _, replacement := range []bool{false, true} {
		for _, value := range []string{"null", " \t\r\nnull\r\n\t "} {
			t.Run(fmt.Sprintf("Static/Replacement%t/%q", replacement, value), func(t *testing.T) {
				req := proto.Clone(svc).(*corev1.Service)
				tools := req.Spec.Config.GetLlm().Plugins[0].GetTools()
				if replacement {
					tools.Filters = []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter{{
						Match:    &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name{Name: "client_tool"},
						Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REPLACE,
						Replace: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Replace{
							Type: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Replace_Value{Value: value},
						},
					}}
				} else {
					tools.Tools[0].Type = &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_Value{Value: value}
				}
				create := proto.Clone(req).(*corev1.Service)
				create.Metadata = &metav1.Metadata{Name: fmt.Sprintf("%s.default", h.Name())}
				create.Status = nil
				_, err := h.CoreC().CreateService(t.Context(), create)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				_, err = h.CoreC().GetService(t.Context(), &metav1.GetOptions{Name: create.Metadata.Name})
				assert.Equal(t, codes.NotFound, status.Code(err))
				_, err = h.CoreC().UpdateService(t.Context(), req)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				stored, err := h.CoreC().GetService(t.Context(), &metav1.GetOptions{Uid: svc.Metadata.Uid})
				require.Nil(t, err)
				assert.True(t, proto.Equal(svc.Spec, stored.Spec))
			})
		}
	}
	for _, source := range []string{"CEL", "OPA"} {
		for _, replacement := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/Replacement%t", source, replacement), func(t *testing.T) {
				tool := &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool{}
				replace := &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Replace{}
				if source == "CEL" {
					tool.Type = &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_Eval{Eval: `ctx.request.llm.http.bodyMap.messages[0].content`}
					replace.Type = &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Replace_Eval{Eval: tool.GetEval()}
				} else {
					tool.Type = &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_Opa{Opa: "package octelium.eval\nresult := input.ctx.request.llm.http.bodyMap.messages[0].content"}
					replace.Type = &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Replace_Opa{Opa: tool.GetOpa()}
				}
				cfg := &corev1.Service_Spec_Config_LLM_Plugin_Tools{}
				if replacement {
					cfg.Filters = []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter{{
						Match:    &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name{Name: "client_tool"},
						Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REPLACE,
						Replace:  replace,
					}}
				} else {
					cfg.Tools = []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool{tool}
				}
				svc.Spec.Config.GetLlm().Plugins[0].Type = &corev1.Service_Spec_Config_LLM_Plugin_Tools_{Tools: cfg}
				svc = h.UpdateService(t, svc)
				value := fmt.Sprintf(`{"type":"function","function":{"name":%q,"description":null}}`, h.Name())
				h.Eventually(t, "the evaluated tool object to reach the upstream", harness.DecisionBudget,
					func(ctx context.Context) error { return check(ctx, value, replacement) })
				for _, value := range []string{"null", " \t\r\nnull\r\n\t "} {
					before := upstream.ReqCount()
					code, body, err := request(t.Context(), value)
					require.Nil(t, err)
					assert.Equal(t, http.StatusInternalServerError, code)
					assert.Contains(t, string(body), "octelium_tool_denied")
					assert.Equal(t, before, upstream.ReqCount())
				}
				require.Nil(t, check(t.Context(), value, replacement))
			})
		}
	}
}
