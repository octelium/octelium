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
	"path"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func newFakeServer(fakeC *tests.FakeClient) *Server {

	return &Server{
		octeliumC: fakeC.OcteliumC,
	}
}

type tstCoreConn struct {
	grpc.ClientConnInterface
	invoke func(string, any, any) error
}

func (c *tstCoreConn) Invoke(ctx context.Context, method string, req, resp any, opts ...grpc.CallOption) error {
	return c.invoke(path.Base(method), req, resp)
}

type tstOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *tstOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

func newTstServer(invoke func(string, any, any) error) *Server {
	return NewServer(&Opts{OcteliumC: &tstOcteliumC{coreC: rcorev1.NewResourceServiceClient(&tstCoreConn{invoke: invoke})}})
}

func TestGetResourceErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*Server, *metav1.GetOptions) error
	}{
		{"User", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetUser(t.Context(), o); return err }},
		{"Group", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetGroup(t.Context(), o); return err }},
		{"Namespace", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetNamespace(t.Context(), o); return err }},
		{"Policy", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetPolicy(t.Context(), o); return err }},
		{"Service", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetService(t.Context(), o); return err }},
		{"Session", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetSession(t.Context(), o); return err }},
		{"Device", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetDevice(t.Context(), o); return err }},
		{"Authenticator", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetAuthenticator(t.Context(), o); return err }},
		{"Credential", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetCredential(t.Context(), o); return err }},
		{"IdentityProvider", func(s *Server, o *metav1.GetOptions) error {
			_, err := s.GetIdentityProvider(t.Context(), o)
			return err
		}},
		{"Config", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetConfig(t.Context(), o); return err }},
		{"Secret", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetSecret(t.Context(), o); return err }},
		{"Gateway", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetGateway(t.Context(), o); return err }},
		{"Region", func(s *Server, o *metav1.GetOptions) error { _, err := s.GetRegion(t.Context(), o); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := newTstServer(func(method string, req, resp any) error {
				calls++
				assert.Equal(t, "Get"+tc.name, method)
				return status.Error(codes.Unavailable, "sensitive backend detail")
			})
			for _, req := range []*metav1.GetOptions{nil, {}, {Name: "invalid/name"}, {Uid: "invalid"}, {Name: "resource\x00"}} {
				assert.Equal(t, codes.InvalidArgument, status.Code(tc.call(srv, req)))
			}
			assert.Zero(t, calls)
			err := tc.call(srv, &metav1.GetOptions{Name: "resource"})
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.Equal(t, 1, calls)
			srv = newTstServer(func(method string, req, resp any) error { return status.Error(codes.NotFound, "missing") })
			assert.Equal(t, codes.NotFound, status.Code(tc.call(srv, &metav1.GetOptions{Name: "resource"})))
		})
	}
}

func TestListResourceErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*Server) error
	}{
		{"User", func(s *Server) error { _, err := s.ListUser(t.Context(), &corev1.ListUserOptions{}); return err }},
		{"Group", func(s *Server) error { _, err := s.ListGroup(t.Context(), &corev1.ListGroupOptions{}); return err }},
		{"Namespace", func(s *Server) error {
			_, err := s.ListNamespace(t.Context(), &corev1.ListNamespaceOptions{})
			return err
		}},
		{"Policy", func(s *Server) error { _, err := s.ListPolicy(t.Context(), &corev1.ListPolicyOptions{}); return err }},
		{"Service", func(s *Server) error { _, err := s.ListService(t.Context(), &corev1.ListServiceOptions{}); return err }},
		{"Session", func(s *Server) error { _, err := s.ListSession(t.Context(), &corev1.ListSessionOptions{}); return err }},
		{"Device", func(s *Server) error { _, err := s.ListDevice(t.Context(), &corev1.ListDeviceOptions{}); return err }},
		{"Authenticator", func(s *Server) error {
			_, err := s.ListAuthenticator(t.Context(), &corev1.ListAuthenticatorOptions{})
			return err
		}},
		{"Credential", func(s *Server) error {
			_, err := s.ListCredential(t.Context(), &corev1.ListCredentialOptions{})
			return err
		}},
		{"IdentityProvider", func(s *Server) error {
			_, err := s.ListIdentityProvider(t.Context(), &corev1.ListIdentityProviderOptions{})
			return err
		}},
		{"Config", func(s *Server) error { _, err := s.ListConfig(t.Context(), &corev1.ListConfigOptions{}); return err }},
		{"Secret", func(s *Server) error { _, err := s.ListSecret(t.Context(), &corev1.ListSecretOptions{}); return err }},
		{"Gateway", func(s *Server) error { _, err := s.ListGateway(t.Context(), &corev1.ListGatewayOptions{}); return err }},
		{"Region", func(s *Server) error { _, err := s.ListRegion(t.Context(), &corev1.ListRegionOptions{}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := newTstServer(func(method string, req, resp any) error {
				calls++
				assert.Equal(t, "List"+tc.name, method)
				return status.Error(codes.PermissionDenied, "denied")
			})
			assert.Equal(t, codes.PermissionDenied, status.Code(tc.call(srv)))
			assert.Equal(t, 1, calls)
		})
	}
}

func TestProtectedResourceMutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		item   proto.Message
		update func(*Server) error
		delete func(*Server) error
	}{
		{"User", &corev1.User{Metadata: &metav1.Metadata{Name: "resource", IsSystem: true}},
			func(s *Server) error {
				_, err := s.UpdateUser(t.Context(), &corev1.User{Metadata: &metav1.Metadata{Name: "resource"}, Spec: &corev1.User_Spec{Type: corev1.User_Spec_WORKLOAD}})
				return err
			},
			func(s *Server) error {
				_, err := s.DeleteUser(t.Context(), &metav1.DeleteOptions{Name: "resource"})
				return err
			}},
		{"Group", &corev1.Group{Metadata: &metav1.Metadata{Name: "resource", IsSystem: true}},
			func(s *Server) error {
				_, err := s.UpdateGroup(t.Context(), &corev1.Group{Metadata: &metav1.Metadata{Name: "resource"}, Spec: &corev1.Group_Spec{}})
				return err
			},
			func(s *Server) error {
				_, err := s.DeleteGroup(t.Context(), &metav1.DeleteOptions{Name: "resource"})
				return err
			}},
		{"Namespace", &corev1.Namespace{Metadata: &metav1.Metadata{Name: "resource", IsSystem: true}},
			func(s *Server) error {
				_, err := s.UpdateNamespace(t.Context(), &corev1.Namespace{Metadata: &metav1.Metadata{Name: "resource"}, Spec: &corev1.Namespace_Spec{}})
				return err
			},
			func(s *Server) error {
				_, err := s.DeleteNamespace(t.Context(), &metav1.DeleteOptions{Name: "resource"})
				return err
			}},
		{"Policy", &corev1.Policy{Metadata: &metav1.Metadata{Name: "resource", IsSystem: true}},
			func(s *Server) error {
				_, err := s.UpdatePolicy(t.Context(), genPolicyWithCondition("resource", genMatchAnyCondition()))
				return err
			},
			func(s *Server) error {
				_, err := s.DeletePolicy(t.Context(), &metav1.DeleteOptions{Name: "resource"})
				return err
			}},
		{"Service", &corev1.Service{Metadata: &metav1.Metadata{Name: "resource.default", IsSystem: true}},
			func(s *Server) error {
				_, err := s.UpdateService(t.Context(), &corev1.Service{Metadata: &metav1.Metadata{Name: "resource"}, Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}})
				return err
			},
			func(s *Server) error {
				_, err := s.DeleteService(t.Context(), &metav1.DeleteOptions{Name: "resource"})
				return err
			}},
		{"Secret", &corev1.Secret{Metadata: &metav1.Metadata{Name: "resource", IsSystem: true}},
			func(s *Server) error {
				_, err := s.UpdateSecret(t.Context(), &corev1.Secret{Metadata: &metav1.Metadata{Name: "resource"}, Spec: &corev1.Secret_Spec{}, Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "secret"}}})
				return err
			},
			func(s *Server) error {
				_, err := s.DeleteSecret(t.Context(), &metav1.DeleteOptions{Name: "resource"})
				return err
			}},
		{"Config", &corev1.Config{Metadata: &metav1.Metadata{Name: "resource", IsSystem: true}},
			func(s *Server) error {
				_, err := s.UpdateConfig(t.Context(), &corev1.Config{Metadata: &metav1.Metadata{Name: "resource"}, Spec: &corev1.Config_Spec{}, Data: &corev1.Config_Data{Type: &corev1.Config_Data_Value{Value: "configuration"}}})
				return err
			},
			func(s *Server) error {
				_, err := s.DeleteConfig(t.Context(), &metav1.DeleteOptions{Name: "resource"})
				return err
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := newTstServer(func(method string, req, resp any) error {
				calls++
				require.Equal(t, "Get"+tc.name, method)
				proto.Merge(resp.(proto.Message), tc.item)
				return nil
			})
			assert.Equal(t, codes.PermissionDenied, status.Code(tc.update(s)))
			assert.Equal(t, codes.PermissionDenied, status.Code(tc.delete(s)))
			assert.Equal(t, 2, calls)
		})
	}
}
