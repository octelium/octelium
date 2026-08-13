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

package oscope

import (
	"fmt"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestGetScopeService(t *testing.T) {

	type tstArg struct {
		arg string
		out *corev1.Scope
	}

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		valids := []tstArg{
			{
				arg: "svc1",
				out: &corev1.Scope{
					Type: &corev1.Scope_Service_{
						Service: &corev1.Scope_Service{
							Type: &corev1.Scope_Service_Filter_{
								Filter: &corev1.Scope_Service_Filter{
									Names:      []string{"svc1"},
									Namespaces: []string{"default"},
								},
							},
						},
					},
				},
			},
			{
				arg: "svc1.ns1",
				out: &corev1.Scope{
					Type: &corev1.Scope_Service_{
						Service: &corev1.Scope_Service{
							Type: &corev1.Scope_Service_Filter_{
								Filter: &corev1.Scope_Service_Filter{
									Names:      []string{"svc1"},
									Namespaces: []string{"ns1"},
								},
							},
						},
					},
				},
			},
			{
				arg: "ns1/*",
				out: &corev1.Scope{
					Type: &corev1.Scope_Service_{
						Service: &corev1.Scope_Service{
							Type: &corev1.Scope_Service_Filter_{
								Filter: &corev1.Scope_Service_Filter{
									Names:      []string{"*"},
									Namespaces: []string{"ns1"},
								},
							},
						},
					},
				},
			},
			{
				arg: "*",
				out: &corev1.Scope{
					Type: &corev1.Scope_Service_{
						Service: &corev1.Scope_Service{
							Type: &corev1.Scope_Service_All_{
								All: &corev1.Scope_Service_All{},
							},
						},
					},
				},
			},
		}

		for _, valid := range valids {
			resp, err := getScopeService(valid.arg)
			assert.Nil(t, err)

			assert.True(t, pbutils.IsEqual(resp, valid.out))

			zap.L().Debug("RESP", zap.Any("resp", resp))
		}
	}

	{
		invalids := []string{
			"",
			":",
			"::",
			"a:b",
			"**",
			"Svc1",
			"svc.Ns1",
			"ns2/",
			"Ns2/*",
			"/",
			"*/*",
		}

		for _, invalid := range invalids {
			_, err := getScopeService(invalid)
			assert.NotNil(t, err)
		}
	}
}

func TestGetScopeAPI(t *testing.T) {

	type tstArg struct {
		arg string
		out *corev1.Scope
	}

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		valids := []tstArg{
			{
				arg: "core",
				out: &corev1.Scope{
					Type: &corev1.Scope_Api{
						Api: &corev1.Scope_API{
							Type: &corev1.Scope_API_Filter_{
								Filter: &corev1.Scope_API_Filter{
									Packages: []string{"octelium.api.main.core.v1"},
									Services: []string{"*"},
									Methods:  []string{"*"},
								},
							},
						},
					},
				},
			},
			{
				arg: "user",
				out: &corev1.Scope{
					Type: &corev1.Scope_Api{
						Api: &corev1.Scope_API{
							Type: &corev1.Scope_API_Filter_{
								Filter: &corev1.Scope_API_Filter{
									Packages: []string{"octelium.api.main.user.v1"},
									Services: []string{"*"},
									Methods:  []string{"*"},
								},
							},
						},
					},
				},
			},
			{
				arg: "custom",
				out: &corev1.Scope{
					Type: &corev1.Scope_Api{
						Api: &corev1.Scope_API{
							Type: &corev1.Scope_API_Filter_{
								Filter: &corev1.Scope_API_Filter{
									Packages: []string{"octelium.api.main.custom.v1"},
									Services: []string{"*"},
									Methods:  []string{"*"},
								},
							},
						},
					},
				},
			},

			{
				arg: "core.SomeService",
				out: &corev1.Scope{
					Type: &corev1.Scope_Api{
						Api: &corev1.Scope_API{
							Type: &corev1.Scope_API_Filter_{
								Filter: &corev1.Scope_API_Filter{
									Packages: []string{"octelium.api.main.core.v1"},
									Services: []string{"SomeService"},
									Methods:  []string{"*"},
								},
							},
						},
					},
				},
			},
			{
				arg: "cluster.SomeService/DoSomething",
				out: &corev1.Scope{
					Type: &corev1.Scope_Api{
						Api: &corev1.Scope_API{
							Type: &corev1.Scope_API_Filter_{
								Filter: &corev1.Scope_API_Filter{
									Packages: []string{"octelium.api.main.cluster.v1"},
									Services: []string{"SomeService"},
									Methods:  []string{"DoSomething"},
								},
							},
						},
					},
				},
			},

			{
				arg: "*",
				out: &corev1.Scope{
					Type: &corev1.Scope_Api{
						Api: &corev1.Scope_API{
							Type: &corev1.Scope_API_All_{
								All: &corev1.Scope_API_All{},
							},
						},
					},
				},
			},
		}

		for _, valid := range valids {
			resp, err := getScopeAPI(valid.arg)
			assert.Nil(t, err)

			assert.True(t, pbutils.IsEqual(resp, valid.out))

			zap.L().Debug("RESP", zap.Any("resp", resp), zap.Any("out", valid.out))
		}
	}

	{
		invalids := []string{
			"",
			"**",
			":",
			"::",
			"a:b",
			"cluster/",
			"cluster/*",
			"cluster.MainService.",
			"cluster.MainService/",
		}

		for _, invalid := range invalids {
			_, err := getScopeAPI(invalid)
			assert.NotNil(t, err, "%s", invalid)
		}
	}
}

func TestGetScope(t *testing.T) {

	type tstArg struct {
		arg string
		out *corev1.Scope
	}

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		valids := []string{
			"api:*",
			"service:*",
			"service:svc1.ns1",
			"api:core",
			"api:cluster",
		}

		for _, valid := range valids {
			_, err := getScope(valid)
			assert.Nil(t, err)
		}
	}

	{
		invalids := []string{
			"",
			"*",
			":",
			"::",
			"a:a",
			"api2:*",
			"custer2",
			"Cluster",
			"coRe",
		}

		for _, invalid := range invalids {
			_, err := getScope(invalid)
			assert.NotNil(t, err)
		}
	}

}

func TestGetScopes(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	valids := [][]string{
		nil,
		{"api:core"},
		{"api:core", "service:svc1"},
		{"api:core", "service:svc1", "api:*"},
	}

	for _, valid := range valids {
		_, err := GetScopes(valid)
		assert.Nil(t, err)
	}

	invalids := [][]string{
		{},
		{""},
		{"type"},
		{"typ2:"},
		func() []string {
			var ret []string
			for i := 0; i < 200; i++ {
				ret = append(ret, "api:core")
			}
			return ret
		}(),
	}
	for _, invalid := range invalids {
		_, err := GetScopes(invalid)
		assert.NotNil(t, err)
	}

}

func TestIsAuthorizedByScopes(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	type tstArg struct {
		svc          *corev1.Service
		sess         *corev1.Session
		isAuthorized bool
		req          *corev1.RequestContext_Request
	}

	tstVs := []tstArg{
		{
			svc: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: "svc1.ns1",
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "ns1",
					},
				},
			},
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: nil,
				},
			},
			isAuthorized: true,
		},
		{
			svc: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: "svc1.ns1",
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "ns1",
					},
				},
			},
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: func() []*corev1.Scope {
						var ret []*corev1.Scope
						scope, _ := getScope("service:*")
						ret = append(ret, scope)
						return ret
					}(),
				},
			},
			isAuthorized: true,
		},

		{
			svc: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: "svc1.ns1",
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "ns1",
					},
				},
			},
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: func() []*corev1.Scope {
						var ret []*corev1.Scope
						scope, _ := getScope("service:svc1.ns1")
						ret = append(ret, scope)
						return ret
					}(),
				},
			},
			isAuthorized: true,
		},

		{
			svc: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: "svc1.ns2",
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "ns2",
					},
				},
			},
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: func() []*corev1.Scope {
						var ret []*corev1.Scope
						scope, _ := getScope("service:svc1.ns1")
						ret = append(ret, scope)
						return ret
					}(),
				},
			},
			isAuthorized: false,
		},
		{
			svc: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: "svc1.ns1",
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "ns1",
					},
				},
			},
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: func() []*corev1.Scope {
						var ret []*corev1.Scope
						scope, _ := getScope("api:*")
						ret = append(ret, scope)
						return ret
					}(),
				},
			},
			isAuthorized: false,
		},

		{
			svc: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: "svc1.ns1",
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "ns1",
					},
				},
			},
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: func() []*corev1.Scope {
						var ret []*corev1.Scope
						scope, _ := getScope("api:*")
						ret = append(ret, scope)
						scope, _ = getScope("service:*")
						ret = append(ret, scope)
						return ret
					}(),
				},
			},
			isAuthorized: true,
		},

		{
			svc: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: "svc1.ns1",
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "ns1",
					},
				},
			},
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: func() []*corev1.Scope {
						var ret []*corev1.Scope
						scope, _ := getScope("service:svc2.ns3")
						ret = append(ret, scope)
						scope, _ = getScope("service:*")
						ret = append(ret, scope)
						return ret
					}(),
				},
			},
			isAuthorized: true,
		},

		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "svc1",
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "ns1",
						},
					},
				},
				sess: &corev1.Session{
					Status: &corev1.Session_Status{
						Scopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("service:*")
							ret = append(ret, scope)
							return ret
						}(),
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("service:svc2.ns1")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				isAuthorized: false,
			},
		*/
		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "svc1",
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "ns1",
						},
					},
				},
				sess: &corev1.Session{
					Status: &corev1.Session_Status{
						Scopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("service:*")
							ret = append(ret, scope)
							return ret
						}(),
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("service:svc1.ns1")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				isAuthorized: true,
			},
		*/
		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "svc1",
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "ns1",
						},
					},
				},
				sess: &corev1.Session{
					Spec: &corev1.Session_Spec{
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("service:ns1/*")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				isAuthorized: true,
			},

		*/
		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "svc1",
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "ns1",
						},
					},
				},
				sess: &corev1.Session{
					Spec: &corev1.Session_Spec{
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("service:ns2/*")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				isAuthorized: false,
			},
		*/
		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "api",
					},
					Spec: &corev1.Service_Spec{
						Backend: &corev1.Service_Spec_Config_Upstream_{
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_ManagedService_{
									ManagedService: &corev1.Service_Spec_Config_Upstream_ManagedService{},
								},
							},
						},
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "octelium",
						},
						ManagedService: &corev1.Service_Status_ManagedService{
							Type: "apiserver",
						},
					},
				},
				sess: &corev1.Session{
					Spec: &corev1.Session_Spec{
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("api:core")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				req: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Grpc{
						Grpc: &corev1.RequestContext_Request_GRPC{
							Package: "octelium.api.main.cluster.v1",
							Service: "MainService",
							Method:  "CreateIdentityProvider",
						},
					},
				},
				isAuthorized: false,
			},

			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "api",
					},
					Spec: &corev1.Service_Spec{
						Backend: &corev1.Service_Spec_Config_Upstream_{
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_ManagedService_{
									ManagedService: &corev1.Service_Spec_Config_Upstream_ManagedService{},
								},
							},
						},
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "octelium",
						},
						ManagedService: &corev1.Service_Status_ManagedService{
							Type: "apiserver",
						},
					},
				},
				sess: &corev1.Session{
					Spec: &corev1.Session_Spec{
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("api:core")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				req: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Grpc{
						Grpc: &corev1.RequestContext_Request_GRPC{
							Package: "octelium.api.main.core.v1",
							Service: "MainService",
							Method:  "CreateUser",
						},
					},
				},
				isAuthorized: true,
			},
		*/
		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "api",
					},
					Spec: &corev1.Service_Spec{
						Backend: &corev1.Service_Spec_Config_Upstream_{
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_ManagedService_{
									ManagedService: &corev1.Service_Spec_Config_Upstream_ManagedService{},
								},
							},
						},
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "octelium",
						},
						ManagedService: &corev1.Service_Status_ManagedService{
							Type: "apiserver",
						},
					},
				},
				sess: &corev1.Session{
					Spec: &corev1.Session_Spec{
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("api:core.MainService/CreateUser")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				req: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Grpc{
						Grpc: &corev1.RequestContext_Request_GRPC{
							Package: "octelium.api.main.core.v1",
							Service: "MainService",
							Method:  "CreateUser",
						},
					},
				},
				isAuthorized: true,
			},

		*/
		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "api",
					},
					Spec: &corev1.Service_Spec{
						Backend: &corev1.Service_Spec_Config_Upstream_{
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_ManagedService_{
									ManagedService: &corev1.Service_Spec_Config_Upstream_ManagedService{},
								},
							},
						},
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "octelium",
						},
						ManagedService: &corev1.Service_Status_ManagedService{
							Type: "apiserver",
						},
					},
				},
				sess: &corev1.Session{
					Spec: &corev1.Session_Spec{
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("api:core.MainService/CreateUser")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				req: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Grpc{
						Grpc: &corev1.RequestContext_Request_GRPC{
							Package: "octelium.api.main.core.v1",
							Service: "MainService",
							Method:  "DeleteUser",
						},
					},
				},
				isAuthorized: false,
			},
		*/

		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "api",
					},
					Spec: &corev1.Service_Spec{
						Backend: &corev1.Service_Spec_Config_Upstream_{
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_ManagedService_{
									ManagedService: &corev1.Service_Spec_Config_Upstream_ManagedService{},
								},
							},
						},
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "octelium",
						},
						ManagedService: &corev1.Service_Status_ManagedService{
							Type: "apiserver",
						},
					},
				},
				sess: &corev1.Session{
					Spec: &corev1.Session_Spec{
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("api:core.MainService")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				req: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Grpc{
						Grpc: &corev1.RequestContext_Request_GRPC{
							Package: "octelium.api.main.core.v1",
							Service: "MainService",
							Method:  "DeleteUser",
						},
					},
				},
				isAuthorized: true,
			},
		*/

		/*
			{
				svc: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "api",
					},
					Spec: &corev1.Service_Spec{
						Backend: &corev1.Service_Spec_Config_Upstream_{
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_ManagedService_{
									ManagedService: &corev1.Service_Spec_Config_Upstream_ManagedService{},
								},
							},
						},
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{
							Name: "octelium",
						},
						ManagedService: &corev1.Service_Status_ManagedService{
							Type: "apiserver",
						},
					},
				},
				sess: &corev1.Session{
					Spec: &corev1.Session_Spec{
						ParentScopes: func() []*corev1.Scope {
							var ret []*corev1.Scope
							scope, _ := getScope("api:core.MainService")
							ret = append(ret, scope)
							return ret
						}(),
					},
				},
				req: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Grpc{
						Grpc: &corev1.RequestContext_Request_GRPC{
							Package: "octelium.api.main.core.v1",
							Service: "OtherService",
							Method:  "DeleteUser",
						},
					},
				},
				isAuthorized: false,
			},
		*/
	}

	for _, tstV := range tstVs {

		req := &corev1.RequestContext{
			Service: tstV.svc,
			Session: tstV.sess,
			Request: tstV.req,
		}
		assert.Equal(t, tstV.isAuthorized, IsAuthorizedByScopes(req), "req: %+v", req)
	}

}

func tstSvcNS(name, ns string) *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.%s", name, ns),
		},
		Spec: &corev1.Service_Spec{},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{
				Name: ns,
			},
		},
	}
}

func tstGrpcReq(pkg, svc, method string) *corev1.RequestContext_Request {
	return &corev1.RequestContext_Request{
		Type: &corev1.RequestContext_Request_Grpc{
			Grpc: &corev1.RequestContext_Request_GRPC{
				Package: pkg,
				Service: svc,
				Method:  method,
			},
		},
	}
}

func TestIsInListOrAny(t *testing.T) {

	assert.False(t, isInListOrAny(nil, "a"))
	assert.False(t, isInListOrAny([]string{}, "a"))

	assert.True(t, isInListOrAny([]string{"a", "b"}, "a"))
	assert.True(t, isInListOrAny([]string{"a", "b"}, "b"))
	assert.False(t, isInListOrAny([]string{"a", "b"}, "c"))

	assert.True(t, isInListOrAny([]string{"*"}, "anything"))
	assert.True(t, isInListOrAny([]string{"a", "*"}, "zzz"))
	assert.True(t, isInListOrAny([]string{"*"}, ""))
}

func TestVerifyScopes(t *testing.T) {

	assert.Nil(t, VerifyScopes(nil))
	assert.Nil(t, VerifyScopes([]string{"api:core"}))
	assert.Nil(t, VerifyScopes([]string{"api:*", "service:*"}))

	assert.NotNil(t, VerifyScopes([]string{}))
	assert.NotNil(t, VerifyScopes([]string{""}))
	assert.NotNil(t, VerifyScopes([]string{"invalid"}))
	assert.NotNil(t, VerifyScopes([]string{"api:core", "api:core"}))
	assert.NotNil(t, VerifyScopes([]string{" api:core"}))
	assert.NotNil(t, VerifyScopes([]string{"api:core "}))
	assert.NotNil(t, VerifyScopes([]string{"unknown:core"}))
	assert.NotNil(t, VerifyScopes([]string{strings.Repeat("a", 300)}))
}

func TestGetScopesLimits(t *testing.T) {

	{
		ret, err := GetScopes(nil)
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, ret)
	}

	{
		_, err := GetScopes([]string{})
		assert.NotNil(t, err)
	}

	{
		var scopes []string
		for i := range 128 {
			scopes = append(scopes, "service:"+utilrand.GetRandomStringCanonical(10)+
				strings.Repeat("", i))
		}

		ret, err := GetScopes(scopes)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 128, len(ret))
	}

	{
		var scopes []string
		for range 129 {
			scopes = append(scopes, "service:"+utilrand.GetRandomStringCanonical(10))
		}

		_, err := GetScopes(scopes)
		assert.NotNil(t, err)
	}
}

func TestIsAuthorizedByScopeService(t *testing.T) {

	svc := tstSvcNS("svc", "default")

	{
		scope := &corev1.Scope_Service{
			Type: &corev1.Scope_Service_All_{
				All: &corev1.Scope_Service_All{},
			},
		}
		assert.True(t, IsAuthorizedByScopeService(scope, svc, nil))
	}

	{
		scope := &corev1.Scope_Service{
			Type: &corev1.Scope_Service_Filter_{
				Filter: &corev1.Scope_Service_Filter{
					Names:      []string{"svc"},
					Namespaces: []string{"default"},
				},
			},
		}
		assert.True(t, IsAuthorizedByScopeService(scope, svc, nil))
	}

	{
		scope := &corev1.Scope_Service{
			Type: &corev1.Scope_Service_Filter_{
				Filter: &corev1.Scope_Service_Filter{
					Names:      []string{"other"},
					Namespaces: []string{"default"},
				},
			},
		}
		assert.False(t, IsAuthorizedByScopeService(scope, svc, nil))
	}

	{
		scope := &corev1.Scope_Service{
			Type: &corev1.Scope_Service_Filter_{
				Filter: &corev1.Scope_Service_Filter{
					Names:      []string{"svc"},
					Namespaces: []string{"other"},
				},
			},
		}
		assert.False(t, IsAuthorizedByScopeService(scope, svc, nil))
	}

	{
		scope := &corev1.Scope_Service{
			Type: &corev1.Scope_Service_Filter_{
				Filter: &corev1.Scope_Service_Filter{
					Names:      []string{"*"},
					Namespaces: []string{"default"},
				},
			},
		}
		assert.True(t, IsAuthorizedByScopeService(scope, svc, nil))
	}

	{
		scope := &corev1.Scope_Service{
			Type: &corev1.Scope_Service_Filter_{
				Filter: &corev1.Scope_Service_Filter{},
			},
		}
		assert.False(t, IsAuthorizedByScopeService(scope, svc, nil))
	}

	{
		scope := &corev1.Scope_Service{
			Type: &corev1.Scope_Service_Filter_{},
		}
		assert.False(t, IsAuthorizedByScopeService(scope, svc, nil))
	}
}

func TestIsAuthorizedByScopeAPIServer(t *testing.T) {

	svc := tstSvcNS("api", "octelium-api")
	req := tstGrpcReq("octelium.api.main.core.v1", "MainService", "ListUser")

	{
		scope := &corev1.Scope_API{
			Type: &corev1.Scope_API_All_{
				All: &corev1.Scope_API_All{},
			},
		}
		assert.True(t, IsAuthorizedByScopeAPIServer(scope, svc, req))
	}

	{
		scope := &corev1.Scope_API{
			Type: &corev1.Scope_API_Filter_{
				Filter: &corev1.Scope_API_Filter{
					Packages: []string{"octelium.api.main.core.v1"},
					Services: []string{"*"},
					Methods:  []string{"*"},
				},
			},
		}
		assert.True(t, IsAuthorizedByScopeAPIServer(scope, svc, req))
	}

	{
		scope := &corev1.Scope_API{
			Type: &corev1.Scope_API_Filter_{
				Filter: &corev1.Scope_API_Filter{
					Packages: []string{"octelium.api.main.auth.v1"},
					Services: []string{"*"},
					Methods:  []string{"*"},
				},
			},
		}
		assert.False(t, IsAuthorizedByScopeAPIServer(scope, svc, req))
	}

	{
		scope := &corev1.Scope_API{
			Type: &corev1.Scope_API_Filter_{
				Filter: &corev1.Scope_API_Filter{
					Packages: []string{"octelium.api.main.core.v1"},
					Services: []string{"OtherService"},
					Methods:  []string{"*"},
				},
			},
		}
		assert.False(t, IsAuthorizedByScopeAPIServer(scope, svc, req))
	}

	{
		scope := &corev1.Scope_API{
			Type: &corev1.Scope_API_Filter_{
				Filter: &corev1.Scope_API_Filter{
					Packages: []string{"octelium.api.main.core.v1"},
					Services: []string{"MainService"},
					Methods:  []string{"GetUser"},
				},
			},
		}
		assert.False(t, IsAuthorizedByScopeAPIServer(scope, svc, req))
	}

	{
		scope := &corev1.Scope_API{
			Type: &corev1.Scope_API_Filter_{
				Filter: &corev1.Scope_API_Filter{
					Packages: []string{"octelium.api.main.core.v1"},
					Services: []string{"MainService"},
					Methods:  []string{"ListUser"},
				},
			},
		}
		assert.True(t, IsAuthorizedByScopeAPIServer(scope, svc, req))
	}

	{
		scope := &corev1.Scope_API{
			Type: &corev1.Scope_API_Filter_{
				Filter: &corev1.Scope_API_Filter{},
			},
		}
		assert.False(t, IsAuthorizedByScopeAPIServer(scope, svc, req))
	}

	{
		scope := &corev1.Scope_API{
			Type: &corev1.Scope_API_Filter_{},
		}
		assert.False(t, IsAuthorizedByScopeAPIServer(scope, svc, req))
	}
}

func TestIsAuthorizedByScopesGuards(t *testing.T) {

	assert.False(t, IsAuthorizedByScopes(nil))

	assert.False(t, IsAuthorizedByScopes(&corev1.RequestContext{}))

	assert.False(t, IsAuthorizedByScopes(&corev1.RequestContext{
		Session: &corev1.Session{},
	}))

	{
		req := &corev1.RequestContext{
			Session: &corev1.Session{
				Status: &corev1.Session_Status{},
			},
		}
		assert.True(t, IsAuthorizedByScopes(req))
	}

	{
		req := &corev1.RequestContext{
			Session: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: []*corev1.Scope{
						{
							Type: &corev1.Scope_Service_{
								Service: &corev1.Scope_Service{
									Type: &corev1.Scope_Service_All_{
										All: &corev1.Scope_Service_All{},
									},
								},
							},
						},
					},
				},
			},
		}
		assert.False(t, IsAuthorizedByScopes(req))
	}

	{
		req := &corev1.RequestContext{
			Session: &corev1.Session{
				Status: &corev1.Session_Status{
					Scopes: []*corev1.Scope{
						{
							Type: &corev1.Scope_Service_{
								Service: &corev1.Scope_Service{
									Type: &corev1.Scope_Service_All_{
										All: &corev1.Scope_Service_All{},
									},
								},
							},
						},
					},
				},
			},
			Service: tstSvcNS("svc", "default"),
		}
		assert.True(t, IsAuthorizedByScopes(req))
	}
}

func TestDoIsAuthorizedByScopes(t *testing.T) {

	svc := tstSvcNS("svc", "default")

	assert.True(t, doIsAuthorizedByScopes(nil, svc, nil))
	assert.True(t, doIsAuthorizedByScopes([]*corev1.Scope{}, svc, nil))

	assert.False(t, doIsAuthorizedByScopes([]*corev1.Scope{nil}, svc, nil))

	assert.False(t, doIsAuthorizedByScopes([]*corev1.Scope{{}}, svc, nil))

	{
		scopes := []*corev1.Scope{
			{
				Type: &corev1.Scope_Api{
					Api: &corev1.Scope_API{
						Type: &corev1.Scope_API_All_{
							All: &corev1.Scope_API_All{},
						},
					},
				},
			},
		}
		assert.False(t, doIsAuthorizedByScopes(scopes, svc,
			tstGrpcReq("octelium.api.main.core.v1", "MainService", "ListUser")))
	}

	{
		scopes := []*corev1.Scope{
			{
				Type: &corev1.Scope_Service_{
					Service: &corev1.Scope_Service{
						Type: &corev1.Scope_Service_Filter_{
							Filter: &corev1.Scope_Service_Filter{
								Names:      []string{"other"},
								Namespaces: []string{"default"},
							},
						},
					},
				},
			},
			{
				Type: &corev1.Scope_Service_{
					Service: &corev1.Scope_Service{
						Type: &corev1.Scope_Service_Filter_{
							Filter: &corev1.Scope_Service_Filter{
								Names:      []string{"svc"},
								Namespaces: []string{"default"},
							},
						},
					},
				},
			},
		}
		assert.True(t, doIsAuthorizedByScopes(scopes, svc, nil))
	}
}
