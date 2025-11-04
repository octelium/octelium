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
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/rscutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestCreateService(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{
		_, err = srv.CreateService(ctx, nil)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err = srv.CreateService(ctx, &corev1.Service{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err = srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err = srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5)),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err = srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.not-existent", fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5))),
			},
			Spec: &corev1.Service_Spec{},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err = srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.not-existent", fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5))),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Port: 80,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{

		secretName := fmt.Sprintf("secret-%s", utilrand.GetRandomStringCanonical(5))
		_, err := srv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: secretName,
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: "password",
				},
			},
		})
		assert.Nil(t, err)

		in := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5)),
			},
			Spec: &corev1.Service_Spec{

				Mode: corev1.Service_Spec_SSH,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "ssh://localhost",
						},
					},
					Type: &corev1.Service_Spec_Config_Ssh{
						Ssh: &corev1.Service_Spec_Config_SSH{
							User: "root",
							Auth: &corev1.Service_Spec_Config_SSH_Auth{
								Type: &corev1.Service_Spec_Config_SSH_Auth_Password_{
									Password: &corev1.Service_Spec_Config_SSH_Auth_Password{
										Type: &corev1.Service_Spec_Config_SSH_Auth_Password_FromSecret{
											FromSecret: secretName,
										},
									},
								},
							},
							UpstreamHostKey: &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
								Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_InsecureIgnoreHostKey{
									InsecureIgnoreHostKey: true,
								},
							},
						},
					},
				},
			},
		}
		out1, err := srv.CreateService(ctx, in)
		assert.Nil(t, err, "%+v", err)
		out2, err := srv.GetService(ctx, &metav1.GetOptions{Uid: out1.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		assert.True(t, pbutils.IsEqual(out1.Spec, out2.Spec))
	}

	{
		net := tests.GenNamespace()
		net, err = srv.CreateNamespace(ctx, net)
		assert.Nil(t, err)

		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-%s.%s", utilrand.GetRandomStringLowercase(5), net.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{

				Port: 80,
				Mode: corev1.Service_Spec_HTTP,

				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
							Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
								Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
									{
										Url: "https://example.com",
									},
								},
							},
						},
					},
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								AddRequestHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
									{
										Key: "x-hdr1",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
											Value: "val1",
										},
									},
									{
										Key: "x-hdr2",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
											Value: "val2",
										},
									},
								},
								RemoveRequestHeaders: []string{
									"x-hdr1",
								},
								RemoveResponseHeaders: []string{
									"x-hdr1",
								},

								AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
									{
										Key: "x-hdr1",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
											Value: "val1",
										},
									},
									{
										Key: "x-hdr2",
										Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
											Value: "val2",
										},
									},
								},
							},

							Cors: &corev1.Service_Spec_Config_HTTP_CORS{
								AllowMethods:     "GET",
								AllowCredentials: true,
							},
						},
					},
				},
			},
		}

		res, err := srv.CreateService(ctx, req)
		assert.Nil(t, err, "%+v", err)

		assert.True(t, proto.Equal(res.Spec, req.Spec))
	}

	{
		net := tests.GenNamespace()
		net, err = srv.CreateNamespace(ctx, net)
		assert.Nil(t, err)

		_, err = srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-1.%s", net.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{

				Port: 80,
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
				Authorization: &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
	}

	{
		net := tests.GenNamespace()
		net, err = srv.CreateNamespace(ctx, net)
		assert.Nil(t, err)

		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-1.%s", net.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Port: 80,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
			},
		})
		assert.Nil(t, err)

		svc.Metadata.DisplayName = "new display name"
		svc.Metadata.Description = "description"
		svc.Metadata.Labels = map[string]string{
			"key": "val",
		}
		svc.Metadata.Annotations = map[string]string{
			"key1": "val1",
		}

		nSvc, err := srv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		assert.Equal(t, svc.Metadata.DisplayName, nSvc.Metadata.DisplayName)
		assert.Equal(t, svc.Metadata.Description, nSvc.Metadata.Description)
		assert.Equal(t, svc.Metadata.Labels, nSvc.Metadata.Labels)
		assert.Equal(t, svc.Metadata.Annotations, nSvc.Metadata.Annotations)
	}

	/*
		{
			svc, err := srv.CreateService(ctx, &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5)),
				},
				Spec: &corev1.Service_Spec{
					Port: 80,
					Backend: &corev1.Service_Spec_Config_Upstream_{
						Upstream: &corev1.Service_Spec_Config_Upstream{
							Type: &corev1.Service_Spec_Config_Upstream_ManagedService_{
								ManagedService: &corev1.Service_Spec_Config_Upstream_ManagedService{
									Type: corev1.Service_Spec_Config_Upstream_ManagedService_WORKSPACE,
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err)

			svcV, err := tst.C.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			assert.True(t, svcV.IsManagedServiceWorkspace())
			assert.True(t, pbutils.IsEqual(svc, svcV))
		}
	*/

	{
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5)),
			},
			Spec: &corev1.Service_Spec{
				IsPublic: true,
				Mode:     corev1.Service_Spec_HTTP,

				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Container_{
							Container: &corev1.Service_Spec_Config_Upstream_Container{
								Port:  80,
								Image: "nginx:latest",
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)

		svcV, err := tst.C.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(svc, svcV))
		assert.Equal(t, 80, ucorev1.ToService(svcV).RealPort())

	}

}
func TestServiceMode(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{

		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_SSH,
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Ssh{
						Ssh: &corev1.Service_Spec_Config_SSH{
							ESSHMode: true,
						},
					},
				},
			},
		})

		assert.Nil(t, err, "%+v", err)

		assert.Equal(t, corev1.Service_Spec_SSH, ucorev1.ToService(svc).GetMode())
		assert.Equal(t, 22, ucorev1.ToService(svc).RealPort())
	}

	{
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_TCP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "ssh://localhost",
						},
					},
				},
			},
		})

		assert.Nil(t, err)
		assert.Equal(t, corev1.Service_Spec_TCP, ucorev1.ToService(svc).GetMode())

		svc, err = srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_SSH,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "ssh://localhost",
						},
					},
				},
			},
		})

		assert.Nil(t, err)
		assert.Equal(t, corev1.Service_Spec_SSH, ucorev1.ToService(svc).GetMode())
	}

	{
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "http://example.com",
						},
					},
				},
			},
		})

		assert.Nil(t, err)
		assert.Equal(t, corev1.Service_Spec_HTTP, ucorev1.ToService(svc).GetMode())

	}

	{
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
			},
		})

		assert.Nil(t, err)
		assert.Equal(t, corev1.Service_Spec_HTTP, ucorev1.ToService(svc).GetMode())

	}

	{
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_TCP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
			},
		})

		assert.Nil(t, err)
		assert.Equal(t, corev1.Service_Spec_TCP, ucorev1.ToService(svc).GetMode())

	}

	{
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_KUBERNETES,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
			},
		})

		assert.Nil(t, err)
		assert.Equal(t, corev1.Service_Spec_KUBERNETES, ucorev1.ToService(svc).GetMode())
	}
}

func TestServiceCEL(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{
		net := tests.GenNamespace()
		net, err = srv.CreateNamespace(ctx, net)
		assert.Nil(t, err)

		_, err = srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-%s.%s", utilrand.GetRandomStringLowercase(5), net.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port: 80,
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
				Authorization: &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
	}

	{
		net := tests.GenNamespace()
		net, err = srv.CreateNamespace(ctx, net)
		assert.Nil(t, err)

		{
			_, err = srv.CreateService(ctx, &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: fmt.Sprintf("svc-%s.%s", utilrand.GetRandomStringLowercase(5), net.Metadata.Name),
				},
				Spec: &corev1.Service_Spec{
					Port: 80,
					Mode: corev1.Service_Spec_HTTP,
					Config: &corev1.Service_Spec_Config{
						Upstream: &corev1.Service_Spec_Config_Upstream{
							Type: &corev1.Service_Spec_Config_Upstream_Url{
								Url: "https://example.com",
							},
						},
					},
					Authorization: &corev1.Service_Spec_Authorization{
						InlinePolicies: []*corev1.InlinePolicy{
							{
								Spec: &corev1.Policy_Spec{
									Rules: []*corev1.Policy_Spec_Rule{
										{
											Effect: corev1.Policy_Spec_Rule_ALLOW,
											Condition: &corev1.Condition{
												Type: &corev1.Condition_MatchAny{
													MatchAny: true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err, "%+v", err)
		}

		{
			_, err = srv.CreateService(ctx, &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: fmt.Sprintf("svc-%s.%s", utilrand.GetRandomStringLowercase(5), net.Metadata.Name),
				},
				Spec: &corev1.Service_Spec{
					Port: 80,
					Mode: corev1.Service_Spec_HTTP,
					Config: &corev1.Service_Spec_Config{
						Upstream: &corev1.Service_Spec_Config_Upstream{
							Type: &corev1.Service_Spec_Config_Upstream_Url{
								Url: "https://example.com",
							},
						},
					},
					Authorization: &corev1.Service_Spec_Authorization{
						InlinePolicies: []*corev1.InlinePolicy{
							{
								Spec: &corev1.Policy_Spec{
									Rules: []*corev1.Policy_Spec_Rule{
										{
											Effect: corev1.Policy_Spec_Rule_ALLOW,
											Condition: &corev1.Condition{

												Type: &corev1.Condition_All_{

													All: &corev1.Condition_All{
														Of: []*corev1.Condition{
															{
																Type: &corev1.Condition_Match{
																	Match: "1 = 1",
																},
															},
															{
																Type: &corev1.Condition_Match{
																	Match: "1 + 1",
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			})
			assert.NotNil(t, err)
		}

	}
}

func TestValidateService(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	invalidSvcs := []*corev1.Service{
		nil,
		{},
		{
			Metadata: &metav1.Metadata{Name: "a"},
		},
		{
			Metadata: &metav1.Metadata{Name: "1ab"},
		},
		{
			Metadata: &metav1.Metadata{Name: "svc-1"},
		},
		{
			Metadata: &metav1.Metadata{Name: "svc.ns1"},
		},

		/*
			{
				Metadata: &metav1.Metadata{Name: "svc.ns1"},
				Spec:     &corev1.Service_Spec{},
			},
			{
				Metadata: &metav1.Metadata{Name: "svc.ns1"},
				Spec:     &corev1.Service_Spec{},
			},
		*/
		{
			Metadata: &metav1.Metadata{Name: "svc.ns1"},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "example.com",
						},
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: "svc.ns1"},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "custom://example.com",
						},
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: "svc.ns1"},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "tcp://example.com",
						},
					},
				},
			},
		},

		{
			Metadata: &metav1.Metadata{Name: "svc.ns1"},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "tcp://example.com",
						},
					},
				},
				Port: 70,
			},
		},
	}

	for _, svc := range invalidSvcs {
		err := srv.validateService(ctx, svc)
		assert.NotNil(t, err, "%+v : %+v", err, svc)
	}

	validSvcs := []*corev1.Service{
		{
			Metadata: &metav1.Metadata{Name: "svc.ns1"},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: "svc.ns1"},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
				IsTLS: true,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: "svc.ns1"},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "postgres://pg",
						},
					},
				},
				Port: 5050,
			},
		},
	}

	for _, svc := range validSvcs {
		err := srv.validateService(ctx, svc)
		assert.Nil(t, err)
	}
}

func TestEmbedded(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)
	srv.isEmbedded = true

	_, err = srv.octeliumC.CoreC().CreateNamespace(ctx, &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name: "octelium-api",
		},
		Spec: &corev1.Namespace_Spec{},
	})
	assert.Nil(t, err)

	req := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name:         "auth.octelium-api",
			IsSystem:     true,
			IsUserHidden: true,
			SystemLabels: map[string]string{
				"octelium-apiserver": "true",
				"apiserver-path":     "/octelium.api.main.auth",
			},
		},
		Spec: &corev1.Service_Spec{
			Port:     8080,
			IsPublic: true,
			Mode:     corev1.Service_Spec_GRPC,

			IsAnonymous: true,
		},
		Status: &corev1.Service_Status{

			ManagedService: &corev1.Service_Status_ManagedService{
				Type:  "apiserver",
				Image: components.GetImage(components.AuthServer, ""),
				Args:  []string{"grpc"},
			},
		},
	}
	svc, err := srv.DoCreateService(ctx, req, true)
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, "/octelium.api.main.auth", svc.Metadata.SystemLabels["apiserver-path"])
	assert.True(t, svc.Metadata.IsUserHidden)
	assert.True(t, svc.Metadata.IsSystem)
	assert.Equal(t, "apiserver", svc.Status.ManagedService.Type)
	assert.True(t, pbutils.IsEqual(svc.Status.ManagedService, req.Status.ManagedService))
	// assert.Equal(t, "true", svc.Metadata.SpecLabels["enable-public"])
}

func TestServiceDynamicConfig(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)
	srv.isEmbedded = true

	ns, err := srv.octeliumC.CoreC().CreateNamespace(ctx, &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Namespace_Spec{},
	})
	assert.Nil(t, err)

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_HTTP,
			},
			Status: &corev1.Service_Status{},
		}
		_, err = srv.CreateService(ctx, req)
		assert.NotNil(t, err, "%+v", err)
	}

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_HTTP,

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "c1",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Container_{
									Container: &corev1.Service_Spec_Config_Upstream_Container{
										Image: "nginx",
										Port:  80,
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}
		_, err = srv.CreateService(ctx, req)
		assert.Nil(t, err, "%+v", err)
	}

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_HTTP,

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "c1",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Container_{
									Container: &corev1.Service_Spec_Config_Upstream_Container{
										Image: "nginx",
										Port:  80,
									},
								},
							},
						},
						{
							Name: "c1",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Container_{
									Container: &corev1.Service_Spec_Config_Upstream_Container{
										Image: "nginx",
										Port:  80,
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}
		_, err = srv.CreateService(ctx, req)
		assert.NotNil(t, err, "%+v", err)
	}

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_HTTP,

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "c1",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Container_{
									Container: &corev1.Service_Spec_Config_Upstream_Container{
										Image: "nginx",
										Port:  80,
									},
								},
							},
						},
						{
							Name: "c2",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Container_{
									Container: &corev1.Service_Spec_Config_Upstream_Container{
										Image: "nginx",
										Port:  80,
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}
		_, err = srv.CreateService(ctx, req)
		assert.Nil(t, err, "%+v", err)
	}

	// assert.Equal(t, "true", svc.Metadata.SpecLabels["enable-public"])
}

func TestServiceDirectResponse(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)
	srv.isEmbedded = true

	ns, err := srv.octeliumC.CoreC().CreateNamespace(ctx, &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Namespace_Spec{},
	})
	assert.Nil(t, err)

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Response: &corev1.Service_Spec_Config_HTTP_Response{
								Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_{
									Direct: &corev1.Service_Spec_Config_HTTP_Response_Direct{
										Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_Inline{
											Inline: utilrand.GetRandomString(32),
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}
		_, err = srv.CreateService(ctx, req)
		assert.Nil(t, err, "%+v", err)
	}

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_HTTP,
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-1",
							},
						},
					},
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "cfg-1",
							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Response: &corev1.Service_Spec_Config_HTTP_Response{
										Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_{
											Direct: &corev1.Service_Spec_Config_HTTP_Response_Direct{
												ContentType: "image/png",
												Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_Inline{
													Inline: utilrand.GetRandomString(32),
												},
											},
										},
									},
								},
							},
						},
						{
							Name: "cfg-2",
							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Response: &corev1.Service_Spec_Config_HTTP_Response{
										Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_{
											Direct: &corev1.Service_Spec_Config_HTTP_Response_Direct{
												Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_Inline{
													Inline: utilrand.GetRandomString(32),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}
		_, err = srv.CreateService(ctx, req)
		assert.Nil(t, err, "%+v", err)
	}
}

func TestMergedServiceConfig(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)
	srv.isEmbedded = true

	ns, err := srv.octeliumC.CoreC().CreateNamespace(ctx, &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Namespace_Spec{},
	})
	assert.Nil(t, err)

	sec, err := srv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		},
	})
	assert.Nil(t, err)

	{
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port:     8080,
				IsPublic: true,
				Mode:     corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Auth: &corev1.Service_Spec_Config_HTTP_Auth{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
									Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
										Username: "parent",
										Password: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password{
											Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password_FromSecret{
												FromSecret: sec.Metadata.Name,
											},
										},
									},
								},
							},
						},
					},
				},

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Parent: "default",
							Name:   "child-cfg",
							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Auth: &corev1.Service_Spec_Config_HTTP_Auth{
										Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
											Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
												Username: "child",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}
		svc, err := srv.CreateService(ctx, req)
		assert.Nil(t, err, "%+v", err)

		cfg := rscutils.GetMergedServiceConfig(svc.Spec.DynamicConfig.Configs[0], svc)
		assert.Equal(t,
			svc.Spec.Config.GetHttp().Auth.GetBasic().Password.GetFromSecret(),
			cfg.GetHttp().Auth.GetBasic().Password.GetFromSecret())
		assert.Equal(t, "child", cfg.GetHttp().Auth.GetBasic().Username)

		assert.True(t, pbutils.IsEqual(req.Spec, svc.Spec))
	}

	{
		// Test with a dynamic config parent
		req := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Port: 8080,
				Mode: corev1.Service_Spec_POSTGRES,

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "parent",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Url{
									Url: fmt.Sprintf("postgres://%s", utilrand.GetRandomStringCanonical(8)),
								},
							},
							Type: &corev1.Service_Spec_Config_Postgres_{
								Postgres: &corev1.Service_Spec_Config_Postgres{
									User:     utilrand.GetRandomStringCanonical(8),
									Database: utilrand.GetRandomStringCanonical(8),
									Auth: &corev1.Service_Spec_Config_Postgres_Auth{
										Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_{
											Password: &corev1.Service_Spec_Config_Postgres_Auth_Password{
												Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_FromSecret{
													FromSecret: sec.Metadata.Name,
												},
											},
										},
									},
								},
							},
						},
						{
							Parent: "parent",
							Name:   "child",
							Type: &corev1.Service_Spec_Config_Postgres_{
								Postgres: &corev1.Service_Spec_Config_Postgres{
									Database: utilrand.GetRandomStringCanonical(8),
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}
		svc, err := srv.CreateService(ctx, req)
		assert.Nil(t, err, "%+v", err)

		cfg := rscutils.GetMergedServiceConfig(svc.Spec.DynamicConfig.Configs[1], svc)
		assert.Equal(t,
			svc.Spec.DynamicConfig.Configs[1].GetPostgres().Database,
			cfg.GetPostgres().Database)

		assert.Equal(t,
			svc.Spec.DynamicConfig.Configs[0].GetPostgres().User,
			cfg.GetPostgres().User)

		assert.Equal(t,
			svc.Spec.DynamicConfig.Configs[0].GetUpstream().GetUrl(),
			cfg.GetUpstream().GetUrl())

		assert.True(t, pbutils.IsEqual(req.Spec, svc.Spec))
	}
}
