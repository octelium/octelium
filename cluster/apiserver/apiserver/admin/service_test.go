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
	"encoding/base64"
	"fmt"
	"math"
	"strings"
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
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

		assert.True(t, pbutils.IsEqual(res.Spec, req.Spec))
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

	{
		name := fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5))
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: name,
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

		rgn, err := srv.GetRegion(ctx, &metav1.GetOptions{
			Name: "default",
		})
		assert.Nil(t, err)
		assert.Equal(t, rgn.Metadata.Uid, svcV.Status.RegionRef.Uid)
		assert.Equal(t, name, svcV.Status.PrimaryHostname)
		assert.NotZero(t, svcV.Status.Port)
	}

	{
		_, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5)),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_TCP,
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},
							Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{
								Eval: `{"upstream": {"url": "https://example.com"}}`,
							},
						},
					},
				},
			},
		})
		assert.NotNil(t, err)
	}

	{
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5)),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},
							Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{
								Eval: `{"upstream": {"url": "https://example.com"}}`,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, 80, ucorev1.ToService(svc).RealPort())
	}

	{
		svc, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("svc-%s", utilrand.GetRandomStringLowercase(5)),
			},
			Spec: &corev1.Service_Spec{
				Port: 8080,
				Mode: corev1.Service_Spec_HTTP,
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},
							Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{
								Eval: `{"upstream": {"url": "https://example.com"}}`,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, 8080, ucorev1.ToService(svc).RealPort())
	}

	{
		_, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode:        corev1.Service_Spec_HTTP,
				IsAnonymous: true,
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
		_, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode:        corev1.Service_Spec_TCP,
				IsAnonymous: true,
				IsPublic:    true,
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
		_, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode:        corev1.Service_Spec_HTTP,
				IsAnonymous: true,
				IsPublic:    true,
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
	}

	{
		_, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode:        corev1.Service_Spec_HTTP,
				IsAnonymous: true,
				IsPublic:    true,
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
							Name: "p1",
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
										Effect: corev1.Policy_Spec_Rule_ALLOW,
									},
								},
							},
						},
					},
				},
			},
		})

		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode:        corev1.Service_Spec_HTTP,
				IsAnonymous: true,
				IsPublic:    true,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
				Authorization: &corev1.Service_Spec_Authorization{
					EnableAnonymous: true,
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Name: "p1",
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
										Effect: corev1.Policy_Spec_Rule_ALLOW,
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
		_, err := srv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode:        corev1.Service_Spec_HTTP,
				IsAnonymous: true,
				IsPublic:    true,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
				Authorization: &corev1.Service_Spec_Authorization{
					EnableAnonymous: true,
				},
			},
		})

		assert.Nil(t, err)
	}
}

func TestCreateServiceReservedName(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	ns, err := srv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	genSvc := func(name string) *corev1.Service {
		return &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: name,
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
			},
		}
	}

	invalids := []string{
		fmt.Sprintf("octelium-gw-%s", utilrand.GetRandomStringCanonical(8)),
		fmt.Sprintf("octelium-region-%s.default", utilrand.GetRandomStringCanonical(8)),
		fmt.Sprintf("octelium%s", utilrand.GetRandomStringCanonical(8)),
	}

	for _, name := range invalids {
		_, err := srv.CreateService(ctx, genSvc(name))
		assert.NotNil(t, err, "%s", name)
		assert.True(t, grpcerr.IsInvalidArg(err), "%s", name)
	}

	{
		svc, err := srv.CreateService(ctx, genSvc(fmt.Sprintf("octelium-gw-%s.%s",
			utilrand.GetRandomStringCanonical(8), ns.Metadata.Name)))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, ns.Metadata.Name, svc.Status.NamespaceRef.Name)
	}

	{
		name := fmt.Sprintf("octelium-gw-%s", utilrand.GetRandomStringCanonical(8))
		svc, err := srv.DoCreateService(ctx, genSvc(name), true)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, fmt.Sprintf("%s.default", name), svc.Metadata.Name)
	}

	{
		_, err := srv.CreateService(ctx, genSvc(fmt.Sprintf("svc-octelium-%s",
			utilrand.GetRandomStringCanonical(8))))
		assert.Nil(t, err, "%+v", err)
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
				Mode: corev1.Service_Spec_TCP,
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
				Mode: corev1.Service_Spec_TCP,
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
				Mode: corev1.Service_Spec_TCP,
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
		assert.Nil(t, err, "%+v", err)
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
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},
							Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{
								Eval: `{"upstream": {"url": "https://example.com"}}`,
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

func TestServiceHostUser(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr, err := srv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err)

	svc, err := srv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					User: usr.Metadata.Name,
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	assert.Equal(t,
		usr.Metadata.Uid,
		svc.Metadata.SpecLabels[fmt.Sprintf("host-user-%s", usr.Metadata.Name)])
}

func TestRDPServices(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	webReq := tests.GenService("")
	webReq.Spec.Mode = corev1.Service_Spec_RDP_WEB
	webReq.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "rdp://localhost",
	}

	webSvc, err := srv.CreateService(ctx, webReq)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, uint32(8080), webSvc.Status.Port)
	assert.Nil(t, webSvc.Status.ManagedService)

	rdpReq := tests.GenService("")
	rdpReq.Spec.Mode = corev1.Service_Spec_RDP
	rdpReq.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "rdp://localhost",
	}
	rdpReq.Spec.Config.Type = &corev1.Service_Spec_Config_Rdp{
		Rdp: &corev1.Service_Spec_Config_RDP{},
	}

	rdpSvc, err := srv.CreateService(ctx, rdpReq)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, uint32(3389), rdpSvc.Status.Port)
	assert.Nil(t, rdpSvc.Status.ManagedService)
}

func TestValidateMCPVisibility(t *testing.T) {
	s := &Server{}

	assert.Nil(t, s.validateMCPVisibility(nil))
	assert.Nil(t, s.validateMCPVisibility(&corev1.Service_Spec_Config_MCP_Visibility{
		DisableRequestBody:     true,
		DisableResponseBody:    true,
		IncludeRequestHeaders:  []string{"User-Agent"},
		IncludeResponseHeaders: []string{"Content-Type"},
		ExcludeRequestHeaders:  []string{"X-Secret"},
	}))

	assert.NotNil(t, s.validateMCPVisibility(&corev1.Service_Spec_Config_MCP_Visibility{
		IncludeRequestHeaders: []string{""},
	}))

	{
		var hdrs []string
		for range maxMCPVisibilityHeaders + 1 {
			hdrs = append(hdrs, "User-Agent")
		}
		assert.NotNil(t, s.validateMCPVisibility(&corev1.Service_Spec_Config_MCP_Visibility{
			ExcludeResponseHeaders: hdrs,
		}))
	}
}

func TestValidateLLMModel(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	assert.Nil(t, s.validateLLMModel(ctx, nil))
	assert.Nil(t, s.validateLLMModel(ctx, &corev1.Service_Spec_Config_LLM_Model{}))

	assert.Nil(t, s.validateLLMModel(ctx, &corev1.Service_Spec_Config_LLM_Model{
		Type: &corev1.Service_Spec_Config_LLM_Model_Value{
			Value: "gpt-4o",
		},
	}))

	assert.Nil(t, s.validateLLMModel(ctx, &corev1.Service_Spec_Config_LLM_Model{
		Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
			Eval: `ctx.request.llm.model == "fast" ? "gpt-4o-mini" : "gpt-4o"`,
		},
	}))

	assert.NotNil(t, s.validateLLMModel(ctx, &corev1.Service_Spec_Config_LLM_Model{
		Type: &corev1.Service_Spec_Config_LLM_Model_Value{
			Value: "",
		},
	}))

	assert.NotNil(t, s.validateLLMModel(ctx, &corev1.Service_Spec_Config_LLM_Model{
		Type: &corev1.Service_Spec_Config_LLM_Model_Value{
			Value: strings.Repeat("a", maxLLMModelLen+1),
		},
	}))

	assert.NotNil(t, s.validateLLMModel(ctx, &corev1.Service_Spec_Config_LLM_Model{
		Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
			Eval: `((((`,
		},
	}))

	for _, arg := range []string{
		"gpt-4o\r\nx-injected: 1",
		"gpt-4o\n",
		"gpt-4o\x00",
		"gpt-4o\x7f",
	} {
		assert.NotNil(t, s.validateLLMModel(ctx, &corev1.Service_Spec_Config_LLM_Model{
			Type: &corev1.Service_Spec_Config_LLM_Model_Value{
				Value: arg,
			},
		}), arg)
	}
}

func TestValidateLLMReasoning(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	assert.Nil(t, s.validateLLMReasoning(ctx, nil))

	assert.Nil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
			Level: corev1.Service_Spec_Config_LLM_Reasoning_NONE,
		},
	}))

	assert.Nil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_TokenBudget{
			TokenBudget: 4096,
		},
	}))

	assert.Nil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Eval{
			Eval: `ctx.request.llm.model == "gpt-5" ? "HIGH" : "LOW"`,
		},
	}))

	assert.NotNil(t, s.validateLLMReasoning(ctx,
		&corev1.Service_Spec_Config_LLM_Reasoning{}))

	assert.NotNil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
			Level: corev1.Service_Spec_Config_LLM_Reasoning_LEVEL_UNSET,
		},
	}))

	assert.NotNil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
			Level: corev1.Service_Spec_Config_LLM_Reasoning_Level(1000),
		},
	}))

	assert.NotNil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_TokenBudget{
			TokenBudget: 0,
		},
	}))

	assert.NotNil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_TokenBudget{
			TokenBudget: maxLLMReasoningTokens + 1,
		},
	}))

	assert.Nil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
			Level: corev1.Service_Spec_Config_LLM_Reasoning_MAX,
		},
	}))

	assert.Nil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Effort{
			Effort: "xhigh",
		},
	}))

	assert.NotNil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Effort{
			Effort: "",
		},
	}))

	assert.NotNil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Effort{
			Effort: utilrand.GetRandomStringCanonical(maxLLMReasoningEffortLen + 1),
		},
	}))

	assert.NotNil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Effort{
			Effort: "high\x00",
		},
	}))

	assert.NotNil(t, s.validateLLMReasoning(ctx, &corev1.Service_Spec_Config_LLM_Reasoning{
		Type: &corev1.Service_Spec_Config_LLM_Reasoning_Eval{
			Eval: `((((`,
		},
	}))
}

func newTokenRateLimit() *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit {
	return &corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit{
		Scope: corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL,
		Limit: 500000,
		Window: &metav1.Duration{
			Type: &metav1.Duration_Minutes{Minutes: 1},
		},
	}
}

func TestValidateLLMTokenRateLimit(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	assert.Nil(t, s.validateLLMTokenRateLimit(ctx, newTokenRateLimit()))

	{
		cfg := newTokenRateLimit()
		cfg.Scope = corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_SCOPE_UNSET
		assert.Nil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.DefaultOutputTokens = 4096
		cfg.DenyMessage = "You are out of tokens"
		cfg.Key = &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerUser{
				PerUser: true,
			},
		}
		cfg.Headers = []*corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_KeyValue{
			{
				Key:   "Retry-After",
				Value: "60",
			},
		}
		assert.Nil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.Key = &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_Eval{
				Eval: `ctx.user.metadata.uid`,
			},
		}
		assert.Nil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.Scope = corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_Scope(1000)
		assert.NotNil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.Limit = 0
		assert.NotNil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.Limit = -1
		assert.NotNil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.Window = nil
		assert.NotNil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.DefaultOutputTokens = maxLLMTokenRateLimitTokens + 1
		assert.NotNil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.Key = &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_Eval{
				Eval: `((((`,
			},
		}
		assert.NotNil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}

	{
		cfg := newTokenRateLimit()
		cfg.Headers = []*corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_KeyValue{
			{
				Key:   "Retry After",
				Value: "60",
			},
		}
		assert.NotNil(t, s.validateLLMTokenRateLimit(ctx, cfg))
	}
}

func newMCPGuardrailPattern(
	action corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Action) *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern {
	return &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
		Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets_{
			Secrets: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Secrets{},
		},
		Action: action,
	}
}

func TestValidateMCPGuardrail(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	assert.Nil(t, s.validateMCPGuardrail(ctx,
		&corev1.Service_Spec_Config_MCP_Plugin_Guardrail{
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				newMCPGuardrailPattern(
					corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT),
			},
		}))

	assert.Nil(t, s.validateMCPGuardrail(ctx,
		&corev1.Service_Spec_Config_MCP_Plugin_Guardrail{
			Leg: corev1.Service_Spec_Config_MCP_Plugin_Guardrail_RESPONSE,
			Scopes: []corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope{
				corev1.Service_Spec_Config_MCP_Plugin_Guardrail_TOOL_DEFINITIONS,
			},
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				newMCPGuardrailPattern(
					corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY),
			},
		}))

	assert.NotNil(t, s.validateMCPGuardrail(ctx,
		&corev1.Service_Spec_Config_MCP_Plugin_Guardrail{}))

	assert.NotNil(t, s.validateMCPGuardrail(ctx,
		&corev1.Service_Spec_Config_MCP_Plugin_Guardrail{
			Leg: corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Leg(1000),
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				newMCPGuardrailPattern(
					corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY),
			},
		}))

	assert.NotNil(t, s.validateMCPGuardrail(ctx,
		&corev1.Service_Spec_Config_MCP_Plugin_Guardrail{
			Scopes: []corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope{
				corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope(1000),
			},
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				newMCPGuardrailPattern(
					corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY),
			},
		}))

	assert.NotNil(t, s.validateMCPGuardrail(ctx,
		&corev1.Service_Spec_Config_MCP_Plugin_Guardrail{
			Leg: corev1.Service_Spec_Config_MCP_Plugin_Guardrail_RESPONSE,
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				newMCPGuardrailPattern(
					corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT),
			},
		}))

	assert.NotNil(t, s.validateMCPGuardrail(ctx,
		&corev1.Service_Spec_Config_MCP_Plugin_Guardrail{
			Scopes: []corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope{
				corev1.Service_Spec_Config_MCP_Plugin_Guardrail_TOOL_DEFINITIONS,
			},
			Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
				newMCPGuardrailPattern(
					corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_STRIP),
			},
		}))
}

func TestValidateMCPPlugins(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	newPlugin := func(name string) *corev1.Service_Spec_Config_MCP_Plugin {
		return &corev1.Service_Spec_Config_MCP_Plugin{
			Name: name,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{MatchAny: true},
			},
			Type: &corev1.Service_Spec_Config_MCP_Plugin_Guardrail_{
				Guardrail: &corev1.Service_Spec_Config_MCP_Plugin_Guardrail{
					Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
						newMCPGuardrailPattern(
							corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY),
					},
				},
			},
		}
	}

	assert.Nil(t, s.validateMCPPlugins(ctx, "default", nil))

	assert.Nil(t, s.validateMCPPlugins(ctx, "default",
		[]*corev1.Service_Spec_Config_MCP_Plugin{newPlugin("g1"), newPlugin("g2")}))

	assert.NotNil(t, s.validateMCPPlugins(ctx, "default",
		[]*corev1.Service_Spec_Config_MCP_Plugin{newPlugin("g1"), newPlugin("g1")}))

	{
		plugin := newPlugin("g1")
		plugin.Phase = corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH
		assert.NotNil(t, s.validateMCPPlugins(ctx, "default",
			[]*corev1.Service_Spec_Config_MCP_Plugin{plugin}))
	}

	{
		plugin := newPlugin("g1")
		plugin.Type = nil
		assert.NotNil(t, s.validateMCPPlugins(ctx, "default",
			[]*corev1.Service_Spec_Config_MCP_Plugin{plugin}))
	}

	{
		var plugins []*corev1.Service_Spec_Config_MCP_Plugin
		for range maxPlugins + 1 {
			plugins = append(plugins, newPlugin("g1"))
		}
		assert.NotNil(t, s.validateMCPPlugins(ctx, "default", plugins))
	}
}

func TestValidateLLMLimits(t *testing.T) {
	s := &Server{}

	assert.Nil(t, s.validateLLMLimits(nil))
	assert.Nil(t, s.validateLLMLimits(&corev1.Service_Spec_Config_LLM_Limits{
		MaxRequestBytes:         16 * 1024 * 1024,
		MaxStreamEventBytes:     512 * 1024,
		MaxEstimatedInputTokens: 100000,
		MaxOutputTokens:         16000,
		MaxTools:                64,
	}))

	assert.NotNil(t, s.validateLLMLimits(&corev1.Service_Spec_Config_LLM_Limits{
		MaxRequestBytes: maxLLMRequestBytesLimit + 1,
	}))

	assert.NotNil(t, s.validateLLMLimits(&corev1.Service_Spec_Config_LLM_Limits{
		MaxStreamEventBytes: maxLLMStreamEventBytesLimit + 1,
	}))
}

func TestValidateLLMTranslation(t *testing.T) {
	s := &Server{}

	newLLM := func(protocol, upstreamProtocol corev1.Service_Spec_Config_LLM_Protocol,
		defaultMaxOutputTokens uint64) *corev1.Service_Spec_Config_LLM {
		return &corev1.Service_Spec_Config_LLM{
			Protocol: protocol,
			Translation: &corev1.Service_Spec_Config_LLM_Translation{
				UpstreamProtocol:       upstreamProtocol,
				DefaultMaxOutputTokens: defaultMaxOutputTokens,
			},
		}
	}

	assert.Nil(t, s.validateLLMTranslation(&corev1.Service_Spec_Config_LLM{}))

	assert.Nil(t, s.validateLLMTranslation(newLLM(
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_PROTOCOL_UNSET, 0)))

	assert.Nil(t, s.validateLLMTranslation(newLLM(
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_OPENAI, 0)))

	assert.Nil(t, s.validateLLMTranslation(newLLM(
		corev1.Service_Spec_Config_LLM_PROTOCOL_UNSET,
		corev1.Service_Spec_Config_LLM_ANTHROPIC, 4096)))

	assert.Nil(t, s.validateLLMTranslation(newLLM(
		corev1.Service_Spec_Config_LLM_ANTHROPIC,
		corev1.Service_Spec_Config_LLM_OPENAI, 0)))

	for _, protocol := range []corev1.Service_Spec_Config_LLM_Protocol{
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_ANTHROPIC,
		corev1.Service_Spec_Config_LLM_GEMINI,
		corev1.Service_Spec_Config_LLM_BEDROCK,
	} {
		for _, upstreamProtocol := range []corev1.Service_Spec_Config_LLM_Protocol{
			corev1.Service_Spec_Config_LLM_OPENAI,
			corev1.Service_Spec_Config_LLM_ANTHROPIC,
			corev1.Service_Spec_Config_LLM_GEMINI,
			corev1.Service_Spec_Config_LLM_BEDROCK,
		} {
			assert.Nil(t, s.validateLLMTranslation(
				newLLM(protocol, upstreamProtocol, 0)))
		}
	}

	assert.NotNil(t, s.validateLLMTranslation(newLLM(
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_ANTHROPIC,
		maxLLMTranslationOutputTokens+1)))

	assert.NotNil(t, s.validateLLMTranslation(newLLM(
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_Protocol(1000), 0)))
}

func newLLMEmbedding() *corev1.Service_Spec_Config_LLM_Embedding {
	return &corev1.Service_Spec_Config_LLM_Embedding{
		Model: "text-embedding-3-small",
		Source: &corev1.Service_Spec_Config_LLM_Embedding_Source{
			Type: &corev1.Service_Spec_Config_LLM_Embedding_Source_CurrentUpstream{
				CurrentUpstream: true,
			},
		},
	}
}

func newLLMEmbeddingUpstream() *corev1.Service_Spec_Config_LLM_Embedding {
	return &corev1.Service_Spec_Config_LLM_Embedding{
		Model: "text-embedding-3-small",
		Source: &corev1.Service_Spec_Config_LLM_Embedding_Source{
			Type: &corev1.Service_Spec_Config_LLM_Embedding_Source_Upstream_{
				Upstream: &corev1.Service_Spec_Config_LLM_Embedding_Source_Upstream{
					Url: "https://api.openai.com/v1",
				},
			},
		},
	}
}

func TestValidateLLMEmbedding(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	assert.Nil(t, s.validateLLMEmbedding(ctx, nil))
	assert.Nil(t, s.validateLLMEmbedding(ctx, newLLMEmbedding()))
	assert.Nil(t, s.validateLLMEmbedding(ctx, newLLMEmbeddingUpstream()))

	{
		cfg := newLLMEmbedding()
		cfg.Dimensions = 512
		assert.Nil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	{
		cfg := newLLMEmbedding()
		cfg.Model = ""
		assert.NotNil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	{
		cfg := newLLMEmbedding()
		cfg.Dimensions = maxLLMEmbeddingDimensions + 1
		assert.NotNil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	{
		cfg := newLLMEmbedding()
		cfg.Source = nil
		assert.NotNil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	{
		cfg := newLLMEmbeddingUpstream()
		cfg.GetSource().GetUpstream().Url = "ftp://example.com"
		assert.NotNil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	{
		cfg := newLLMEmbeddingUpstream()
		cfg.GetSource().GetUpstream().Url = "/v1"
		assert.NotNil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	{
		cfg := newLLMEmbeddingUpstream()
		cfg.GetSource().GetUpstream().Url = "https://api.openai.com/v1?api-version=1"
		assert.NotNil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	for _, protocol := range []corev1.Service_Spec_Config_LLM_Protocol{
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_GEMINI,
	} {
		cfg := newLLMEmbeddingUpstream()
		cfg.GetSource().GetUpstream().Protocol = protocol
		assert.Nil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	for _, protocol := range []corev1.Service_Spec_Config_LLM_Protocol{
		corev1.Service_Spec_Config_LLM_ANTHROPIC,
		corev1.Service_Spec_Config_LLM_BEDROCK,
	} {
		cfg := newLLMEmbeddingUpstream()
		cfg.GetSource().GetUpstream().Protocol = protocol
		assert.NotNil(t, s.validateLLMEmbedding(ctx, cfg))
	}

	{
		cfg := newLLMEmbeddingUpstream()
		cfg.GetSource().GetUpstream().Auth = &corev1.Service_Spec_Config_HTTP_Auth{
			Type: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4_{
				Sigv4: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4{
					Region: "us-east-1",
				},
			},
		}
		assert.NotNil(t, s.validateLLMEmbedding(ctx, cfg))
	}
}

func newLLMSemanticCache() *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache {
	return &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache{
		Embedding:     newLLMEmbedding(),
		MinSimilarity: 0.95,
	}
}

func TestValidateLLMSemanticCache(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	assert.Nil(t, s.validateLLMSemanticCache(ctx,
		&corev1.Service_Spec_Config_LLM_Plugin_SemanticCache{}))
	assert.Nil(t, s.validateLLMSemanticCache(ctx, newLLMSemanticCache()))

	{
		cfg := newLLMSemanticCache()
		cfg.Ttl = &metav1.Duration{
			Type: &metav1.Duration_Hours{Hours: 2},
		}
		cfg.MaxSize = 128 * 1024
		cfg.UseXCacheHeader = true
		cfg.Scope = &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope{
			Type: &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope_Eval{
				Eval: `ctx.user.metadata.uid`,
			},
		}
		assert.Nil(t, s.validateLLMSemanticCache(ctx, cfg))
	}

	{
		cfg := newLLMSemanticCache()
		cfg.MinSimilarity = 1.5
		assert.NotNil(t, s.validateLLMSemanticCache(ctx, cfg))
	}

	{
		cfg := newLLMSemanticCache()
		cfg.MinSimilarity = float32(math.NaN())
		assert.NotNil(t, s.validateLLMSemanticCache(ctx, cfg))
	}

	{
		cfg := newLLMSemanticCache()
		cfg.MaxSize = maxLLMSemanticCacheSize + 1
		assert.NotNil(t, s.validateLLMSemanticCache(ctx, cfg))
	}

	{
		cfg := newLLMSemanticCache()
		cfg.Scope = &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope{
			Type: &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope_Eval{
				Eval: `!!!`,
			},
		}
		assert.NotNil(t, s.validateLLMSemanticCache(ctx, cfg))
	}

	{
		cfg := newLLMSemanticCache()
		cfg.Embedding.Model = ""
		assert.NotNil(t, s.validateLLMSemanticCache(ctx, cfg))
	}
}

func newLLMSemanticRouter() *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter {
	return &corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter{
		Embedding: newLLMEmbedding(),
		Routes: []*corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter_Route{
			{
				Name:     "code",
				Examples: []string{"Why does this Go program deadlock?"},
				Model:    "gpt-5",
			},
		},
		FallbackModel: "gpt-5-mini",
	}
}

func TestValidateLLMSemanticRouter(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	assert.Nil(t, s.validateLLMSemanticRouter(ctx, newLLMSemanticRouter()))

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes[0].Description = "Software development and debugging"
		cfg.Routes[0].Examples = nil
		cfg.Routes[0].MinSimilarity = 0.8
		assert.Nil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes = nil
		assert.NotNil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes = append(cfg.Routes,
			&corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter_Route{
				Name:     "code",
				Examples: []string{"Another example"},
				Model:    "o3",
			})
		assert.NotNil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes[0].Model = ""
		assert.NotNil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes[0].Name = ""
		assert.NotNil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes[0].Examples = nil
		assert.NotNil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes[0].Examples = []string{strings.Repeat("a", maxLLMSemanticTextLen+1)}
		assert.NotNil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes[0].MinSimilarity = -1
		assert.NotNil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}

	{
		cfg := newLLMSemanticRouter()
		cfg.FallbackModel = strings.Repeat("a", maxLLMModelLen+1)
		assert.NotNil(t, s.validateLLMSemanticRouter(ctx, cfg))
	}
}

func TestValidateLLMSemanticPlugins(t *testing.T) {
	ctx := context.Background()
	s := &Server{}

	newPlugin := func(name string, typ any) *corev1.Service_Spec_Config_LLM_Plugin {
		ret := &corev1.Service_Spec_Config_LLM_Plugin{
			Name: name,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{MatchAny: true},
			},
		}
		switch cur := typ.(type) {
		case *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache:
			ret.Type = &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_{SemanticCache: cur}
		case *corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter:
			ret.Type = &corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter_{SemanticRouter: cur}
		}
		return ret
	}

	assert.Nil(t, s.validateLLMPlugins(ctx, "", []*corev1.Service_Spec_Config_LLM_Plugin{
		newPlugin("cache", newLLMSemanticCache()),
		newPlugin("router", newLLMSemanticRouter()),
	}))

	{
		cfg := newLLMSemanticRouter()
		cfg.Routes[0].Model = ""
		assert.NotNil(t, s.validateLLMPlugins(ctx, "",
			[]*corev1.Service_Spec_Config_LLM_Plugin{
				newPlugin("router", cfg),
			}))
	}
}

func tstServiceConfig(t *testing.T, value string) *corev1.Service_Spec_Config {
	t.Helper()
	ret := &corev1.Service_Spec_Config{}
	require.Nil(t, pbutils.UnmarshalJSONStrict([]byte(value), ret))
	return ret
}

func TestServiceUpstreamValidation(t *testing.T) {
	s := newTstServer(func(method string, req, resp any) error { return nil })
	for _, tc := range []struct {
		name  string
		value string
		port  uint32
		valid bool
	}{
		{"HTTP", `{"url":"https://example.com"}`, 0, true},
		{"IPv6", `{"url":"http://[2001:db8::1]:8080"}`, 0, true},
		{"TCP", `{"url":"tcp://example.com:8080"}`, 0, true},
		{"Empty", `{}`, 0, false},
		{"EmptyURL", `{"url":""}`, 0, false},
		{"InvalidURL", `{"url":"http://%"}`, 0, false},
		{"NoScheme", `{"url":"example.com"}`, 0, false},
		{"MissingPort", `{"url":"tcp://example.com"}`, 0, false},
		{"ZeroPort", `{"url":"http://example.com:0"}`, 0, false},
		{"LargePort", `{"url":"http://example.com:65536"}`, 0, false},
		{"LongURL", `{"url":"https://example.com/` + strings.Repeat("a", 2049) + `"}`, 0, false},
		{"EmptyLoadbalance", `{"loadbalance":{}}`, 0, false},
		{"MissingEndpointURL", `{"loadbalance":{"endpoints":[{}]}}`, 0, false},
		{"Loadbalance", `{"loadbalance":{"endpoints":[{"url":"http://one.example.com"},{"url":"http://two.example.com"}]}}`, 0, true},
		{"DifferentSchemes", `{"loadbalance":{"endpoints":[{"url":"http://one.example.com"},{"url":"https://two.example.com"}]}}`, 8080, false},
		{"DifferentPorts", `{"loadbalance":{"endpoints":[{"url":"http://one.example.com:8080"},{"url":"http://two.example.com:8081"}]}}`, 0, false},
		{"ExplicitPort", `{"loadbalance":{"endpoints":[{"url":"http://one.example.com:8080"},{"url":"http://two.example.com:8081"}]}}`, 9000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tstServiceConfig(t, `{"upstream":`+tc.value+`}`)
			err := s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Port: tc.port}}, false)
			if tc.valid {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			}
		})
	}
	cfg := &corev1.Service_Spec_Config{Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{Endpoints: make([]*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint, 101)}}}}
	assert.NotNil(t, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{}}, false))
	assert.NotNil(t, s.ValidateServiceConfig(t.Context(), nil, &corev1.Service{Spec: &corev1.Service_Spec{}}, false))
}

func TestServiceContainerValidation(t *testing.T) {
	s := newTstServer(func(method string, req, resp any) error { return nil })
	for _, tc := range []struct {
		name  string
		value string
		valid bool
	}{
		{"Minimal", `{"image":"example/image","port":8080}`, true},
		{"MissingImage", `{"port":8080}`, false},
		{"LongImage", `{"image":"` + strings.Repeat("a", 257) + `","port":8080}`, false},
		{"MissingPort", `{"image":"example/image"}`, false},
		{"TooManyReplicas", `{"image":"example/image","port":8080,"replicas":101}`, false},
		{"LongArgument", `{"image":"example/image","port":8080,"args":["` + strings.Repeat("a", 1025) + `"]}`, false},
		{"LongCommand", `{"image":"example/image","port":8080,"command":["` + strings.Repeat("a", 1025) + `"]}`, false},
		{"LiteralEnvironment", `{"image":"example/image","port":8080,"env":[{"name":"KEY","value":"value"}]}`, true},
		{"MissingEnvName", `{"image":"example/image","port":8080,"env":[{"value":"value"}]}`, false},
		{"MissingEnvType", `{"image":"example/image","port":8080,"env":[{"name":"KEY"}]}`, false},
		{"LongEnvValue", `{"image":"example/image","port":8080,"env":[{"name":"KEY","value":"` + strings.Repeat("a", 2049) + `"}]}`, false},
		{"KubernetesSecret", `{"image":"example/image","port":8080,"env":[{"name":"KEY","kubernetesSecretRef":{"name":"secret","key":"key"}}]}`, true},
		{"KubernetesSecretName", `{"image":"example/image","port":8080,"env":[{"name":"KEY","kubernetesSecretRef":{"key":"key"}}]}`, false},
		{"KubernetesSecretKey", `{"image":"example/image","port":8080,"env":[{"name":"KEY","kubernetesSecretRef":{"name":"secret"}}]}`, false},
		{"CapabilityAdd", `{"image":"example/image","port":8080,"securityContext":{"capabilities":{"add":["NET_ADMIN"],"drop":["ALL"]}}}`, true},
		{"InvalidCapabilityAdd", `{"image":"example/image","port":8080,"securityContext":{"capabilities":{"add":["net_admin"]}}}`, false},
		{"InvalidCapabilityDrop", `{"image":"example/image","port":8080,"securityContext":{"capabilities":{"drop":["NET ADMIN"]}}}`, false},
		{"MissingVolumeType", `{"image":"example/image","port":8080,"volumes":[{"name":"data"}]}`, false},
		{"PVC", `{"image":"example/image","port":8080,"volumes":[{"name":"data","persistentVolumeClaim":{"name":"claim"}}],"volumeMounts":[{"name":"data","mountPath":"/data","subPath":"nested"}]}`, true},
		{"MissingPVCName", `{"image":"example/image","port":8080,"volumes":[{"name":"data","persistentVolumeClaim":{}}]}`, false},
		{"BadVolumeName", `{"image":"example/image","port":8080,"volumes":[{"name":"/data"}]}`, false},
		{"BadMountName", `{"image":"example/image","port":8080,"volumeMounts":[{"name":"/data","mountPath":"/data"}]}`, false},
		{"BadMountPath", `{"image":"example/image","port":8080,"volumeMounts":[{"name":"data","mountPath":"/data\u0000"}]}`, false},
		{"BadSubPath", `{"image":"example/image","port":8080,"volumeMounts":[{"name":"data","mountPath":"/data","subPath":"` + strings.Repeat("a", 257) + `"}]}`, false},
		{"HTTPProbe", `{"image":"example/image","port":8080,"readinessProbe":{"httpGet":{"path":"/ready","port":8080}}}`, true},
		{"TCPProbe", `{"image":"example/image","port":8080,"livenessProbe":{"tcpSocket":{"port":8080}}}`, true},
		{"GRPCProbe", `{"image":"example/image","port":8080,"readinessProbe":{"grpc":{"port":8080}}}`, true},
		{"MissingProbeType", `{"image":"example/image","port":8080,"readinessProbe":{}}`, false},
		{"InvalidProbePort", `{"image":"example/image","port":8080,"livenessProbe":{"grpc":{"port":65536}}}`, false},
		{"InvalidProbePath", `{"image":"example/image","port":8080,"readinessProbe":{"httpGet":{"path":"invalid path","port":8080}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tstServiceConfig(t, `{"upstream":{"container":`+tc.value+`}}`)
			err := s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}, false)
			assert.Equal(t, tc.valid, err == nil, "%+v", err)
		})
	}
}

func TestServiceHTTPHeaders(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`{}`, true},
		{`{"addRequestHeaders":[{"key":"X-Value","value":""}]}`, true},
		{`{"addRequestHeaders":[{"key":"X-Value","value":"value\r\nInjected: true"}]}`, false},
		{`{"addRequestHeaders":[{"key":"Bad Name","value":"value"}]}`, false},
		{`{"addRequestHeaders":[{"key":"X-Value"}]}`, false},
		{`{"addRequestHeaders":[{"key":"X-Value","eval":"ctx.user.metadata.name"}]}`, true},
		{`{"addRequestHeaders":[{"key":"X-Value","eval":"true"}]}`, false},
		{`{"addResponseHeaders":[{"key":"X-Value","value":"value"}]}`, true},
		{`{"addResponseHeaders":[{"key":"Bad Name","value":"value"}]}`, false},
		{`{"addResponseHeaders":[{"key":"X-Value"}]}`, false},
		{`{"addResponseHeaders":[{"key":"X-Value","eval":"ctx.user.metadata.name"}]}`, true},
		{`{"addResponseHeaders":[{"key":"X-Value","eval":"42"}]}`, false},
		{`{"removeRequestHeaders":[""]}`, false},
		{`{"removeResponseHeaders":[""]}`, false},
	} {
		hdr := &corev1.Service_Spec_Config_HTTP_Header{}
		require.Nil(t, pbutils.UnmarshalJSONStrict([]byte(tc.value), hdr))
		assert.Equal(t, tc.valid, s.validateHTTPHeader(t.Context(), hdr) == nil, tc.value)
	}
	for _, field := range []string{"addRequestHeaders", "addResponseHeaders", "removeRequestHeaders", "removeResponseHeaders"} {
		value := `"X-Value"`
		if strings.HasPrefix(field, "add") {
			value = `{"key":"X-Value","value":"value"}`
		}
		hdr := &corev1.Service_Spec_Config_HTTP_Header{}
		require.Nil(t, pbutils.UnmarshalJSONStrict([]byte(`{"`+field+`":[`+strings.Repeat(value+",", 256)+value+`]}`), hdr))
		assert.Equal(t, codes.InvalidArgument, status.Code(s.validateHTTPHeader(t.Context(), hdr)))
	}
}

func TestServiceHTTPAuth(t *testing.T) {
	s := newTstServer(func(method string, req, resp any) error { return nil })
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`{}`, true},
		{`{"bearer":{"fromSecret":"secret"}}`, true},
		{`{"bearer":{}}`, false},
		{`{"basic":{"username":"user","password":{"fromSecret":"secret"}}}`, true},
		{`{"basic":{"password":{"fromSecret":"secret"}}}`, false},
		{`{"basic":{"username":"user"}}`, false},
		{`{"basic":{"username":"日本語"}}`, false},
		{`{"custom":{"header":"X-Token","value":{"fromSecret":"secret"}}}`, true},
		{`{"custom":{"value":{"fromSecret":"secret"}}}`, false},
		{`{"custom":{"header":"X-Token"}}`, false},
		{`{"sigv4":{"service":"s3","region":"us-east-1","accessKeyID":"key","secretAccessKey":{"fromSecret":"secret"}}}`, true},
		{`{"sigv4":{}}`, false},
		{`{"sigv4":{"service":"s3"}}`, false},
		{`{"sigv4":{"service":"s3","region":"us-east-1"}}`, false},
		{`{"sigv4":{"service":"s3","region":"us-east-1","accessKeyID":"key"}}`, false},
		{`{"oauth2ClientCredentials":{"clientID":"client","tokenURL":"https://example.com/token","clientSecret":{"fromSecret":"secret"}}}`, true},
		{`{"oauth2ClientCredentials":{}}`, false},
		{`{"oauth2ClientCredentials":{"clientID":"client"}}`, false},
		{`{"oauth2ClientCredentials":{"clientID":"client","tokenURL":"https://example.com/token"}}`, false},
	} {
		auth := &corev1.Service_Spec_Config_HTTP_Auth{}
		require.Nil(t, pbutils.UnmarshalJSONStrict([]byte(tc.value), auth))
		assert.Equal(t, tc.valid, s.validateHTTPAuth(t.Context(), auth) == nil, tc.value)
	}
}

func TestServiceSharedPlugins(t *testing.T) {
	s := &Server{}
	for _, mode := range []corev1.Service_Spec_Mode{corev1.Service_Spec_HTTP, corev1.Service_Spec_MCP, corev1.Service_Spec_LLM} {
		for _, tc := range []struct {
			name  string
			value string
			valid bool
		}{
			{"Lua", `"lua":{"inline":"return true"}`, true},
			{"EmptyLua", `"lua":{}`, false},
			{"LongLua", `"lua":{"inline":"` + strings.Repeat("a", 20001) + `"}`, false},
			{"Direct", `"direct":{"statusCode":200,"headers":[{"key":"X-Value","value":"value"}],"body":{"inline":"response"}}`, true},
			{"BadStatus", `"direct":{"statusCode":600}`, false},
			{"BadHeaderName", `"direct":{"headers":[{"key":"Bad Name","value":"value"}]}`, false},
			{"BadHeaderValue", `"direct":{"headers":[{"key":"X-Value","value":"value\r\nInjected: true"}]}`, false},
			{"LongDirectBody", `"direct":{"body":{"inline":"` + strings.Repeat("a", 50001) + `"}}`, false},
			{"ExtProc", `"extProc":{"address":"extproc.example.com:8080","messageTimeout":{"milliseconds":6000}}`, true},
			{"ExtProcAddress", `"extProc":{"address":"invalid"}`, false},
			{"ExtProcTimeout", `"extProc":{"address":"extproc.example.com:8080","messageTimeout":{"milliseconds":6001}}`, false},
			{"ExtProcContainer", `"extProc":{"container":{"image":"example/image"}}`, true},
			{"ExtProcImage", `"extProc":{"container":{}}`, false},
			{"LongExtProcImage", `"extProc":{"container":{"image":"` + strings.Repeat("a", 257) + `"}}`, false},
			{"JSONSchema", `"jsonSchema":{"inline":"{\"type\":\"object\"}","headers":[{"key":"X-Value","value":"value"}],"body":{"inline":"invalid body"}}`, true},
			{"JSONSchemaType", `"jsonSchema":{}`, false},
			{"JSONSchemaEmpty", `"jsonSchema":{"inline":""}`, false},
			{"JSONSchemaMalformed", `"jsonSchema":{"inline":"{"}`, false},
			{"JSONSchemaLong", `"jsonSchema":{"inline":"` + strings.Repeat("a", 30001) + `"}`, false},
			{"JSONSchemaHeaderName", `"jsonSchema":{"inline":"{}","headers":[{"key":"Bad Name","value":"value"}]}`, false},
			{"JSONSchemaHeaderValue", `"jsonSchema":{"inline":"{}","headers":[{"key":"X-Value","value":"value\r\n"}]}`, false},
			{"JSONSchemaBody", `"jsonSchema":{"inline":"{}","body":{"inline":"` + strings.Repeat("a", 50001) + `"}}`, false},
			{"Path", `"path":{"addPrefix":"/api","removePrefix":"/old"}`, true},
			{"PathAdd", `"path":{"addPrefix":"invalid path"}`, false},
			{"PathRemove", `"path":{"removePrefix":"invalid path"}`, false},
			{"PathLongAdd", `"path":{"addPrefix":"/` + strings.Repeat("a", 513) + `"}`, false},
			{"PathLongRemove", `"path":{"removePrefix":"/` + strings.Repeat("a", 513) + `"}`, false},
			{"RateLimit", `"rateLimit":{"limit":1,"window":{"seconds":1},"statusCode":429,"headers":[{"key":"X-Value","value":"value"}],"body":{"inline":"limited"}}`, true},
			{"RateLimitZero", `"rateLimit":{"window":{"seconds":1}}`, false},
			{"RateLimitNegative", `"rateLimit":{"limit":-1,"window":{"seconds":1}}`, false},
			{"RateLimitWindow", `"rateLimit":{"limit":1}`, false},
			{"RateLimitDuration", `"rateLimit":{"limit":1,"window":{"seconds":0}}`, false},
			{"RateLimitStatus", `"rateLimit":{"limit":1,"window":{"seconds":1},"statusCode":600}`, false},
			{"RateLimitHeaderName", `"rateLimit":{"limit":1,"window":{"seconds":1},"headers":[{"key":"Bad Name","value":"value"}]}`, false},
			{"RateLimitHeaderValue", `"rateLimit":{"limit":1,"window":{"seconds":1},"headers":[{"key":"X-Value","value":"value\r\n"}]}`, false},
			{"RateLimitBody", `"rateLimit":{"limit":1,"window":{"seconds":1},"body":{"inline":"` + strings.Repeat("a", 50001) + `"}}`, false},
		} {
			t.Run(mode.String()+"/"+tc.name, func(t *testing.T) {
				key := strings.ToLower(mode.String())
				cfg := tstServiceConfig(t, `{"`+key+`":{"plugins":[{"name":"plugin","condition":{"matchAny":true},`+tc.value+`}]}}`)
				err := s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: mode}}, false)
				assert.Equal(t, tc.valid, err == nil, "%+v", err)
			})
		}
	}
}

func TestServiceHTTPPluginLists(t *testing.T) {
	s := &Server{}
	for _, value := range []string{
		`{"plugins":[{"name":"plugin","condition":{"matchAny":true}}]}`,
		`{"plugins":[{"name":"invalid/name","condition":{"matchAny":true},"lua":{"inline":"return true"}}]}`,
		`{"plugins":[{"name":"plugin","condition":{"match":"1"},"lua":{"inline":"return true"}}]}`,
		`{"plugins":[{"name":"plugin","condition":{"matchAny":true},"lua":{"inline":"return true"}},{"name":"plugin","condition":{"matchAny":true},"lua":{"inline":"return true"}}]}`,
		`{"plugins":[{"name":"plugin","lua":{"inline":"return true"}}]}`,
		`{"plugins":[{"name":"plugin","condition":{"matchAny":true},"cache":{"ttl":{"seconds":0}}}]}`,
		`{"plugins":[{"name":"plugin","condition":{"matchAny":true},"cache":{"key":{}}}]}`,
		`{"plugins":[{"name":"plugin","condition":{"matchAny":true},"cache":{"key":{"eval":"true"}}}]}`,
		`{"plugins":[{"name":"plugin","condition":{"matchAny":true},"cache":{"maxSize":256000001}}]}`,
	} {
		cfg := tstServiceConfig(t, `{"http":`+value+`}`)
		assert.NotNil(t, s.validateHTTPPlugins(t.Context(), "default", cfg.GetHttp().Plugins), value)
	}
	cfg := tstServiceConfig(t, `{"http":{"plugins":[{"name":"plugin","condition":{"matchAny":true},"cache":{"ttl":{"seconds":1},"key":{"eval":"ctx.user.metadata.name"},"maxSize":256000000}}]}}`)
	assert.Nil(t, s.validateHTTPPlugins(t.Context(), "default", cfg.GetHttp().Plugins))
	assert.NotNil(t, s.validateHTTPPlugins(t.Context(), "default", make([]*corev1.Service_Spec_Config_HTTP_Plugin, maxPlugins+1)))
}

func TestServiceHTTPPaths(t *testing.T) {
	s := &Server{}
	assert.Nil(t, s.validateHTTPPath(nil))
	for _, tc := range []struct {
		path  string
		valid bool
	}{
		{"", true}, {"/api", true}, {"invalid path", false}, {"/" + strings.Repeat("a", 512), false},
	} {
		assert.Equal(t, tc.valid, s.validateHTTPPath(&corev1.Service_Spec_Config_HTTP_Path{AddPrefix: tc.path}) == nil)
		assert.Equal(t, tc.valid, s.validateHTTPPath(&corev1.Service_Spec_Config_HTTP_Path{RemovePrefix: tc.path}) == nil)
	}
}

func TestServiceProtocolValidation(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		path  string
		valid bool
	}{
		{"", true}, {"/mcp", true}, {"/", true}, {"/api/mcp", true},
		{"mcp", false}, {"//mcp", false}, {"/./mcp", false}, {"/../mcp", false},
		{"/mcp/.", false}, {"/mcp/..", false}, {"/mcp?query", false}, {"/mcp#fragment", false},
		{"/mcp\n", false}, {"/mcp\x7f", false}, {"/.well-known/mcp", false},
		{"/" + strings.Repeat("a", maxMCPEndpointPathLen), false},
	} {
		assert.Equal(t, tc.valid, s.validateMCPEndpoint(tc.path) == nil, "%q", tc.path)
	}
	assert.Nil(t, s.validateMCPProtocol(nil))
	assert.Nil(t, s.validateMCPProtocol(&corev1.Service_Spec_Config_MCP_Protocol{Versions: []string{"2025-03-26", "2025-06-18"}}))
	for _, versions := range [][]string{{""}, {"version", "version"}, {"日本語"}, {strings.Repeat("a", 257)}, make([]string, maxMCPProtocolVersions+1)} {
		assert.NotNil(t, s.validateMCPProtocol(&corev1.Service_Spec_Config_MCP_Protocol{Versions: versions}))
	}
	assert.Nil(t, s.validateMCPLimits(nil))
	assert.Nil(t, s.validateMCPLimits(&corev1.Service_Spec_Config_MCP_Limits{MaxRequestBytes: maxMCPRequestBytesLimit, MaxStreamEventBytes: maxMCPStreamEventBytesLimit}))
	assert.NotNil(t, s.validateMCPLimits(&corev1.Service_Spec_Config_MCP_Limits{MaxRequestBytes: maxMCPRequestBytesLimit + 1}))
	assert.NotNil(t, s.validateMCPLimits(&corev1.Service_Spec_Config_MCP_Limits{MaxStreamEventBytes: maxMCPStreamEventBytesLimit + 1}))
}

func TestServiceCORSValidation(t *testing.T) {
	s := &Server{}
	assert.Nil(t, s.validateHTTPCors(nil))
	for _, tc := range []struct {
		origins []string
		valid   bool
	}{
		{nil, true}, {[]string{"*"}, true}, {[]string{"https://example.com", "https://example.com:8443"}, true},
		{[]string{"*", "*"}, false}, {[]string{"https://example.com", "https://example.com"}, false},
		{[]string{""}, false}, {[]string{"example.com"}, false}, {[]string{"https://user:password@example.com"}, false},
		{[]string{"https://example.com/path"}, false}, {[]string{"https://example.com?query"}, false},
		{[]string{"https://example.com#fragment"}, false}, {[]string{"https://%"}, false},
		{[]string{"https://" + strings.Repeat("a", maxCorsOriginLen)}, false}, {make([]string, maxCorsAllowedOrigins+1), false},
	} {
		assert.Equal(t, tc.valid, s.validateHTTPCors(&corev1.Service_Spec_Config_HTTP_CORS{AllowOriginStringMatch: tc.origins}) == nil, "%v", tc.origins)
	}
}

func TestServiceLLMPrompt(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name  string
		value string
		valid bool
	}{
		{"Empty", `{}`, false},
		{"System", `{"system":{"content":{"value":"system instruction"}}}`, true},
		{"MissingContent", `{"system":{}}`, false},
		{"EmptyContent", `{"system":{"content":{"value":""}}}`, false},
		{"ContentType", `{"system":{"content":{}}}`, false},
		{"ContentLength", `{"system":{"content":{"value":"` + strings.Repeat("a", maxPromptContentLen+1) + `"}}}`, false},
		{"ContentCEL", `{"system":{"mode":"APPEND","content":{"eval":"ctx.user.metadata.name"}}}`, true},
		{"InvalidCEL", `{"system":{"content":{"eval":"true"}}}`, false},
		{"ContentOPA", `{"system":{"mode":"REPLACE","content":{"opa":"package octelium.eval\nresult := \"instruction\""}}}`, true},
		{"InvalidOPA", `{"system":{"content":{"opa":"invalid rego"}}}`, false},
		{"Strip", `{"system":{"mode":"STRIP"}}`, true},
		{"StripContent", `{"system":{"mode":"STRIP","content":{"value":"instruction"}}}`, false},
		{"Reject", `{"system":{"mode":"REJECT"}}`, true},
		{"RejectContent", `{"system":{"mode":"REJECT","content":{"value":"denied"}}}`, true},
		{"RejectBadContent", `{"system":{"mode":"REJECT","content":{"eval":"true"}}}`, false},
		{"InvalidSystemMode", `{"system":{"mode":1000,"content":{"value":"instruction"}}}`, false},
		{"Message", `{"message":{"role":"USER","content":{"value":"instruction"}}}`, true},
		{"Assistant", `{"message":{"role":"ASSISTANT","position":"NEW_AFTER","selector":"LAST","content":{"value":"instruction"}}}`, true},
		{"MissingRole", `{"message":{"content":{"value":"instruction"}}}`, false},
		{"InvalidPosition", `{"message":{"role":"USER","position":1000,"content":{"value":"instruction"}}}`, false},
		{"InvalidSelector", `{"message":{"role":"USER","selector":1000,"content":{"value":"instruction"}}}`, false},
		{"AllNewMessage", `{"message":{"role":"USER","selector":"ALL","position":"NEW_BEFORE","content":{"value":"instruction"}}}`, false},
		{"MissingMessageContent", `{"message":{"role":"USER"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &corev1.Service_Spec_Config_LLM_Plugin_Prompt{}
			require.Nil(t, pbutils.UnmarshalJSONStrict([]byte(tc.value), cfg))
			assert.Equal(t, tc.valid, s.validatePluginPrompt(t.Context(), cfg) == nil)
		})
	}
}

func TestServiceLLMTools(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name  string
		value string
		valid bool
	}{
		{"Empty", `{}`, true},
		{"Literal", `{"tools":[{"value":"{\"type\":\"function\"}"}]}`, true},
		{"CEL", `{"tools":[{"eval":"json.marshal({\"type\": \"function\"})"}]}`, true},
		{"OPA", `{"tools":[{"opa":"package octelium.eval\nresult := \"{}\""}]}`, true},
		{"MissingDefinition", `{"tools":[{}]}`, false},
		{"MalformedJSON", `{"tools":[{"value":"{"}]}`, false},
		{"ArrayJSON", `{"tools":[{"value":"[]"}]}`, false},
		{"InvalidCEL", `{"tools":[{"eval":"true"}]}`, false},
		{"InvalidOPA", `{"tools":[{"opa":"invalid rego"}]}`, false},
		{"InvalidPosition", `{"tools":[{"value":"{}","position":1000}]}`, false},
		{"NameFilter", `{"filters":[{"name":"get_*","decision":"ALLOW"}]}`, true},
		{"TypeFilter", `{"filters":[{"type":"function","decision":"REMOVE"}]}`, true},
		{"MissingMatch", `{"filters":[{}]}`, false},
		{"InvalidGlob", `{"filters":[{"name":"invalid\n"}]}`, false},
		{"InvalidTypeGlob", `{"filters":[{"type":"invalid\n"}]}`, false},
		{"InvalidDecision", `{"filters":[{"name":"*","decision":1000}]}`, false},
		{"UnexpectedReplace", `{"filters":[{"name":"*","decision":"DENY","replace":{"value":"{}"}}]}`, false},
		{"MissingReplace", `{"filters":[{"name":"*","decision":"REPLACE"}]}`, false},
		{"Replace", `{"filters":[{"name":"*","decision":"REPLACE","replace":{"value":"{}"}}],"choice":"AUTO"}`, true},
		{"InvalidChoice", `{"choice":1000}`, false},
		{"InvalidMessage", `{"denyMessage":"` + strings.Repeat("a", maxGenStrLen+1) + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &corev1.Service_Spec_Config_LLM_Plugin_Tools{}
			require.Nil(t, pbutils.UnmarshalJSONStrict([]byte(tc.value), cfg))
			assert.Equal(t, tc.valid, s.validatePluginTools(t.Context(), cfg) == nil)
		})
	}
	assert.NotNil(t, s.validatePluginTools(t.Context(), &corev1.Service_Spec_Config_LLM_Plugin_Tools{Filters: make([]*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter, maxToolFilters+1)}))
	assert.NotNil(t, s.validatePluginTools(t.Context(), &corev1.Service_Spec_Config_LLM_Plugin_Tools{Tools: make([]*corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool, maxToolFilters+1)}))
	assert.NotNil(t, validateToolDefinition(t.Context(), &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool{Type: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_Value{Value: strings.Repeat("a", maxToolDefinitionLen+1)}}))
}

func TestServiceLLMGuardrails(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name  string
		value string
		valid bool
	}{
		{"Empty", `{}`, false},
		{"Deny", `{"patterns":[{"regex":"secret","action":"DENY"}]}`, true},
		{"InvalidLeg", `{"leg":1000,"patterns":[{"regex":"secret"}]}`, false},
		{"InvalidScope", `{"scopes":[1000],"patterns":[{"regex":"secret"}]}`, false},
		{"InvalidMessage", `{"denyMessage":"` + strings.Repeat("a", 257) + `","patterns":[{"regex":"secret"}]}`, false},
		{"MissingMatch", `{"patterns":[{}]}`, false},
		{"EmptyRegex", `{"patterns":[{"regex":""}]}`, false},
		{"MalformedRegex", `{"patterns":[{"regex":"["}]}`, false},
		{"LongRegex", `{"patterns":[{"regex":"` + strings.Repeat("a", maxGuardrailRegexLen+1) + `"}]}`, false},
		{"MissingType", `{"patterns":[{"type":"TYPE_UNSET"}]}`, false},
		{"InvalidType", `{"patterns":[{"type":1000}]}`, false},
		{"Secrets", `{"patterns":[{"secrets":{"excludeRules":["test-rule"]}}]}`, true},
		{"InvalidExcludeRule", `{"patterns":[{"secrets":{"excludeRules":[""]}}]}`, false},
		{"InvalidAction", `{"patterns":[{"regex":"secret","action":1000}]}`, false},
		{"UnexpectedReplace", `{"patterns":[{"regex":"secret","action":"DENY","replace":{"value":"safe"}}]}`, false},
		{"Redact", `{"patterns":[{"regex":"secret","action":"REDACT"}]}`, true},
		{"Strip", `{"patterns":[{"regex":"secret","action":"STRIP"}]}`, true},
		{"ResponseRewrite", `{"leg":"RESPONSE","patterns":[{"regex":"secret","action":"REDACT"}]}`, false},
		{"ToolDefinitionRewrite", `{"scopes":["TOOL_DEFINITIONS"],"patterns":[{"regex":"secret","action":"REDACT"}]}`, false},
		{"MissingReplace", `{"patterns":[{"regex":"secret","action":"REPLACE"}]}`, false},
		{"LiteralReplace", `{"patterns":[{"regex":"secret","action":"REPLACE","replace":{"value":""}}]}`, true},
		{"CELReplace", `{"patterns":[{"regex":"secret","action":"REPLACE","replace":{"eval":"ctx.user.metadata.name"}}]}`, true},
		{"InvalidCELReplace", `{"patterns":[{"regex":"secret","action":"REPLACE","replace":{"eval":"true"}}]}`, false},
		{"OPAReplace", `{"patterns":[{"regex":"secret","action":"REPLACE","replace":{"opa":"package octelium.eval\nresult := \"safe\""}}]}`, true},
		{"InvalidOPAReplace", `{"patterns":[{"regex":"secret","action":"REPLACE","replace":{"opa":"invalid rego"}}]}`, false},
		{"EmptyReplace", `{"patterns":[{"regex":"secret","action":"REPLACE","replace":{}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &corev1.Service_Spec_Config_LLM_Plugin_Guardrail{}
			require.Nil(t, pbutils.UnmarshalJSONStrict([]byte(tc.value), cfg))
			assert.Equal(t, tc.valid, s.validatePluginGuardrail(t.Context(), cfg) == nil)
		})
	}
	assert.NotNil(t, s.validatePluginGuardrail(t.Context(), &corev1.Service_Spec_Config_LLM_Plugin_Guardrail{Scopes: make([]corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope, maxGuardrailScopes+1)}))
	assert.NotNil(t, s.validatePluginGuardrail(t.Context(), &corev1.Service_Spec_Config_LLM_Plugin_Guardrail{Patterns: make([]*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern, maxGuardrailPatterns+1)}))
}

func TestServiceMCPAndLLMConfigs(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name  string
		mode  corev1.Service_Spec_Mode
		value string
		valid bool
	}{
		{"MCP", corev1.Service_Spec_MCP, `{"mcp":{}}`, true},
		{"MCPEndpoint", corev1.Service_Spec_MCP, `{"mcp":{"endpoint":"relative"}}`, false},
		{"MCPProtocol", corev1.Service_Spec_MCP, `{"mcp":{"protocol":{"versions":[""]}}}`, false},
		{"MCPLimits", corev1.Service_Spec_MCP, `{"mcp":{"limits":{"maxRequestBytes":16777217}}}`, false},
		{"MCPCORS", corev1.Service_Spec_MCP, `{"mcp":{"cors":{"allowOriginStringMatch":["relative"]}}}`, false},
		{"MCPVisibility", corev1.Service_Spec_MCP, `{"mcp":{"visibility":{"includeRequestHeaders":[""]}}}`, false},
		{"MCPHeader", corev1.Service_Spec_MCP, `{"mcp":{"header":{"addRequestHeaders":[{"key":"Bad Name","value":"value"}]}}}`, false},
		{"MCPAuth", corev1.Service_Spec_MCP, `{"mcp":{"auth":{"basic":{}}}}`, false},
		{"MCPPath", corev1.Service_Spec_MCP, `{"mcp":{"path":{"addPrefix":"invalid path"}}}`, false},
		{"MCPPlugins", corev1.Service_Spec_MCP, `{"mcp":{"plugins":[{"name":"plugin"}]}}`, false},
		{"LLM", corev1.Service_Spec_LLM, `{"llm":{}}`, true},
		{"LLMProtocol", corev1.Service_Spec_LLM, `{"llm":{"protocol":1000}}`, false},
		{"LLMModel", corev1.Service_Spec_LLM, `{"llm":{"model":{"value":""}}}`, false},
		{"LLMReasoning", corev1.Service_Spec_LLM, `{"llm":{"reasoning":{}}}`, false},
		{"LLMLimits", corev1.Service_Spec_LLM, `{"llm":{"limits":{"maxRequestBytes":67108865}}}`, false},
		{"LLMTranslation", corev1.Service_Spec_LLM, `{"llm":{"translation":{"upstreamProtocol":1000}}}`, false},
		{"LLMEmbedding", corev1.Service_Spec_LLM, `{"llm":{"embedding":{"model":"embedding-model"}}}`, false},
		{"LLMVisibility", corev1.Service_Spec_LLM, `{"llm":{"visibility":{"excludeResponseHeaders":[""]}}}`, false},
		{"LLMCORS", corev1.Service_Spec_LLM, `{"llm":{"cors":{"allowOriginStringMatch":["relative"]}}}`, false},
		{"LLMHeader", corev1.Service_Spec_LLM, `{"llm":{"header":{"addRequestHeaders":[{"key":"Bad Name","value":"value"}]}}}`, false},
		{"LLMAuth", corev1.Service_Spec_LLM, `{"llm":{"auth":{"basic":{}}}}`, false},
		{"LLMPath", corev1.Service_Spec_LLM, `{"llm":{"path":{"addPrefix":"invalid path"}}}`, false},
		{"LLMPlugins", corev1.Service_Spec_LLM, `{"llm":{"plugins":[{"name":"plugin"}]}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tstServiceConfig(t, tc.value)
			assert.Equal(t, tc.valid, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: tc.mode}}, false) == nil)
		})
	}
	assert.NotNil(t, s.validateMCPConfig(t.Context(), &corev1.Service_Spec_Config{}))
	assert.NotNil(t, s.validateLLMConfig(t.Context(), &corev1.Service_Spec_Config{}))
}

func TestServiceConfigModes(t *testing.T) {
	s := newTstServer(func(method string, req, resp any) error { return nil })
	for _, tc := range []struct {
		mode  corev1.Service_Spec_Mode
		value string
	}{
		{corev1.Service_Spec_HTTP, `{"http":{}}`},
		{corev1.Service_Spec_KUBERNETES, `{"kubernetes":{"bearerToken":{"fromSecret":"secret"}}}`},
		{corev1.Service_Spec_SOCKS5, `{"socks5":{}}`},
		{corev1.Service_Spec_MCP, `{"mcp":{}}`},
		{corev1.Service_Spec_LLM, `{"llm":{}}`},
		{corev1.Service_Spec_RDP, `{"rdp":{}}`},
		{corev1.Service_Spec_SSH, `{"ssh":{}}`},
		{corev1.Service_Spec_POSTGRES, `{"postgres":{"user":"user","database":"database"}}`},
		{corev1.Service_Spec_MYSQL, `{"mysql":{"user":"user","database":"database"}}`},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			cfg := tstServiceConfig(t, tc.value)
			assert.Nil(t, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: tc.mode}}, false))
			assert.NotNil(t, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP}}, false))
		})
	}
}

func TestServiceVisibilityLimits(t *testing.T) {
	s := &Server{}
	for _, kind := range []string{"http", "mcp", "llm"} {
		for _, field := range []string{"includeRequestHeaders", "includeResponseHeaders", "excludeRequestHeaders", "excludeResponseHeaders"} {
			if kind == "http" && strings.HasPrefix(field, "exclude") {
				continue
			}
			for _, count := range []int{128, 129} {
				cfg := tstServiceConfig(t, `{"`+kind+`":{"visibility":{"`+field+`":[`+strings.Repeat(`"X-Value",`, count-1)+`"X-Value"]}}}`)
				var err error
				switch kind {
				case "http":
					err = s.validateHTTPVisibility(cfg.GetHttp().Visibility)
				case "mcp":
					err = s.validateMCPVisibility(cfg.GetMcp().Visibility)
				case "llm":
					err = s.validateLLMVisibility(cfg.GetLlm().Visibility)
				}
				assert.Equal(t, count == 128, err == nil, "%s.%s: %d", kind, field, count)
			}
		}
	}
	assert.Nil(t, s.validateLLMVisibility(nil))
	assert.NotNil(t, s.validateHTTPVisibility(&corev1.Service_Spec_Config_HTTP_Visibility{IncludeResponseHeaders: []string{""}}))
}

func TestServiceTLSValidation(t *testing.T) {
	s := newTstServer(func(method string, req, resp any) error { return nil })
	for _, value := range []string{
		`{"tls":{"trustedCAs":["not a certificate"]}}`,
		`{"tls":{"clientCertificate":{}}}`,
		`{"clientCertificate":{"fromSecret":"secret","trustedCAs":["not a certificate"]}}`,
		`{"clientCertificate":{}}`,
	} {
		cfg := tstServiceConfig(t, value)
		assert.NotNil(t, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{}}, false))
	}
	for _, value := range []string{
		`{"tls":{"clientCertificate":{"fromSecret":"secret"}}}`,
		`{"clientCertificate":{"fromSecret":"secret"}}`,
	} {
		cfg := tstServiceConfig(t, value)
		assert.Nil(t, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{}}, false))
	}
	for _, value := range []string{
		`{"tls":{"trustedCAs":[` + strings.Repeat(`"certificate",`, 32) + `"certificate"]}}`,
		`{"clientCertificate":{"fromSecret":"secret","trustedCAs":[` + strings.Repeat(`"certificate",`, 32) + `"certificate"]}}`,
	} {
		cfg := tstServiceConfig(t, value)
		assert.NotNil(t, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{}}, false))
	}
}

func TestServiceSpecBoundaries(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Service)
	}{
		{"Spec", func(s *corev1.Service) { s.Spec = nil }},
		{"Mode", func(s *corev1.Service) { s.Spec.Mode = corev1.Service_Spec_MODE_UNSET }},
		{"Port", func(s *corev1.Service) { s.Spec.Port = 65536 }},
		{"ConfigName", func(s *corev1.Service) { s.Spec.Config.Name = "custom" }},
		{"ConfigParent", func(s *corev1.Service) { s.Spec.Config.Parent = "default" }},
		{"EmptyDynamicConfig", func(s *corev1.Service) { s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{} }},
		{"TooManyConfigs", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: make([]*corev1.Service_Spec_Config, 1001)}
			for i := range s.Spec.DynamicConfig.Configs {
				s.Spec.DynamicConfig.Configs[i] = &corev1.Service_Spec_Config{}
			}
		}},
		{"TooManyRules", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: make([]*corev1.Service_Spec_DynamicConfig_Rule, 1001)}
		}},
		{"ReservedConfig", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{{Name: "default"}}}
		}},
		{"InvalidConfigName", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{{Name: "invalid/name"}}}
		}},
		{"DuplicateConfig", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{{Name: "custom"}, {Name: "custom"}}}
		}},
		{"MissingParent", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{{Name: "custom", Parent: "missing"}}}
		}},
		{"SelfParent", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Configs: []*corev1.Service_Spec_Config{{Name: "custom", Parent: "custom"}}}
		}},
		{"MissingCondition", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "default"}}}}
		}},
		{"MissingRuleType", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{Condition: genMatchAnyCondition()}}}
		}},
		{"InvalidCELRule", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{Condition: genMatchAnyCondition(), Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: "("}}}}
		}},
		{"InvalidOPARule", func(s *corev1.Service) {
			s.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{Condition: genMatchAnyCondition(), Type: &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: "invalid rego"}}}}
		}},
		{"NonHTTPPublic", func(s *corev1.Service) { s.Spec.Mode, s.Spec.IsPublic = corev1.Service_Spec_TCP, true }},
		{"MissingConfig", func(s *corev1.Service) { s.Spec.Config = nil }},
		{"PrivateAnonymous", func(s *corev1.Service) { s.Spec.IsAnonymous = true }},
		{"AnonymousAuthorization", func(s *corev1.Service) {
			s.Spec.IsPublic, s.Spec.IsAnonymous, s.Spec.Authorization = true, true, &corev1.Service_Spec_Authorization{}
		}},
		{"NonAnonymousAuthorization", func(s *corev1.Service) {
			s.Spec.Authorization = &corev1.Service_Spec_Authorization{EnableAnonymous: true}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "service.default"}, Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Config: &corev1.Service_Spec_Config{}}, Status: &corev1.Service_Status{}}
			tc.mutate(svc)
			assert.NotNil(t, s.validateService(t.Context(), svc))
		})
	}
}

func TestServiceListReferences(t *testing.T) {
	s := newTstServer(func(method string, req, resp any) error {
		switch method {
		case "GetNamespace":
			resp.(*corev1.Namespace).Metadata = &metav1.Metadata{Name: "namespace", Uid: "namespace-uid"}
		case "GetRegion":
			resp.(*corev1.Region).Metadata = &metav1.Metadata{Name: "region", Uid: "region-uid"}
		case "ListService":
			data := string(pbutils.MarshalMust(req.(*rmetav1.ListOptions)))
			assert.Contains(t, data, "status.namespaceRef.uid")
			assert.Contains(t, data, "namespace-uid")
			assert.Contains(t, data, "status.regionRef.uid")
			assert.Contains(t, data, "region-uid")
		}
		return nil
	})
	_, err := s.ListService(t.Context(), &corev1.ListServiceOptions{NamespaceRef: &metav1.ObjectReference{Name: "namespace"}, RegionRef: &metav1.ObjectReference{Name: "region"}})
	assert.Nil(t, err)
	for _, req := range []*corev1.ListServiceOptions{
		{NamespaceRef: &metav1.ObjectReference{Name: "invalid/name"}},
		{RegionRef: &metav1.ObjectReference{Uid: "invalid"}},
	} {
		_, err := s.ListService(t.Context(), req)
		assert.NotNil(t, err)
	}
	s = newTstServer(func(method string, req, resp any) error { return status.Error(codes.Unavailable, "backend") })
	for _, req := range []*corev1.ListServiceOptions{{NamespaceRef: &metav1.ObjectReference{Name: "namespace"}}, {RegionRef: &metav1.ObjectReference{Name: "region"}}} {
		_, err := s.ListService(t.Context(), req)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	}
}

func TestServiceMetadataDefaults(t *testing.T) {
	s := newTstServer(func(method string, req, resp any) error {
		resp.(*corev1.Region).Metadata = &metav1.Metadata{Name: "default", Uid: "region-uid"}
		return nil
	})
	for _, tc := range []struct {
		mode corev1.Service_Spec_Mode
		port uint32
	}{
		{corev1.Service_Spec_HTTP, 80}, {corev1.Service_Spec_WEB, 80}, {corev1.Service_Spec_MCP, 80}, {corev1.Service_Spec_LLM, 80},
		{corev1.Service_Spec_SSH, 22}, {corev1.Service_Spec_DNS, 53}, {corev1.Service_Spec_POSTGRES, 5432},
		{corev1.Service_Spec_MYSQL, 3306}, {corev1.Service_Spec_SOCKS5, 1080}, {corev1.Service_Spec_RDP, 3389}, {corev1.Service_Spec_RDP_WEB, 8080},
	} {
		svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "service.default"}, Spec: &corev1.Service_Spec{Mode: tc.mode}, Status: &corev1.Service_Status{}}
		require.Nil(t, s.setServiceMetadataStatus(t.Context(), svc))
		assert.Equal(t, tc.port, svc.Status.Port, tc.mode.String())
		assert.Equal(t, "region-uid", svc.Status.RegionRef.Uid)
	}
	for _, tc := range []struct {
		name string
		host string
		alt  []string
	}{
		{"default.default", "", []string{"default.default"}},
		{"service.default", "service", []string{"service.default"}},
		{"default.namespace", "namespace", []string{"default.namespace"}},
		{"service.namespace", "service.namespace", nil},
	} {
		svc := &corev1.Service{Metadata: &metav1.Metadata{Name: tc.name}, Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}, Status: &corev1.Service_Status{NamespaceRef: &metav1.ObjectReference{Name: strings.Split(tc.name, ".")[1]}}}
		require.Nil(t, s.setServiceMetadataStatus(t.Context(), svc))
		assert.Equal(t, tc.host, svc.Status.PrimaryHostname)
		assert.Equal(t, tc.alt, svc.Status.AdditionalHostnames)
	}
}

func TestServiceContainerLimits(t *testing.T) {
	s := newTstServer(func(method string, req, resp any) error { return nil })
	for _, tc := range []struct {
		name  string
		value string
		valid bool
	}{
		{"Arguments", `"args":[` + strings.Repeat(`"arg",`, 64) + `"arg"]`, false},
		{"Command", `"command":[` + strings.Repeat(`"arg",`, 64) + `"arg"]`, false},
		{"Environment", `"env":[` + strings.Repeat(`{"name":"KEY","value":"value"},`, 32) + `{"name":"KEY","value":"value"}]`, false},
		{"SecretEnvironment", `"env":[{"name":"KEY","fromSecret":"secret"}]`, true},
		{"MissingSecretEnvironment", `"env":[{"name":"KEY","fromSecret":""}]`, false},
		{"InvalidK8sSecretName", `"env":[{"name":"KEY","kubernetesSecretRef":{"name":"日本語","key":"key"}}]`, false},
		{"InvalidK8sSecretKey", `"env":[{"name":"KEY","kubernetesSecretRef":{"name":"secret","key":"日本語"}}]`, false},
		{"ExtendedResources", `"resourceLimit":{"ext":{"example.com/gpu":"1"}}`, true},
		{"InvalidResourceKey", `"resourceLimit":{"ext":{"日本語":"1"}}`, false},
		{"InvalidResourceValue", `"resourceLimit":{"ext":{"example.com/gpu":"日本語"}}`, false},
		{"Credentials", `"credentials":{"usernamePassword":{"username":"user","password":{"fromSecret":"secret"},"server":"registry.example.com"}}`, true},
		{"MissingUsername", `"credentials":{"usernamePassword":{"password":{"fromSecret":"secret"}}}`, false},
		{"MissingPassword", `"credentials":{"usernamePassword":{"username":"user"}}`, false},
		{"InvalidRegistry", `"credentials":{"usernamePassword":{"username":"user","password":{"fromSecret":"secret"},"server":"invalid registry"}}`, false},
		{"Volumes", `"volumes":[` + strings.Repeat(`{"name":"data"},`, 32) + `{"name":"data"}]`, false},
		{"Mounts", `"volumeMounts":[` + strings.Repeat(`{"name":"data"},`, 32) + `{"name":"data"}]`, false},
		{"LongProbePath", `"readinessProbe":{"httpGet":{"path":"/` + strings.Repeat("a", 513) + `","port":8080}}`, false},
		{"HTTPProbePort", `"readinessProbe":{"httpGet":{"path":"/ready","port":0}}`, false},
		{"TCPProbePort", `"readinessProbe":{"tcpSocket":{"port":0}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tstServiceConfig(t, `{"upstream":{"container":{"image":"example/image","port":8080,`+tc.value+`}}}`)
			assert.Equal(t, tc.valid, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}, false) == nil)
		})
	}
}

func TestServicePluginByteLimits(t *testing.T) {
	s := &Server{}
	for _, name := range []string{"direct", "jsonSchema", "rateLimit"} {
		for _, size := range []int{35000, 35001} {
			fields := ""
			switch name {
			case "jsonSchema":
				fields = `"inline":"{}",`
			case "rateLimit":
				fields = `"limit":1,"window":{"seconds":1},`
			}
			data := base64.StdEncoding.EncodeToString(make([]byte, size))
			cfg := tstServiceConfig(t, `{"http":{"plugins":[{"name":"plugin","condition":{"matchAny":true},"`+name+`":{`+fields+`"body":{"inlineBytes":"`+data+`"}}}]}}`)
			err := s.validateHTTPPlugins(t.Context(), "default", cfg.GetHttp().Plugins)
			assert.Equal(t, size == 35000, err == nil, "%s: %d", name, size)
		}
	}
}

func TestServiceHTTPConfigBoundaries(t *testing.T) {
	s := &Server{}
	for _, value := range []string{
		`{"body":{"validation":{}}}`,
		`{"body":{"validation":{"jsonSchema":{}}}}`,
		`{"body":{"validation":{"jsonSchema":{"inline":""}}}}`,
		`{"body":{"validation":{"jsonSchema":{"inline":"{"}}}}`,
		`{"body":{"validation":{"jsonSchema":{"inline":"` + strings.Repeat("a", 30001) + `"}}}}`,
		`{"retry":{"maxRetries":101}}`,
		`{"retry":{"initialInterval":{"seconds":0}}}`,
		`{"retry":{"maxInterval":{"seconds":0}}}`,
		`{"retry":{"maxElapsedTime":{"seconds":0}}}`,
		`{"retry":{"statusCodes":[600]}}`,
		`{"retry":{"statusCodes":[` + strings.Repeat("500,", 64) + `500]}}`,
		`{"response":{}}`,
		`{"response":{"direct":{}}}`,
		`{"response":{"direct":{"statusCode":199,"inline":"body"}}}`,
		`{"response":{"direct":{"contentType":"invalid type","inline":"body"}}}`,
		`{"response":{"direct":{"contentType":"` + strings.Repeat("a", 129) + `","inline":"body"}}}`,
	} {
		cfg := tstServiceConfig(t, `{"http":`+value+`}`)
		assert.NotNil(t, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}, false), value)
	}
	cfg := tstServiceConfig(t, `{"http":{"body":{"validation":{"jsonSchema":{"inline":"{\"type\":\"object\"}"}}},"retry":{"maxRetries":100,"initialInterval":{"seconds":1},"statusCodes":[500,502,503]},"response":{"direct":{"inline":"body"}}}}`)
	assert.Nil(t, s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}, false))
}

func TestServiceSecretReferences(t *testing.T) {
	for _, tc := range []struct {
		mode  corev1.Service_Spec_Mode
		value string
	}{
		{corev1.Service_Spec_KUBERNETES, `{"kubernetes":{"clientCertificate":{"fromSecret":"secret"}}}`},
		{corev1.Service_Spec_SOCKS5, `{"socks5":{"auth":{"usernamePassword":{"username":"user","password":{"fromSecret":"secret"}}}}}`},
		{corev1.Service_Spec_SSH, `{"ssh":{"auth":{"password":{"fromSecret":"secret"}}}}`},
		{corev1.Service_Spec_SSH, `{"ssh":{"auth":{"privateKey":{"fromSecret":"secret"}}}}`},
		{corev1.Service_Spec_RDP, `{"rdp":{"auth":{"password":{"fromSecret":"secret"}}}}`},
		{corev1.Service_Spec_POSTGRES, `{"postgres":{"user":"user","database":"database","auth":{"password":{"fromSecret":"secret"}}}}`},
		{corev1.Service_Spec_MYSQL, `{"mysql":{"user":"user","database":"database","auth":{"password":{"fromSecret":"secret"}}}}`},
	} {
		for _, code := range []codes.Code{codes.OK, codes.NotFound} {
			s := newTstServer(func(method string, req, resp any) error { return status.Error(code, "secret lookup") })
			cfg := tstServiceConfig(t, tc.value)
			err := s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: tc.mode}}, false)
			assert.Equal(t, code == codes.OK, err == nil, "%s: %+v", tc.value, err)
		}
	}
}

func TestServiceKubeconfigMetadata(t *testing.T) {
	const kubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: https://kubernetes.example.com:6443
users:
- name: user
  user:
    token: unused-token
contexts:
- name: context
  context:
    cluster: cluster
    user: user
current-context: context
`
	content := kubeconfig
	s := newTstServer(func(method string, req, resp any) error {
		switch method {
		case "GetSecret":
			resp.(*corev1.Secret).Data = &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: content}}
		case "GetRegion":
			resp.(*corev1.Region).Metadata = &metav1.Metadata{Name: "default", Uid: "region-uid"}
		}
		return nil
	})
	cfg := tstServiceConfig(t, `{"kubernetes":{"kubeconfig":{"fromSecret":"secret"}}}`)
	svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "kubernetes.default"}, Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES, Port: 8443, Config: cfg}, Status: &corev1.Service_Status{}}
	require.Nil(t, s.ValidateServiceConfig(t.Context(), cfg, svc, false))
	require.Nil(t, s.setServiceMetadataStatus(t.Context(), svc))
	assert.Equal(t, "https://kubernetes.example.com:6443", svc.Metadata.SpecLabels["k8s-kubeconfig-url-default"])
	for _, data := range []string{"{", "apiVersion: v1", strings.ReplaceAll(kubeconfig, "user: user", "user: missing-user")} {
		content = data
		assert.NotNil(t, s.ValidateServiceConfig(t.Context(), cfg, svc, false))
		assert.NotNil(t, s.setServiceMetadataStatus(t.Context(), svc))
	}
	ca, err := utils_cert.GenerateCARoot()
	require.Nil(t, err)
	caPEM, err := ca.GetCertPEM()
	require.Nil(t, err)
	for _, config := range []*corev1.Service_Spec_Config{
		{Tls: &corev1.Service_Spec_Config_TLS{TrustedCAs: []string{caPEM}}},
		{ClientCertificate: &corev1.Service_Spec_Config_ClientCertificate{TrustedCAs: []string{caPEM}, Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{FromSecret: "secret"}}},
	} {
		assert.Nil(t, s.ValidateServiceConfig(t.Context(), config, &corev1.Service{Spec: &corev1.Service_Spec{}}, false))
	}
}

func TestServiceLLMPluginDispatch(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`"prompt":{"system":{"content":{"value":"instruction"}}}`, true},
		{`"prompt":{}`, false},
		{`"tools":{}`, true},
		{`"tools":{"choice":1000}`, false},
		{`"guardrail":{"patterns":[{"regex":"secret"}]}`, true},
		{`"guardrail":{}`, false},
		{`"model":{"value":"model"}`, true},
		{`"model":{"value":""}`, false},
		{`"reasoning":{"tokenBudget":1}`, true},
		{`"reasoning":{}`, false},
		{`"tokenRateLimit":{"limit":1,"window":{"seconds":1}}`, true},
		{`"tokenRateLimit":{}`, false},
	} {
		cfg := tstServiceConfig(t, `{"llm":{"plugins":[{"name":"plugin","condition":{"matchAny":true},`+tc.value+`}]}}`)
		assert.Equal(t, tc.valid, s.validateLLMPlugins(t.Context(), "default", cfg.GetLlm().Plugins) == nil, tc.value)
	}
	assert.NotNil(t, s.validateLLMPlugins(t.Context(), "default", make([]*corev1.Service_Spec_Config_LLM_Plugin, maxPlugins+1)))
}

func TestServiceEmptyDirValidation(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name  string
		value string
		valid bool
	}{
		{"DefaultLimit", `[{"name":"data","emptyDir":{}}]`, true},
		{"ZeroLimit", `[{"name":"data","emptyDir":{"sizeLimitMegabytes":0}}]`, true},
		{"MinimumLimit", `[{"name":"data","emptyDir":{"sizeLimitMegabytes":1}}]`, true},
		{"SizeLimit", `[{"name":"data","emptyDir":{"sizeLimitMegabytes":64}}]`, true},
		{"MaximumLimit", fmt.Sprintf(`[{"name":"data","emptyDir":{"sizeLimitMegabytes":%d}}]`, uint32(math.MaxUint32)), true},
		{"MixedVolumes", `[{"name":"data","emptyDir":{}},{"name":"cache","emptyDir":{"sizeLimitMegabytes":64}},{"name":"persistent","persistentVolumeClaim":{"name":"claim"}}]`, true},
		{"MissingName", `[{"emptyDir":{}}]`, false},
		{"InvalidName", `[{"name":"invalid/name","emptyDir":{}}]`, false},
		{"MissingType", `[{"name":"data"}]`, false},
		{"MissingPVCName", `[{"name":"data","emptyDir":{}},{"name":"persistent","persistentVolumeClaim":{}}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tstServiceConfig(t, `{"upstream":{"container":{"image":"example/image","port":8080,"volumes":`+tc.value+`,"volumeMounts":[{"name":"data","mountPath":"/data"}]}}}`)
			err := s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}, false)
			if tc.valid {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
	for _, count := range []int{32, 33} {
		t.Run(fmt.Sprintf("Volumes%d", count), func(t *testing.T) {
			cfg := tstServiceConfig(t, `{"upstream":{"container":{"image":"example/image","port":8080}}}`)
			for i := range count {
				cfg.Upstream.GetContainer().Volumes = append(cfg.Upstream.GetContainer().Volumes,
					&corev1.Service_Spec_Config_Upstream_Container_Volume{
						Name: fmt.Sprintf("data-%d", i),
						Type: &corev1.Service_Spec_Config_Upstream_Container_Volume_EmptyDir_{
							EmptyDir: &corev1.Service_Spec_Config_Upstream_Container_Volume_EmptyDir{},
						},
					})
			}
			err := s.ValidateServiceConfig(t.Context(), cfg, &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP}}, false)
			if count == 32 {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			}
		})
	}
}

func TestServiceEmptyDirLifecycle(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s := newFakeServer(tst.C)

	for _, name := range []string{"DefaultConfig", "DynamicConfig"} {
		t.Run(name, func(t *testing.T) {
			cfg := tstServiceConfig(t, `{"upstream":{"container":{"image":"example/image","port":8080,"volumes":[{"name":"data","emptyDir":{}}],"volumeMounts":[{"name":"data","mountPath":"/data"}]}}}`)
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
				Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Config: cfg},
			}
			getConfig := func(svc *corev1.Service) *corev1.Service_Spec_Config {
				if name == "DynamicConfig" {
					return svc.Spec.DynamicConfig.Configs[0]
				}
				return svc.Spec.Config
			}
			if name == "DynamicConfig" {
				cfg.Name = "managed"
				svc.Spec.Config = nil
				svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{cfg},
				}
			}
			want := pbutils.MarshalMust(cfg.Upstream)
			svc, err := s.CreateService(t.Context(), svc)
			require.Nil(t, err)
			assert.Equal(t, want, pbutils.MarshalMust(getConfig(svc).Upstream))
			for _, size := range []uint32{64, 0} {
				getConfig(svc).Upstream.GetContainer().Volumes[0].GetEmptyDir().SizeLimitMegabytes = size
				want := pbutils.MarshalMust(getConfig(svc).Upstream)
				svc, err = s.UpdateService(t.Context(), svc)
				require.Nil(t, err)
				assert.Equal(t, want, pbutils.MarshalMust(getConfig(svc).Upstream))
				svc, err = s.GetService(t.Context(), &metav1.GetOptions{Name: svc.Metadata.Name})
				require.Nil(t, err)
				assert.Equal(t, want, pbutils.MarshalMust(getConfig(svc).Upstream))
			}
		})
	}
}

func TestServiceModeValidation(t *testing.T) {
	s := &Server{}
	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_TCP,
		corev1.Service_Spec_UDP,
		corev1.Service_Spec_HTTP,
		corev1.Service_Spec_SSH,
		corev1.Service_Spec_KUBERNETES,
		corev1.Service_Spec_POSTGRES,
		corev1.Service_Spec_MYSQL,
		corev1.Service_Spec_GRPC,
		corev1.Service_Spec_WEB,
		corev1.Service_Spec_DNS,
		corev1.Service_Spec_SOCKS5,
		corev1.Service_Spec_RDP_WEB,
		corev1.Service_Spec_MCP,
		corev1.Service_Spec_LLM,
		corev1.Service_Spec_RDP,
		corev1.Service_Spec_MODE_UNSET,
		-1, 16, 1000, math.MinInt32, math.MaxInt32,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Name: "service.default"},
				Spec:     &corev1.Service_Spec{Mode: mode, Config: &corev1.Service_Spec_Config{}},
				Status:   &corev1.Service_Status{},
			}
			err := s.validateService(t.Context(), svc)
			if mode >= corev1.Service_Spec_TCP && mode <= corev1.Service_Spec_RDP {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			}
		})
	}
}

func TestServiceInvalidModePersistence(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s := newFakeServer(tst.C)
	svc, err := s.CreateService(t.Context(), &corev1.Service{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec: &corev1.Service_Spec{
			Mode:   corev1.Service_Spec_HTTP,
			Config: tstServiceConfig(t, `{"upstream":{"url":"http://example.com"}}`),
		},
	})
	require.Nil(t, err)
	want := pbutils.MarshalMust(svc.Spec)
	for _, mode := range []corev1.Service_Spec_Mode{corev1.Service_Spec_MODE_UNSET, -1, 16, 1000, math.MinInt32, math.MaxInt32} {
		t.Run(mode.String(), func(t *testing.T) {
			name := utilrand.GetRandomStringCanonical(8)
			_, err := s.CreateService(t.Context(), &corev1.Service{
				Metadata: &metav1.Metadata{Name: name},
				Spec:     &corev1.Service_Spec{Mode: mode, Config: tstServiceConfig(t, `{"upstream":{"url":"http://example.com"}}`)},
			})
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			_, err = s.GetService(t.Context(), &metav1.GetOptions{Name: name})
			assert.Equal(t, codes.NotFound, status.Code(err))

			svc.Spec.Mode = mode
			_, err = s.UpdateService(t.Context(), svc)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			stored, err := s.GetService(t.Context(), &metav1.GetOptions{Uid: svc.Metadata.Uid})
			require.Nil(t, err)
			assert.Equal(t, want, pbutils.MarshalMust(stored.Spec))
		})
	}
}
