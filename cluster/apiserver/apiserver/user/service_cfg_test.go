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

package user

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestSetServiceConfigs(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usr, err := tstuser.NewUser(usrSrv.octeliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: "topsecret",
			},
		},
	})
	assert.Nil(t, err)

	svcReq := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_KUBERNETES,

			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com:6443",
					},
				},

				Type: &corev1.Service_Spec_Config_Kubernetes_{
					Kubernetes: &corev1.Service_Spec_Config_Kubernetes{
						Type: &corev1.Service_Spec_Config_Kubernetes_BearerToken_{
							BearerToken: &corev1.Service_Spec_Config_Kubernetes_BearerToken{
								Type: &corev1.Service_Spec_Config_Kubernetes_BearerToken_FromSecret{
									FromSecret: sec.Metadata.Name,
								},
							},
						},
					},
				},
			},
		},
	}
	svc, err := adminSrv.CreateService(ctx, svcReq)
	assert.Nil(t, err)

	assert.True(t, pbutils.IsEqual(svc.Spec, svcReq.Spec))

	_, err = usrSrv.SetServiceConfigs(usr.Ctx(), &userv1.SetServiceConfigsRequest{
		Name: svc.Metadata.Name,
	})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err))

	err = usr.Connect()
	assert.Nil(t, err)

	_, err = usrSrv.SetServiceConfigs(usr.Ctx(), &userv1.SetServiceConfigsRequest{
		Name: svc.Metadata.Name,
	})
	assert.Nil(t, err)
}

func TestGetServiceConfigHostPort(t *testing.T) {

	cc := &corev1.ClusterConfig{
		Status: &corev1.ClusterConfig_Status{
			Domain: "example.com",
		},
	}

	newSvc := func(addrs []*corev1.Service_Status_Address) *corev1.Service {
		return &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				PrimaryHostname: "svc1",
				Port:            8080,
				NamespaceRef: &metav1.ObjectReference{
					Name: "default",
				},
				Addresses: addrs,
			},
		}
	}

	newSess := func(l3Mode corev1.Session_Status_Connection_L3Mode) *corev1.Session {
		return &corev1.Session{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Session_Spec{},
			Status: &corev1.Session_Status{
				Connection: &corev1.Session_Status_Connection{
					IgnoreDNS: true,
					L3Mode:    l3Mode,
				},
			},
		}
	}

	dualStack := []*corev1.Service_Status_Address{
		{
			DualStackIP: &metav1.DualStackIP{
				Ipv4: "1.2.3.4",
				Ipv6: "::1",
			},
		},
	}

	{
		host, port := getServiceConfigHostPort(newSvc(dualStack),
			newSess(corev1.Session_Status_Connection_BOTH), cc)
		assert.Equal(t, "::1", host)
		assert.Equal(t, 8080, port)
	}

	{
		host, port := getServiceConfigHostPort(newSvc(dualStack),
			newSess(corev1.Session_Status_Connection_V4), cc)
		assert.Equal(t, "1.2.3.4", host)
		assert.Equal(t, 8080, port)
	}

	{
		host, port := getServiceConfigHostPort(newSvc(nil),
			newSess(corev1.Session_Status_Connection_BOTH), cc)
		assert.Equal(t, "svc1.local.example.com", host)
		assert.Equal(t, 8080, port)
	}

	{
		host, _ := getServiceConfigHostPort(newSvc([]*corev1.Service_Status_Address{}),
			newSess(corev1.Session_Status_Connection_V4), cc)
		assert.Equal(t, "svc1.local.example.com", host)
	}

	{
		host, _ := getServiceConfigHostPort(newSvc([]*corev1.Service_Status_Address{
			nil,
			{},
			{
				DualStackIP: &metav1.DualStackIP{},
			},
		}), newSess(corev1.Session_Status_Connection_BOTH), cc)
		assert.Equal(t, "svc1.local.example.com", host)
	}

	{
		host, _ := getServiceConfigHostPort(newSvc([]*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.4",
				},
			},
		}), newSess(corev1.Session_Status_Connection_V6), cc)
		assert.Equal(t, "svc1.local.example.com", host)
	}

	{
		host, _ := getServiceConfigHostPort(newSvc([]*corev1.Service_Status_Address{
			{
				DualStackIP: nil,
			},
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv6: "::2",
				},
			},
		}), newSess(corev1.Session_Status_Connection_V6), cc)
		assert.Equal(t, "::2", host)
	}

	{
		sess := newSess(corev1.Session_Status_Connection_BOTH)
		sess.Status.Connection.IgnoreDNS = false

		host, _ := getServiceConfigHostPort(newSvc(dualStack), sess, cc)
		assert.Equal(t, "svc1.local.example.com", host)
	}
}
