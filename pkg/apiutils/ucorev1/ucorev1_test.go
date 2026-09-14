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

package ucorev1

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
)

func TestServiceAddresses(t *testing.T) {

	{
		svc := ToService(nil)
		assert.Nil(t, svc.Addresses())
		assert.Nil(t, svc.AddressesV4())
		assert.Nil(t, svc.AddressesV6())
		assert.False(t, svc.HasAddresses())
	}

	{
		svc := ToService(&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
		})
		assert.Nil(t, svc.Addresses())
		assert.Nil(t, svc.AddressesV4())
		assert.Nil(t, svc.AddressesV6())
		assert.False(t, svc.HasAddresses())
	}

	{
		svc := ToService(&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec:   &corev1.Service_Spec{},
			Status: &corev1.Service_Status{},
		})
		assert.Nil(t, svc.Addresses())
		assert.Nil(t, svc.AddressesV4())
		assert.Nil(t, svc.AddressesV6())
		assert.False(t, svc.HasAddresses())
	}

	{
		svc := ToService(&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				Addresses: []*corev1.Service_Status_Address{},
			},
		})
		assert.Nil(t, svc.Addresses())
		assert.False(t, svc.HasAddresses())
	}

	{
		svc := ToService(&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				Addresses: []*corev1.Service_Status_Address{
					nil,
					{},
					{
						DualStackIP: &metav1.DualStackIP{},
					},
				},
			},
		})
		assert.Nil(t, svc.Addresses())
		assert.Nil(t, svc.AddressesV4())
		assert.Nil(t, svc.AddressesV6())
		assert.False(t, svc.HasAddresses())
	}

	{
		svc := ToService(&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				Addresses: []*corev1.Service_Status_Address{
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv4: "1.2.3.4",
							Ipv6: "::1",
						},
					},
					nil,
					{
						DualStackIP: nil,
					},
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv4: "1.2.3.5",
						},
					},
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv6: "::2",
						},
					},
				},
			},
		})

		assert.Equal(t, 3, len(svc.Addresses()))
		assert.True(t, svc.HasAddresses())
		assert.Equal(t, []string{"1.2.3.4", "1.2.3.5"}, svc.AddressesV4())
		assert.Equal(t, []string{"::1", "::2"}, svc.AddressesV6())
	}

	{
		svc := ToService(&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				Addresses: []*corev1.Service_Status_Address{
					{
						DualStackIP: &metav1.DualStackIP{
							Ipv4: "1.2.3.4",
						},
					},
				},
			},
		})

		assert.True(t, svc.HasAddresses())
		assert.Equal(t, []string{"1.2.3.4"}, svc.AddressesV4())
		assert.Nil(t, svc.AddressesV6())
	}
}

func TestSecretValues(t *testing.T) {

	{
		sec := ToSecret(nil)

		assert.Equal(t, "", sec.GetSpecValueStr())
		assert.Equal(t, "", sec.GetValueStr())
		assert.Empty(t, sec.GetSpecValueBytes())
		assert.Empty(t, sec.GetValueBytes())

		_, _, err := sec.GetCertificateChainAndKey()
		assert.NotNil(t, err)
	}

	{
		sec := ToSecret(&corev1.Secret{})

		assert.Equal(t, "", sec.GetSpecValueStr())
		assert.Equal(t, "", sec.GetValueStr())

		_, _, err := sec.GetCertificateChainAndKey()
		assert.NotNil(t, err)
	}

	{
		sec := ToSecret(&corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: "crt-ns-default",
			},
			Spec: &corev1.Secret_Spec{},
		})

		assert.Equal(t, "", sec.GetSpecValueStr())
		assert.Equal(t, "", sec.GetValueStr())

		_, _, err := sec.GetCertificateChainAndKey()
		assert.NotNil(t, err)
	}

	{
		sec := ToSecret(&corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: "sec1",
			},
			Spec: &corev1.Secret_Spec{
				Data: &corev1.Secret_Spec_Data{
					Type: &corev1.Secret_Spec_Data_Value{
						Value: "spec-value",
					},
				},
			},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_ValueBytes{
					ValueBytes: []byte("data-value"),
				},
			},
		})

		assert.Equal(t, "spec-value", sec.GetSpecValueStr())
		assert.Equal(t, "data-value", sec.GetValueStr())

		chain, key, err := sec.GetCertificateChainAndKey()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []byte("spec-value"), chain)
		assert.Equal(t, []byte("data-value"), key)
	}
}
