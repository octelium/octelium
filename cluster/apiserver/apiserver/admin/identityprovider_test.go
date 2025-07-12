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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestIdentityProvider(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	sec, err := srv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		},
	})
	assert.Nil(t, err)

	invalids := []*corev1.IdentityProvider{
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec:     &corev1.IdentityProvider_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Github_{
					Github: &corev1.IdentityProvider_Spec_Github{},
				},
			},
		},

		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Github_{
					Github: &corev1.IdentityProvider_Spec_Github{
						ClientID: utilrand.GetRandomStringCanonical(8),
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Github_{
					Github: &corev1.IdentityProvider_Spec_Github{
						ClientID: utilrand.GetRandomStringCanonical(8),
						ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
							Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{},
						},
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Github_{
					Github: &corev1.IdentityProvider_Spec_Github{
						ClientID: utilrand.GetRandomStringCanonical(8),
						ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
							Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
								FromSecret: utilrand.GetRandomStringCanonical(8),
							},
						},
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Oidc{
					Oidc: &corev1.IdentityProvider_Spec_OIDC{},
				},
			},
		},

		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Oidc{
					Oidc: &corev1.IdentityProvider_Spec_OIDC{
						ClientID: utilrand.GetRandomStringCanonical(32),
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Oidc{
					Oidc: &corev1.IdentityProvider_Spec_OIDC{
						ClientID: utilrand.GetRandomStringCanonical(32),
						ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
							Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
								FromSecret: sec.Metadata.Name,
							},
						},
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Saml{
					Saml: &corev1.IdentityProvider_Spec_SAML{},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Saml{
					Saml: &corev1.IdentityProvider_Spec_SAML{
						EntityID: utilrand.GetRandomStringCanonical(8),
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
					OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{},
				},
			},
		},
	}

	for _, invalid := range invalids {
		_, err = srv.CreateIdentityProvider(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	valids := []*corev1.IdentityProvider{

		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Github_{
					Github: &corev1.IdentityProvider_Spec_Github{
						ClientID: utilrand.GetRandomString(32),
						ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
							Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
								FromSecret: sec.Metadata.Name,
							},
						},
					},
				},
			},
		},

		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Oidc{
					Oidc: &corev1.IdentityProvider_Spec_OIDC{
						ClientID:  utilrand.GetRandomString(32),
						IssuerURL: "https://example.com",
						ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
							Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
								FromSecret: sec.Metadata.Name,
							},
						},
					},
				},
			},
		},

		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Saml{
					Saml: &corev1.IdentityProvider_Spec_SAML{
						MetadataType: &corev1.IdentityProvider_Spec_SAML_MetadataURL{
							MetadataURL: "https://example.com/metadata",
						},
					},
				},
			},
		},
	}

	for _, valid := range valids {
		_, err = srv.CreateIdentityProvider(ctx, valid)
		assert.Nil(t, err)
	}

}
