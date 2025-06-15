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

package vwebauthn

/*
func TestAttestation(t *testing.T) {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	octeliumC := tst.C.OcteliumC

	ctx := context.Background()

	t.Run("cert", func(t *testing.T) {
		cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		fctr, err := octeliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(7),
			},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Webauthn_{
					Webauthn: &corev1.IdentityProvider_Spec_Webauthn{},
				},
			},
		})
		assert.Nil(t, err)

		cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{}

		webauthnctl, err := NewFactor(tst.C.OcteliumC, cc, fctr)
		assert.Nil(t, err)

		rootCA, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		{
			err := webauthnctl.doVerifyAttestation([]*x509.Certificate{
				rootCA.Certificate,
			}, fctr)

			assert.Nil(t, err)
		}

		{

			rootPEM, err := rootCA.GetCertPEM()
			assert.Nil(t, err)

			cert, err := utils_cert.GenerateCertificateTmp(utilrand.GetRandomStringLowercase(10), rootCA, false)
			assert.Nil(t, err)
			certPEM, err := cert.GetCertPEM()
			assert.Nil(t, err)
			certD, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(certPEM))
			assert.Nil(t, err)

			fctr.Spec.GetWebauthn().AllowedAttestationCAs = []string{
				rootPEM,
			}

			err = webauthnctl.doVerifyAttestation([]*x509.Certificate{
				certD,
			}, fctr)

			assert.Nil(t, err)
		}

		{

			cert, err := utils_cert.GenerateCertificateTmp(utilrand.GetRandomStringLowercase(10), rootCA, false)
			assert.Nil(t, err)
			certPEM, err := cert.GetCertPEM()
			assert.Nil(t, err)
			certD, err := utils_cert.ParseX509LeafCertificateChainPEM([]byte(certPEM))
			assert.Nil(t, err)

			root2, err := utils_cert.GenerateCARoot()
			assert.Nil(t, err)
			root2PEM, err := root2.GetCertPEM()
			assert.Nil(t, err)

			fctr.Spec.GetWebauthn().AllowedAttestationCAs = []string{
				root2PEM,
			}

			err = webauthnctl.doVerifyAttestation([]*x509.Certificate{
				certD,
			}, fctr)

			assert.NotNil(t, err)
		}
	})
}
*/
