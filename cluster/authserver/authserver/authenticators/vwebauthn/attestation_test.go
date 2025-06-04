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
