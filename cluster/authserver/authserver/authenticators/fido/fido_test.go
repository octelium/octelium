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

package fido

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestBegin(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(tst.C.OcteliumC)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	/*
		fctr, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
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
	*/

	authn, err := tst.C.OcteliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{},
		Status: &corev1.Authenticator_Status{
			// IdentityProviderRef: umetav1.GetObjectReference(fctr),
			UserRef:               umetav1.GetObjectReference(usr.Usr),
			AuthenticationAttempt: &corev1.Authenticator_Status_AuthenticationAttempt{},
		},
	})
	assert.Nil(t, err)

	t.Run("valid", func(t *testing.T) {

		cc := &corev1.ClusterConfig{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.ClusterConfig_Spec{},
			Status: &corev1.ClusterConfig_Status{
				Domain: "octeliumdomain.xyz",
			},
		}

		webauthnctl, err := NewFactor(ctx, &authenticators.Opts{
			OcteliumC:     tst.C.OcteliumC,
			ClusterConfig: cc,
			Authenticator: authn,
			User:          usr.Usr,
		}, nil)
		assert.Nil(t, err)

		resp, err := webauthnctl.BeginRegistration(context.Background(), &authenticators.BeginRegistrationReq{
			Req: &authv1.RegisterAuthenticatorBeginRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, resp.Response.ChallengeRequest.GetFido())
	})
}

/*
func TestFinish(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	t.Run("valid", func(t *testing.T) {

		reqBody := `
{"id":"pNeE0iBONTcZ9gyjyO5q62PYen3Jq0i8q2PdH6HAqxJDmULaArxpumQ1AEMQAxRnYcCGvY9HhS_lGMQzFUUGeOgoSIUvSRjZzmRHX3YnzbOvrH-QDpzgAMilejPCFYIMEtWo_lZYPHlRM7LsM2S2IUULaL5DqOJ8R5E-E8qnfA5l7AsVoJnpoocxuRVHV_jX3FjCrykA_o2pfx1tG-xderd43sgTTDu8i1b4ZTUzB8lxEFOe71MJE268gBeQ6C-MCpTdp5QzVoaCUuDhMxdCrSt781mPOEnynONXOAIhEEpYhvtRjrckPjElAtSMIC739SgUeMcHDZ-PqdL-V7fC","rawId":"pNeE0iBONTcZ9gyjyO5q62PYen3Jq0i8q2PdH6HAqxJDmULaArxpumQ1AEMQAxRnYcCGvY9HhS_lGMQzFUUGeOgoSIUvSRjZzmRHX3YnzbOvrH-QDpzgAMilejPCFYIMEtWo_lZYPHlRM7LsM2S2IUULaL5DqOJ8R5E-E8qnfA5l7AsVoJnpoocxuRVHV_jX3FjCrykA_o2pfx1tG-xderd43sgTTDu8i1b4ZTUzB8lxEFOe71MJE268gBeQ6C-MCpTdp5QzVoaCUuDhMxdCrSt781mPOEnynONXOAIhEEpYhvtRjrckPjElAtSMIC739SgUeMcHDZ-PqdL-V7fC","type":"public-key","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBg2YuYlDbcmjIlP1Rxpu4VkPFHd37oT5SOlbW7AXfjCRaQQAAAAAAAAAAAAAAAAAAAAAAAAAAAP-k14TSIE41Nxn2DKPI7mrrY9h6fcmrSLyrY90focCrEkOZQtoCvGm6ZDUAQxADFGdhwIa9j0eFL-UYxDMVRQZ46ChIhS9JGNnOZEdfdifNs6-sf5AOnOAAyKV6M8IVggwS1aj-Vlg8eVEzsuwzZLYhRQtovkOo4nxHkT4Tyqd8DmXsCxWgmemihzG5FUdX-NfcWMKvKQD-jal_HW0b7F16t3jeyBNMO7yLVvhlNTMHyXEQU57vUwkTbryAF5DoL4wKlN2nlDNWhoJS4OEzF0KtK3vzWY84SfKc41c4AiEQSliG-1GOtyQ-MSUC1IwgLvf1KBR4xwcNn4-p0v5Xt8KlAQIDJiABIVgg4wa4h47Wtuu1LvGhOQVA2mABhppPubzZk8_6Srqg7CkiWCAYJPqb1zdsMpjZnkElWWLZpiqKXXL-q-3jmrwfKoS31Q","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTlhSak5FUTVXRzE2ZFVWRk5YTmhXbTlPTjBwMk1tcE9aVEp4Y2tjMFUxTldaM0ZJVEZoMlUzSlhZejAiLCJvcmlnaW4iOiJodHRwczovL3ZlcGVuZG9tYWluLnh5eiIsImNyb3NzT3JpZ2luIjpmYWxzZX0"}}
		`








		fctr := &corev1.IdentityProvider{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(7),
			},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Webauthn_{
					Webauthn: &corev1.IdentityProvider_Spec_Webauthn{},
				},
			},
		}

		cc := &corev1.ClusterConfig{
			Metadata: &metav1.Metadata{
				Domain: "octeliumdomain.xyz",
			},
			Spec: &corev1.ClusterConfig_Spec{
				Identity: &corev1.ClusterConfig_Spec_Authentication{},
			},
		}

		webauthnctl, err := NewFactor(cc, fctr)
		assert.Nil(t, err)

		 err = webauthnctl.Finish(context.Background(), &corev1.User{
			Metadata: &metav1.Metadata{
				Uid:  "e01d2308-3ef1-42e7-aa28-7c9e87f651a6",
				Name: "usr1",
			},
		},
			&corev1.Device{
				Metadata: &metav1.Metadata{
					Uid: "96dc880d-984a-4d02-a05b-d000e6bc0594",
				},
			}, nil, fctr)
		assert.Nil(t, err)


		zap.S().Debugf("RESP: %+v", resp)
	})
}

*/
