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

package authserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

/*
func TestParseAuthenticationToken(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	invalidVals := []string{
		"",
		".",
		"..",
		"...",
		"....",
		"aa.aa.aa.aa",
		"a.b",
		"a.b.c",
		utilrand.GetRandomString(2),
		utilrand.GetRandomString(1000),
		string(utilrand.GetRandomBytesMust(40)),
		fmt.Sprintf("%s.%s.%s", utilrand.GetRandomStringLowercase(10), utilrand.GetRandomStringLowercase(32), utilrand.GetRandomStringLowercase(10)),
	}

	for _, v := range invalidVals {
		_, _, err := srv.parseAuthenticationToken(v)
		assert.NotNil(t, err)
	}

	{

		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		claims, err := srv.jwkCtl.VerifyCredential(tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.Nil(t, err)
		tkn, err := adminSrv.GetCredential(ctx, &metav1.GetOptions{Uid: claims.UID})
		assert.Nil(t, err)
		assert.Equal(t, claims.TokenID, tkn.Status.TokenID)
	}
}
*/

func TestGetAuthenticationToken(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		_, err := srv.getCredentialFromToken(ctx, "")
		assert.NotNil(t, err)
	}

	{

		_, err := srv.getCredentialFromToken(ctx, fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(10), utilrand.GetRandomString(200)))
		assert.NotNil(t, err)
	}

	{

		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		_, err = srv.getCredentialFromToken(ctx, tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.Nil(t, err)

	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		cred, err = srv.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{
			Uid: cred.Metadata.Uid,
		})
		assert.Nil(t, err)

		cred.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(-1 * time.Hour))
		_, err = tst.C.OcteliumC.CoreC().UpdateCredential(ctx, cred)
		assert.Nil(t, err)

		_, err = srv.getCredentialFromToken(ctx, tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.NotNil(t, err)
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		cred, err = srv.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{
			Uid: cred.Metadata.Uid,
		})
		assert.Nil(t, err)
		cred.Status.TokenID = vutils.UUIDv4()
		_, err = tst.C.OcteliumC.CoreC().UpdateCredential(ctx, cred)
		assert.Nil(t, err)

		_, err = srv.getCredentialFromToken(ctx, tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.NotNil(t, err)
	}

	{

		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		cred, err = srv.getCredentialFromToken(ctx, tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.Nil(t, err)

		cred.Spec.MaxAuthentications = 3
		cred.Status.TotalAuthentications = 3

		cred, err = srv.octeliumC.CoreC().UpdateCredential(ctx, cred)
		assert.Nil(t, err)

		_, err = srv.getCredentialFromToken(ctx, tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.NotNil(t, err)

		cred.Spec.MaxAuthentications = 3
		cred.Status.TotalAuthentications = 4

		cred, err = srv.octeliumC.CoreC().UpdateCredential(ctx, cred)
		assert.Nil(t, err)

		_, err = srv.getCredentialFromToken(ctx, tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.NotNil(t, err)

		cred.Spec.MaxAuthentications = 3
		cred.Status.TotalAuthentications = 2

		cred, err = srv.octeliumC.CoreC().UpdateCredential(ctx, cred)
		assert.Nil(t, err)

		_, err = srv.getCredentialFromToken(ctx, tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.Nil(t, err)
	}
}

func TestNeedsReAuth(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	accessTokenDuration := func(hours int64) *metav1.Duration {
		return &metav1.Duration{
			Type: &metav1.Duration_Hours{
				Hours: uint32(hours),
			},
		}
	}

	assert.True(t, srv.needsReAuth(nil))

	assert.True(t, srv.needsReAuth(&corev1.Session{}))

	assert.True(t, srv.needsReAuth(&corev1.Session{
		Status: &corev1.Session_Status{},
	}))

	assert.True(t, srv.needsReAuth(&corev1.Session{
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{},
		},
	}))

	assert.True(t, srv.needsReAuth(&corev1.Session{
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{
				SetAt: pbutils.Now(),
			},
		},
	}))

	assert.True(t, srv.needsReAuth(&corev1.Session{
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{
				AccessTokenDuration: accessTokenDuration(2),
			},
		},
	}))

	assert.False(t, srv.needsReAuth(&corev1.Session{
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{
				SetAt:               pbutils.Now(),
				AccessTokenDuration: accessTokenDuration(2),
			},
		},
	}))

	assert.False(t, srv.needsReAuth(&corev1.Session{
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{
				SetAt:               pbutils.Timestamp(time.Now().Add(-20 * time.Minute)),
				AccessTokenDuration: accessTokenDuration(2),
			},
		},
	}))

	assert.True(t, srv.needsReAuth(&corev1.Session{
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{
				SetAt:               pbutils.Timestamp(time.Now().Add(-90 * time.Minute)),
				AccessTokenDuration: accessTokenDuration(2),
			},
		},
	}))

	assert.True(t, srv.needsReAuth(&corev1.Session{
		Status: &corev1.Session_Status{
			Authentication: &corev1.Session_Status_Authentication{
				SetAt:               pbutils.Timestamp(time.Now().Add(-3 * time.Hour)),
				AccessTokenDuration: accessTokenDuration(2),
			},
		},
	}))
}

func TestCheckReauthRateLimit(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	assert.Nil(t, srv.checkReauthRateLimit(&corev1.Session{
		Status: &corev1.Session_Status{},
	}))

	lastAuthentications := []*corev1.Session_Status_Authentication{}
	for i := 0; i < maxAuthenticationsPerHour*2; i++ {

		err := srv.checkReauthRateLimit(&corev1.Session{
			Status: &corev1.Session_Status{
				LastAuthentications: lastAuthentications,
			},
		})

		if i < maxAuthenticationsPerHour {
			assert.Nil(t, err, "%d", i)
		} else {
			assert.NotNil(t, err, "%d", i)
		}

		lastAuthentications = append(lastAuthentications, &corev1.Session_Status_Authentication{
			SetAt: pbutils.Timestamp(time.Now().Add(time.Duration(-i) * time.Second)),
		})
	}

	oldAuthentications := []*corev1.Session_Status_Authentication{}
	for i := 0; i < maxAuthenticationsPerHour*2; i++ {
		oldAuthentications = append(oldAuthentications, &corev1.Session_Status_Authentication{
			SetAt: pbutils.Timestamp(time.Now().Add(-2 * time.Hour)),
		})
	}
	assert.Nil(t, srv.checkReauthRateLimit(&corev1.Session{
		Status: &corev1.Session_Status{
			LastAuthentications: oldAuthentications,
		},
	}))

	skewedAuthentications := []*corev1.Session_Status_Authentication{
		nil,
		{},
		{SetAt: pbutils.Timestamp(time.Now().Add(-2 * time.Hour))},
	}
	for i := 0; i < maxAuthenticationsPerHour; i++ {
		skewedAuthentications = append(skewedAuthentications, &corev1.Session_Status_Authentication{
			SetAt: pbutils.Timestamp(time.Now().Add(time.Duration(-i) * time.Second)),
		})
	}
	assert.NotNil(t, srv.checkReauthRateLimit(&corev1.Session{
		Status: &corev1.Session_Status{
			LastAuthentications: skewedAuthentications,
		},
	}))
}
