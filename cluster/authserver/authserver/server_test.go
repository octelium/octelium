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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func newTestIdentityProvider(t *testing.T, ctx context.Context,
	srv *server, idpType corev1.IdentityProvider_Status_Type) *corev1.IdentityProvider {

	sec, err := srv.octeliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
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

	idp, err := srv.octeliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: "xxx",
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
		Status: &corev1.IdentityProvider_Status{
			Type: idpType,
		},
	})
	assert.Nil(t, err)

	return idp
}

func TestGetWebProviderFromUID(t *testing.T) {

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

	{
		_, err := srv.getWebProviderFromUID(vutils.UUIDv4())
		assert.NotNil(t, err)
	}

	{
		_, err := srv.getWebProviderFromUID("")
		assert.NotNil(t, err)
	}

	idp := newTestIdentityProvider(t, ctx, srv, corev1.IdentityProvider_Status_GITHUB)

	assert.Nil(t, srv.setIdentityProviders(ctx))

	{
		provider, err := srv.getWebProviderFromUID(idp.Metadata.Uid)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, idp.Metadata.Uid, provider.Provider().Metadata.Uid)
	}

	{
		idp, err := srv.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{
			Uid: idp.Metadata.Uid,
		})
		assert.Nil(t, err)

		idp.Spec.IsDisabled = true
		idp, err = srv.octeliumC.CoreC().UpdateIdentityProvider(ctx, idp)
		assert.Nil(t, err)

		assert.Nil(t, srv.setIdentityProviders(ctx))

		_, err = srv.getWebProviderFromUID(idp.Metadata.Uid)
		assert.NotNil(t, err)

		idp.Spec.IsDisabled = false
		_, err = srv.octeliumC.CoreC().UpdateIdentityProvider(ctx, idp)
		assert.Nil(t, err, "%+v", err)

		assert.Nil(t, srv.setIdentityProviders(ctx))
	}

	{
		idp, err := srv.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{
			Uid: idp.Metadata.Uid,
		})
		assert.Nil(t, err)

		idp.Status.IsLocked = true
		idp, err = srv.octeliumC.CoreC().UpdateIdentityProvider(ctx, idp)
		assert.Nil(t, err)

		assert.Nil(t, srv.setIdentityProviders(ctx))

		_, err = srv.getWebProviderFromUID(idp.Metadata.Uid)
		assert.NotNil(t, err)

		idp.Status.IsLocked = false
		_, err = srv.octeliumC.CoreC().UpdateIdentityProvider(ctx, idp)
		assert.Nil(t, err)

		assert.Nil(t, srv.setIdentityProviders(ctx))
	}

	{
		idp, err := srv.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{
			Uid: idp.Metadata.Uid,
		})
		assert.Nil(t, err)

		idp.Status.Type = corev1.IdentityProvider_Status_TYPE_UNKNOWN
		idp, err = srv.octeliumC.CoreC().UpdateIdentityProvider(ctx, idp)
		assert.Nil(t, err)

		assert.Nil(t, srv.setIdentityProviders(ctx))

		_, err = srv.getWebProviderFromUID(idp.Metadata.Uid)
		assert.NotNil(t, err)
	}

	{
		_, err := srv.getAssertionProviderFromName(utilrand.GetRandomStringCanonical(8))
		assert.NotNil(t, err)
	}
}

func TestCheckMaxSessionsPerUser(t *testing.T) {

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
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		assert.Nil(t, srv.checkMaxSessionsPerUser(ctx, usrT.Usr, clusterCfg))
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		usr, err := srv.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid: usrT.Usr.Metadata.Uid,
		})
		assert.Nil(t, err)

		usr.Spec.Session = &corev1.User_Spec_Session{
			MaxPerUser: 1,
		}

		assert.NotNil(t, srv.checkMaxSessionsPerUser(ctx, usr, clusterCfg))

		usr.Spec.Session.MaxPerUser = 1000
		assert.Nil(t, srv.checkMaxSessionsPerUser(ctx, usr, clusterCfg))
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		usr, err := srv.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid: usrT.Usr.Metadata.Uid,
		})
		assert.Nil(t, err)

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{
			Human: &corev1.ClusterConfig_Spec_Session_Human{
				MaxPerUser: 1,
			},
		}

		assert.NotNil(t, srv.checkMaxSessionsPerUser(ctx, usr, cc))

		cc.Spec.Session.Human.MaxPerUser = 500
		assert.Nil(t, srv.checkMaxSessionsPerUser(ctx, usr, cc))
	}
}

func TestGetAuthenticatorAction(t *testing.T) {

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

	idp := newTestIdentityProvider(t, ctx, srv, corev1.IdentityProvider_Status_GITHUB)

	newUser := func() *tstuser.User {
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)
		return usrT
	}

	matchAnyRule := func(effect corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_Effect) *corev1.ClusterConfig_Spec_Authenticator_EnforcementRule {
		return &corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_MatchAny{
					MatchAny: true,
				},
			},
			Effect: effect,
		}
	}

	{
		usrT := newUser()

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		cc.Spec.Authenticator = nil

		ret, err := srv.getAuthenticatorAction(ctx, cc, idp, usrT.Usr, usrT.Session)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, ret)
	}

	{
		usrT := newUser()

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{}

		ret, err := srv.getAuthenticatorAction(ctx, cc, idp, usrT.Usr, usrT.Session)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, ret)
	}

	{
		usrT := newUser()

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			RegistrationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				matchAnyRule(corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE),
			},
		}

		ret, err := srv.getAuthenticatorAction(ctx, cc, idp, usrT.Usr, usrT.Session)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Session_Status_REGISTRATION_REQUIRED, ret)
	}

	{
		usrT := newUser()

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			RegistrationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				matchAnyRule(corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_RECOMMEND),
			},
		}

		ret, err := srv.getAuthenticatorAction(ctx, cc, idp, usrT.Usr, usrT.Session)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Session_Status_REGISTRATION_RECOMMENDED, ret)
	}

	{
		usrT := newUser()

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			RegistrationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				matchAnyRule(corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_IGNORE),
			},
		}

		ret, err := srv.getAuthenticatorAction(ctx, cc, idp, usrT.Usr, usrT.Session)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, ret)
	}

	{
		usrT := newUser()

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			RegistrationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `ctx.user.metadata.name == "does-not-exist"`,
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
				},
			},
		}

		ret, err := srv.getAuthenticatorAction(ctx, cc, idp, usrT.Usr, usrT.Session)
		assert.Nil(t, err)
		assert.Equal(t, corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, ret)
	}
}
