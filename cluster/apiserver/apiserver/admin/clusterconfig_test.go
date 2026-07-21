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
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func getTestClusterConfig(ctx context.Context, t *testing.T, srv *Server) *corev1.ClusterConfig {
	cc, err := srv.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
	assert.Nil(t, err, "%+v", err)
	cc.Status = nil
	return cc
}

func getTestCondition() *corev1.Condition {
	return &corev1.Condition{
		Type: &corev1.Condition_MatchAny{
			MatchAny: true,
		},
	}
}

func TestClusterConfig(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv := NewServer(&Opts{
		OcteliumC: tst.C.OcteliumC,
	})

	cc, err := srv.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
	assert.Nil(t, err)

	assert.Nil(t, cc.Spec.Device)

	cc.Status = nil

	maxPerUser := uint32(utilrand.GetRandomRangeMath(1, 100))
	cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
		Human: &corev1.ClusterConfig_Spec_Device_Human{
			MaxPerUser:   maxPerUser,
			DefaultState: corev1.Device_Spec_PENDING,
		},
		Workload: &corev1.ClusterConfig_Spec_Device_Workload{
			MaxPerUser:   maxPerUser,
			DefaultState: corev1.Device_Spec_ACTIVE,
		},
	}

	cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{
		Human: &corev1.ClusterConfig_Spec_Session_Human{
			ClientDuration: &metav1.Duration{
				Type: &metav1.Duration_Hours{Hours: 8},
			},
			ClientlessDuration: &metav1.Duration{
				Type: &metav1.Duration_Hours{Hours: 4},
			},
			AccessTokenDuration: &metav1.Duration{
				Type: &metav1.Duration_Minutes{Minutes: 30},
			},
			RefreshTokenDuration: &metav1.Duration{
				Type: &metav1.Duration_Hours{Hours: 12},
			},
			MaxPerUser:   maxPerUser,
			DefaultState: corev1.Session_Spec_ACTIVE,
		},
		Workload: &corev1.ClusterConfig_Spec_Session_Workload{
			ClientDuration: &metav1.Duration{
				Type: &metav1.Duration_Hours{Hours: 8},
			},
			ClientlessDuration: &metav1.Duration{
				Type: &metav1.Duration_Hours{Hours: 4},
			},
			AccessTokenDuration: &metav1.Duration{
				Type: &metav1.Duration_Minutes{Minutes: 30},
			},
			RefreshTokenDuration: &metav1.Duration{
				Type: &metav1.Duration_Hours{Hours: 12},
			},
			MaxPerUser:   maxPerUser,
			DefaultState: corev1.Session_Spec_PENDING,
		},
	}

	cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{
		UseForwardedForHeader: true,
		XffNumTrustedHops:     2,
	}

	cc.Spec.Gateway = &corev1.ClusterConfig_Spec_Gateway{
		WireguardKeyRotationDuration: &metav1.Duration{
			Type: &metav1.Duration_Hours{Hours: 24},
		},
	}

	cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
		FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
			Servers: []string{"8.8.8.8", "dns.example.com"},
			CacheDuration: &metav1.Duration{
				Type: &metav1.Duration_Minutes{Minutes: 5},
			},
		},
	}

	cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
		EnablePasskeyLogin: true,
		DefaultState:       corev1.Authenticator_Spec_ACTIVE,
		Fido: &corev1.ClusterConfig_Spec_Authenticator_FIDO{
			AttestationConveyancePreference: corev1.ClusterConfig_Spec_Authenticator_FIDO_DIRECT,
		},
		AuthenticationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
			{
				Condition: getTestCondition(),
				Effect:    corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
			},
		},
		RegistrationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
			{
				Condition: getTestCondition(),
				Effect:    corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_RECOMMEND,
			},
		},
		PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
			{
				Name:      utilrand.GetRandomStringCanonical(8),
				Condition: getTestCondition(),
				Effect:    corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW,
			},
		},
	}

	cc, err = srv.UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, maxPerUser, cc.Spec.Device.Human.MaxPerUser)
	assert.Equal(t, corev1.Device_Spec_PENDING, cc.Spec.Device.Human.DefaultState)
	assert.Equal(t, maxPerUser, cc.Spec.Device.Workload.MaxPerUser)
	assert.Equal(t, maxPerUser, cc.Spec.Session.Human.MaxPerUser)
	assert.Equal(t, corev1.Session_Spec_PENDING, cc.Spec.Session.Workload.DefaultState)
	assert.Equal(t, int32(2), cc.Spec.Ingress.XffNumTrustedHops)
	assert.True(t, cc.Spec.Ingress.UseForwardedForHeader)
	assert.Equal(t, 2, len(cc.Spec.Dns.FallbackZone.Servers))
	assert.True(t, cc.Spec.Authenticator.EnablePasskeyLogin)
	assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_FIDO_DIRECT,
		cc.Spec.Authenticator.Fido.AttestationConveyancePreference)
	assert.Equal(t, "default", cc.Metadata.Name)

	{
		cc.Spec.Ingress.XffNumTrustedHops = -1
		_, err = srv.UpdateClusterConfig(ctx, cc)
		assert.NotNil(t, err)
		cc.Spec.Ingress.XffNumTrustedHops = 2
	}

	{
		cc.Spec.Device.Human.DefaultState = corev1.Device_Spec_REJECTED
		_, err = srv.UpdateClusterConfig(ctx, cc)
		assert.NotNil(t, err)
		cc.Spec.Device.Human.DefaultState = corev1.Device_Spec_PENDING
	}

	{
		_, err = srv.UpdateClusterConfig(ctx, &corev1.ClusterConfig{
			Metadata: cc.Metadata,
		})
		assert.NotNil(t, err)
	}

	{
		cc, err = srv.UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, int32(2), cc.Spec.Ingress.XffNumTrustedHops)
	}
}

func TestValidateClusterConfig(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv := NewServer(&Opts{
		OcteliumC: tst.C.OcteliumC,
	})

	secret, err := srv.CreateSecret(ctx, &corev1.Secret{
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
	assert.Nil(t, err, "%+v", err)

	policy, err := srv.CreatePolicy(ctx, &corev1.Policy{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Condition: getTestCondition(),
					Effect:    corev1.Policy_Spec_Rule_ALLOW,
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	t.Run("common", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec = nil
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Metadata = nil
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}
	})

	t.Run("session", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Session = nil
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{
				Human: &corev1.ClusterConfig_Spec_Session_Human{
					ClientDuration: &metav1.Duration{
						Type: &metav1.Duration_Hours{Hours: 8},
					},
					ClientlessDuration: &metav1.Duration{
						Type: &metav1.Duration_Hours{Hours: 4},
					},
					AccessTokenDuration: &metav1.Duration{
						Type: &metav1.Duration_Minutes{Minutes: 15},
					},
					RefreshTokenDuration: &metav1.Duration{
						Type: &metav1.Duration_Hours{Hours: 24},
					},
					MaxPerUser:   ccMaxSessionsPerUser,
					DefaultState: corev1.Session_Spec_ACTIVE,
				},
				Workload: &corev1.ClusterConfig_Spec_Session_Workload{
					MaxPerUser:   1,
					DefaultState: corev1.Session_Spec_PENDING,
				},
			}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{
				Human: &corev1.ClusterConfig_Spec_Session_Human{
					MaxPerUser: ccMaxSessionsPerUser + 1,
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{
				Workload: &corev1.ClusterConfig_Spec_Session_Workload{
					MaxPerUser: ccMaxSessionsPerUser + 1,
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{
				Human: &corev1.ClusterConfig_Spec_Session_Human{
					DefaultState: corev1.Session_Spec_REJECTED,
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Session = &corev1.ClusterConfig_Spec_Session{
				Workload: &corev1.ClusterConfig_Spec_Session_Workload{
					DefaultState: corev1.Session_Spec_State(1000),
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

	})

	t.Run("device", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Device = nil
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
				Human: &corev1.ClusterConfig_Spec_Device_Human{
					MaxPerUser:   ccMaxDevicesPerUser,
					DefaultState: corev1.Device_Spec_ACTIVE,
				},
				Workload: &corev1.ClusterConfig_Spec_Device_Workload{
					MaxPerUser:   1,
					DefaultState: corev1.Device_Spec_PENDING,
				},
			}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
				Human: &corev1.ClusterConfig_Spec_Device_Human{
					MaxPerUser: ccMaxDevicesPerUser + 1,
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
				Workload: &corev1.ClusterConfig_Spec_Device_Workload{
					MaxPerUser: ccMaxDevicesPerUser + 1,
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
				Human: &corev1.ClusterConfig_Spec_Device_Human{
					DefaultState: corev1.Device_Spec_REJECTED,
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Device = &corev1.ClusterConfig_Spec_Device{
				Workload: &corev1.ClusterConfig_Spec_Device_Workload{
					DefaultState: corev1.Device_Spec_State(1000),
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}
	})

	t.Run("ingress", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Ingress = nil
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{
				UseForwardedForHeader: true,
				XffNumTrustedHops:     ccMaxXFFNumTrustedHops,
			}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{
				XffNumTrustedHops: -1,
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{
				XffNumTrustedHops: ccMaxXFFNumTrustedHops + 1,
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}
	})

	t.Run("gateway", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Gateway = nil
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Gateway = &corev1.ClusterConfig_Spec_Gateway{
				WireguardKeyRotationDuration: &metav1.Duration{
					Type: &metav1.Duration_Hours{Hours: 12},
				},
			}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

	})

	t.Run("dns", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Dns = nil
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
					Servers: []string{"1.1.1.1", "2606:4700:4700::1111", "dns.example.com"},
					CacheDuration: &metav1.Duration{
						Type: &metav1.Duration_Minutes{Minutes: 10},
					},
				},
			}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			var servers []string
			for i := 0; i < ccMaxDNSServers+1; i++ {
				servers = append(servers, fmt.Sprintf("dns-%d.example.com", i))
			}
			cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
					Servers: servers,
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
					Servers: []string{""},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
					Servers: []string{strings.Repeat("a", ccMaxDNSServerLen+1)},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Dns = &corev1.ClusterConfig_Spec_DNS{
				FallbackZone: &corev1.ClusterConfig_Spec_DNS_Zone{
					Servers: []string{"invalid dns server"},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}
	})

	t.Run("authorization", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authorization = nil
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authorization = &corev1.ClusterConfig_Spec_Authorization{
				Policies: []string{policy.Metadata.Name},
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Name: utilrand.GetRandomStringCanonical(8),
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Condition: getTestCondition(),
									Effect:    corev1.Policy_Spec_Rule_ALLOW,
								},
							},
						},
					},
				},
			}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authorization = &corev1.ClusterConfig_Spec_Authorization{
				Policies: []string{utilrand.GetRandomStringCanonical(8)},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authorization = &corev1.ClusterConfig_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Name: utilrand.GetRandomStringCanonical(8),
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_Match{
											Match: "!!!!",
										},
									},
									Effect: corev1.Policy_Spec_Rule_ALLOW,
								},
							},
						},
					},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}
	})

	t.Run("authenticator", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = nil
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				EnablePasskeyLogin: true,
				DefaultState:       corev1.Authenticator_Spec_PENDING,
				Fido: &corev1.ClusterConfig_Spec_Authenticator_FIDO{
					AttestationConveyancePreference: corev1.ClusterConfig_Spec_Authenticator_FIDO_ENTERPRISE,
				},
				AuthenticationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
					{
						Condition: getTestCondition(),
						Effect:    corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_IGNORE,
					},
				},
				RegistrationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
					{
						Condition: getTestCondition(),
						Effect:    corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
					},
				},
				PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
					{
						Name:      utilrand.GetRandomStringCanonical(8),
						Condition: getTestCondition(),
						Effect:    corev1.ClusterConfig_Spec_Authenticator_Rule_DENY,
					},
				},
			}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			var rules []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule
			for i := 0; i < ccMaxRules+1; i++ {
				rules = append(rules, &corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
					Condition: getTestCondition(),
					Effect:    corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
				})
			}
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				AuthenticationEnforcementRules: rules,
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))

			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				RegistrationEnforcementRules: rules,
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			var rules []*corev1.ClusterConfig_Spec_Authenticator_Rule
			for i := 0; i < ccMaxRules+1; i++ {
				rules = append(rules, &corev1.ClusterConfig_Spec_Authenticator_Rule{
					Condition: getTestCondition(),
					Effect:    corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW,
				})
			}
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				PostAuthenticationRules: rules,
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				AuthenticationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
					{
						Effect: corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
					},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				RegistrationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
					{
						Condition: getTestCondition(),
						Effect:    corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_EFFECT_UNKNOWN,
					},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				AuthenticationEnforcementRules: []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_Match{
								Match: "!!!!",
							},
						},
						Effect: corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
					},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
					{
						Condition: getTestCondition(),
						Effect:    corev1.ClusterConfig_Spec_Authenticator_Rule_EFFECT_UNKNOWN,
					},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
					{
						Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW,
					},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
					{
						Name:      strings.Repeat("a", ccMaxRuleNameLen+1),
						Condition: getTestCondition(),
						Effect:    corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW,
					},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				DefaultState: corev1.Authenticator_Spec_REJECTED,
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
				Fido: &corev1.ClusterConfig_Spec_Authenticator_FIDO{
					AttestationConveyancePreference: corev1.ClusterConfig_Spec_Authenticator_FIDO_AttestationConveyancePreference(1000),
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}
	})

	t.Run("authentication", func(t *testing.T) {
		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = nil
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{}
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{
				Geolocation: &corev1.ClusterConfig_Spec_Authentication_Geolocation{},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{
				Geolocation: &corev1.ClusterConfig_Spec_Authentication_Geolocation{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_Mmdb{
						Mmdb: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{},
					},
				},
			}
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationFromConfig(utilrand.GetRandomStringCanonical(8))
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationFromConfig("invalid config name")
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationFromConfig(strings.Repeat("a", ccMaxNameLen+1))
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb", nil)
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("", nil)
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream(
				"https://example.com/"+strings.Repeat("a", ccMaxURLLen), nil)
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("not a valid url", nil)
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("ftp://example.com/db.mmdb", nil)
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Bearer_{
						Bearer: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Bearer{
							Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Bearer_FromSecret{
								FromSecret: secret.Metadata.Name,
							},
						},
					},
				})
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Bearer_{
						Bearer: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Bearer{},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Bearer_{
						Bearer: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Bearer{
							Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Bearer_FromSecret{
								FromSecret: utilrand.GetRandomStringCanonical(8),
							},
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_{
						Basic: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic{
							Username: utilrand.GetRandomStringCanonical(8),
							Password: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_Password{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_Password_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_{
						Basic: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic{
							Password: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_Password{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_Password_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_{
						Basic: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic{
							Username: strings.Repeat("a", ccMaxNameLen+1),
							Password: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_Password{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_Password_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_{
						Basic: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic{
							Username: utilrand.GetRandomStringCanonical(8),
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_{
						Basic: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic{
							Username: utilrand.GetRandomStringCanonical(8),
							Password: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Basic_Password{},
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_{
						Custom: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom{
							Header: "X-Custom-Auth",
							Value: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_Value{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_Value_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_{
						Custom: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom{
							Value: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_Value{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_Value_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_{
						Custom: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom{
							Header: strings.Repeat("a", ccMaxNameLen+1),
							Value: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_Value{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_Value_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom_{
						Custom: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Custom{
							Header: "X-Custom-Auth",
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_{
						Query: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query{
							Key: "license_key",
							Value: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_Value{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_Value_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.Nil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_{
						Query: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query{
							Value: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_Value{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_Value_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_{
						Query: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query{
							Key: strings.Repeat("a", ccMaxNameLen+1),
							Value: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_Value{
								Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_Value_FromSecret{
									FromSecret: secret.Metadata.Name,
								},
							},
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}

		{
			cc := getTestClusterConfig(ctx, t, srv)
			cc.Spec.Authentication = getTestAuthenticationUpstream("https://example.com/db.mmdb",
				&corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query_{
						Query: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth_Query{
							Key: "license_key",
						},
					},
				})
			assert.NotNil(t, srv.validateClusterConfig(ctx, cc))
		}
	})
}

func getTestAuthenticationFromConfig(name string) *corev1.ClusterConfig_Spec_Authentication {
	return &corev1.ClusterConfig_Spec_Authentication{
		Geolocation: &corev1.ClusterConfig_Spec_Authentication_Geolocation{
			Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_Mmdb{
				Mmdb: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_FromConfig{
						FromConfig: name,
					},
				},
			},
		},
	}
}

func getTestAuthenticationUpstream(url string,
	auth *corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_Auth) *corev1.ClusterConfig_Spec_Authentication {
	return &corev1.ClusterConfig_Spec_Authentication{
		Geolocation: &corev1.ClusterConfig_Spec_Authentication_Geolocation{
			Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_Mmdb{
				Mmdb: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{
					Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_{
						Upstream: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream{
							Url:  url,
							Auth: auth,
						},
					},
				},
			},
		},
	}
}
