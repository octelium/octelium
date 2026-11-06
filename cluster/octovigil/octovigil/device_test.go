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

package octovigil

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGetEffectiveDevice(t *testing.T) {
	now := time.Now()

	assert.Nil(t, getEffectiveDevice(nil, nil, now))

	{
		dev := &corev1.Device{}
		assert.True(t, dev == getEffectiveDevice(dev, nil, now))
	}

	{
		dev := &corev1.Device{
			Status: &corev1.Device_Status{
				Hostname: "host",
				Binding: &corev1.Device_Status_Binding{
					State: corev1.Device_Status_Binding_AMBIGUOUS,
				},
			},
		}
		assert.True(t, dev == getEffectiveDevice(dev, nil, now))
	}

	getDevice := func() *corev1.Device {
		return &corev1.Device{
			Status: &corev1.Device_Status{
				SerialNumber: "C02XK1ABJHD3",
				Binding: &corev1.Device_Status_Binding{
					OwnerRef: &metav1.ObjectReference{Uid: "dm1"},
					State:    corev1.Device_Status_Binding_ACCEPTED,
					Validity: corev1.Device_Status_Binding_VALID,
				},
				Posture: &corev1.Device_Status_Posture{
					ThreatFree: corev1.Device_Status_Posture_PASS,
					ExpiresAt:  timestamppb.New(now.Add(time.Hour)),
				},
				ProbeAttempt: &corev1.Device_Status_ProbeAttempt{
					Uid: "attempt",
				},
			},
		}
	}

	{
		dev := getDevice()
		res := getEffectiveDevice(dev, nil, now)
		assert.False(t, dev == res)
		assert.NotNil(t, res.Status.Posture)
		assert.Equal(t, corev1.Device_Status_Posture_PASS, res.Status.Posture.ThreatFree)
		assert.Nil(t, res.Status.ProbeAttempt)
		assert.Equal(t, "C02XK1ABJHD3", res.Status.SerialNumber)
		assert.NotNil(t, dev.Status.ProbeAttempt)
	}

	{
		dev := getDevice()
		dev.Status.Posture.ExpiresAt = timestamppb.New(now.Add(-time.Minute))
		res := getEffectiveDevice(dev, nil, now)
		assert.Nil(t, res.Status.Posture)
		assert.NotNil(t, dev.Status.Posture)
	}

	{
		dev := getDevice()
		dev.Status.Binding.Validity = corev1.Device_Status_Binding_SUSPENDED
		res := getEffectiveDevice(dev, nil, now)
		assert.Nil(t, res.Status.Posture)
		assert.NotNil(t, res.Status.Binding)
	}

	{
		dev := getDevice()
		dev.Status.Binding = nil
		res := getEffectiveDevice(dev, nil, now)
		assert.Nil(t, res.Status.Posture)
	}
}

func TestGetEffectiveDeviceAssurance(t *testing.T) {
	now := time.Now()

	getDevice := func(assurance corev1.Device_Status_Binding_Assurance) *corev1.Device {
		return &corev1.Device{
			Status: &corev1.Device_Status{
				Binding: &corev1.Device_Status_Binding{
					Uid:       "binding",
					Assurance: assurance,
				},
			},
		}
	}

	getSession := func(proof *corev1.Session_Status_DeviceProof) *corev1.Session {
		return &corev1.Session{
			Status: &corev1.Session_Status{
				DeviceProof: proof,
			},
		}
	}

	probe := getSession(&corev1.Session_Status_DeviceProof{
		Type:       corev1.Session_Status_DeviceProof_PROBE,
		BindingUID: "binding",
	})
	staleProbe := getSession(&corev1.Session_Status_DeviceProof{
		Type:       corev1.Session_Status_DeviceProof_PROBE,
		BindingUID: "another-binding",
	})
	hardwareKey := getSession(&corev1.Session_Status_DeviceProof{
		Type: corev1.Session_Status_DeviceProof_HARDWARE_KEY,
	})

	for _, tc := range []struct {
		assurance corev1.Device_Status_Binding_Assurance
		sess      *corev1.Session
		want      corev1.Device_Status_Binding_Assurance
	}{
		{corev1.Device_Status_Binding_ASSURANCE_UNKNOWN, nil, corev1.Device_Status_Binding_ASSURANCE_UNKNOWN},
		{corev1.Device_Status_Binding_OWNER_ONLY, nil, corev1.Device_Status_Binding_OWNER_ONLY},
		{corev1.Device_Status_Binding_IDENTIFIER, nil, corev1.Device_Status_Binding_IDENTIFIER},
		{corev1.Device_Status_Binding_PROVIDER_ID, nil, corev1.Device_Status_Binding_IDENTIFIER},
		{corev1.Device_Status_Binding_SIGNED, nil, corev1.Device_Status_Binding_IDENTIFIER},
		{corev1.Device_Status_Binding_HARDWARE, nil, corev1.Device_Status_Binding_IDENTIFIER},
		{corev1.Device_Status_Binding_PROVIDER_ID, getSession(nil), corev1.Device_Status_Binding_IDENTIFIER},
		{corev1.Device_Status_Binding_PROVIDER_ID, staleProbe, corev1.Device_Status_Binding_IDENTIFIER},
		{corev1.Device_Status_Binding_PROVIDER_ID, probe, corev1.Device_Status_Binding_PROVIDER_ID},
		{corev1.Device_Status_Binding_PROVIDER_ID, hardwareKey, corev1.Device_Status_Binding_PROVIDER_ID},
		{corev1.Device_Status_Binding_HARDWARE, hardwareKey, corev1.Device_Status_Binding_HARDWARE},
		{corev1.Device_Status_Binding_OWNER_ONLY, hardwareKey, corev1.Device_Status_Binding_OWNER_ONLY},
	} {
		dev := getDevice(tc.assurance)
		res := getEffectiveDevice(dev, tc.sess, now)
		assert.Equal(t, tc.want, res.Status.Binding.Assurance, "%+v", tc)
		assert.Equal(t, tc.assurance, dev.Status.Binding.Assurance, "the Device must not be changed")
	}
}

func TestIsAuthorizedDevicePosture(t *testing.T) {
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

	ns, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, tests.GenService(ns.Metadata.Name))
	assert.Nil(t, err)

	svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
		InlinePolicies: []*corev1.InlinePolicy{
			{
				Spec: &corev1.Policy_Spec{
					Rules: []*corev1.Policy_Spec_Rule{
						{
							Effect: corev1.Policy_Spec_Rule_ALLOW,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `has(ctx.device.status.posture) && ctx.device.status.posture.threatFree == "PASS"`,
								},
							},
						},
					},
				},
			},
		},
	}

	svc, err = adminSrv.UpdateService(ctx, svc)
	assert.Nil(t, err)

	srv, err := New(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)
	srv.cache.SetService(svc)

	usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)
	srv.cache.SetUser(usr.Usr)

	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)
	srv.cache.SetSession(usr.Session)

	getReq := func() *coctovigilv1.DownstreamRequest {
		return &coctovigilv1.DownstreamRequest{
			Source: &coctovigilv1.DownstreamRequest_Source{
				Address: func() string {
					if usr.Session.Status.Connection.Addresses[0].V4 != "" {
						return umetav1.ToDualStackNetwork(usr.Session.Status.Connection.Addresses[0]).ToIP().Ipv4
					}
					return umetav1.ToDualStackNetwork(usr.Session.Status.Connection.Addresses[0]).ToIP().Ipv6
				}(),
			},
		}
	}

	isAuthorized := func() bool {
		i, err := srv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: getReq(),
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, i.IsAuthenticated)
		return i.IsAuthorized
	}

	setDevice := func(binding *corev1.Device_Status_Binding, posture *corev1.Device_Status_Posture) {
		usr.Device.Status.Binding = binding
		usr.Device.Status.Posture = posture
		usr.Device, err = fakeC.OcteliumC.CoreC().UpdateDevice(ctx, usr.Device)
		assert.Nil(t, err)
		srv.cache.SetDevice(usr.Device)
	}

	getBinding := func() *corev1.Device_Status_Binding {
		return &corev1.Device_Status_Binding{
			Uid:      "binding",
			OwnerRef: &metav1.ObjectReference{Uid: "dm1", Name: "dm1"},
			State:    corev1.Device_Status_Binding_ACCEPTED,
			Validity: corev1.Device_Status_Binding_VALID,
		}
	}

	getPosture := func(expiresAt time.Time) *corev1.Device_Status_Posture {
		return &corev1.Device_Status_Posture{
			ThreatFree: corev1.Device_Status_Posture_PASS,
			ExpiresAt:  timestamppb.New(expiresAt),
		}
	}

	assert.False(t, isAuthorized())

	setDevice(getBinding(), getPosture(time.Now().Add(time.Hour)))
	assert.True(t, isAuthorized())

	setDevice(getBinding(), getPosture(time.Now().Add(-time.Second)))
	assert.False(t, isAuthorized())

	{
		b := getBinding()
		b.Validity = corev1.Device_Status_Binding_SUSPENDED
		setDevice(b, getPosture(time.Now().Add(time.Hour)))
		assert.False(t, isAuthorized())
	}

	{
		b := getBinding()
		b.State = corev1.Device_Status_Binding_AMBIGUOUS
		setDevice(b, getPosture(time.Now().Add(time.Hour)))
		assert.False(t, isAuthorized())
	}

	setDevice(nil, getPosture(time.Now().Add(time.Hour)))
	assert.False(t, isAuthorized())

	{
		p := getPosture(time.Now().Add(time.Hour))
		p.ThreatFree = corev1.Device_Status_Posture_NOT_APPLICABLE
		setDevice(getBinding(), p)
		assert.False(t, isAuthorized())
	}

	setDevice(getBinding(), getPosture(time.Now().Add(time.Hour)))
	assert.True(t, isAuthorized())

	svc.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].Condition = &corev1.Condition{
		Type: &corev1.Condition_Match{
			Match: `has(ctx.device.status.posture) && ctx.device.status.binding.isOwnerMatched && ` +
				`ctx.device.status.binding.assurance in ["PROVIDER_ID", "SIGNED", "HARDWARE"]`,
		},
	}
	svc, err = adminSrv.UpdateService(ctx, svc)
	assert.Nil(t, err)
	srv.cache.SetService(svc)

	assert.False(t, isAuthorized())

	setDeviceProof := func(proof *corev1.Session_Status_DeviceProof) {
		usr.Session.Status.DeviceProof = proof
		srv.cache.SetSession(usr.Session)
	}

	{
		b := getBinding()
		b.IsOwnerMatched = true
		b.Assurance = corev1.Device_Status_Binding_OWNER_ONLY
		setDevice(b, getPosture(time.Now().Add(time.Hour)))
		assert.False(t, isAuthorized())
	}

	{
		b := getBinding()
		b.IsOwnerMatched = true
		b.Assurance = corev1.Device_Status_Binding_IDENTIFIER
		setDevice(b, getPosture(time.Now().Add(time.Hour)))
		assert.False(t, isAuthorized())
	}

	{
		b := getBinding()
		b.IsOwnerMatched = true
		b.Assurance = corev1.Device_Status_Binding_PROVIDER_ID
		setDevice(b, getPosture(time.Now().Add(time.Hour)))
		assert.False(t, isAuthorized(), "a strong Binding must not pass to a Session without a proof")

		setDeviceProof(&corev1.Session_Status_DeviceProof{
			Type:       corev1.Session_Status_DeviceProof_PROBE,
			BindingUID: "another-binding",
		})
		assert.False(t, isAuthorized())

		setDeviceProof(&corev1.Session_Status_DeviceProof{
			Type:       corev1.Session_Status_DeviceProof_PROBE,
			BindingUID: "binding",
		})
		assert.True(t, isAuthorized())

		setDeviceProof(&corev1.Session_Status_DeviceProof{
			Type: corev1.Session_Status_DeviceProof_HARDWARE_KEY,
		})
		assert.True(t, isAuthorized())
	}

	{
		b := getBinding()
		b.Assurance = corev1.Device_Status_Binding_PROVIDER_ID
		setDevice(b, getPosture(time.Now().Add(time.Hour)))
		assert.False(t, isAuthorized())
	}

	svc.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].Condition = &corev1.Condition{
		Type: &corev1.Condition_Match{
			Match: `ctx.session.status.deviceProof.type == "HARDWARE_KEY"`,
		},
	}
	svc, err = adminSrv.UpdateService(ctx, svc)
	assert.Nil(t, err)
	srv.cache.SetService(svc)

	assert.True(t, isAuthorized())

	setDeviceProof(&corev1.Session_Status_DeviceProof{
		Type:       corev1.Session_Status_DeviceProof_PROBE,
		BindingUID: "binding",
	})
	assert.False(t, isAuthorized())

	setDeviceProof(nil)
	assert.False(t, isAuthorized())
}
