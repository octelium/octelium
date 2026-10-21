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
	"math"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestDevice(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr, err := srv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err)

	usr2, err := srv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err)

	createDevice := func(userRef *metav1.ObjectReference) *corev1.Device {
		dev, err := srv.octeliumC.CoreC().CreateDevice(ctx, &corev1.Device{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Device_Spec{
				State: corev1.Device_Spec_ACTIVE,
			},
			Status: &corev1.Device_Status{
				UserRef:  userRef,
				OsType:   corev1.Device_Status_LINUX,
				Hostname: utilrand.GetRandomStringLowercase(10),
				Id:       utilrand.GetRandomStringCanonical(12),
			},
		})
		assert.Nil(t, err, "%+v", err)
		return dev
	}

	{
		dev := createDevice(umetav1.GetObjectReference(usr))

		res, err := srv.GetDevice(ctx, &metav1.GetOptions{Uid: dev.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, dev.Metadata.Uid, res.Metadata.Uid)
		assert.True(t, pbutils.IsEqual(dev.Spec, res.Spec))
		assert.Equal(t, usr.Metadata.Uid, res.Status.UserRef.Uid)
	}

	{
		res, err := srv.GetDevice(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
		assert.Nil(t, res)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		dev := createDevice(umetav1.GetObjectReference(usr))

		devClone := pbutils.Clone(dev).(*corev1.Device)
		devClone.Spec.State = corev1.Device_Spec_PENDING

		out, err := srv.UpdateDevice(ctx, devClone)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, corev1.Device_Spec_PENDING, out.Spec.State)

		res, err := srv.GetDevice(ctx, &metav1.GetOptions{Uid: dev.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, corev1.Device_Spec_PENDING, res.Spec.State)
		assert.Equal(t, usr.Metadata.Uid, res.Status.UserRef.Uid)
	}

	{
		dev := createDevice(umetav1.GetObjectReference(usr))

		devClone := pbutils.Clone(dev).(*corev1.Device)
		devClone.Spec.Authorization = &corev1.Device_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
							},
						},
					},
				},
			},
		}

		out, err := srv.UpdateDevice(ctx, devClone)
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, out.Spec.Authorization)
	}

	{
		_, err := srv.UpdateDevice(ctx, &corev1.Device{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateDevice(ctx, &corev1.Device{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Device_Spec{
				State: corev1.Device_Spec_STATE_UNKNOWN,
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateDevice(ctx, &corev1.Device{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Device_Spec{
				State: corev1.Device_Spec_ACTIVE,
				Authorization: &corev1.Device_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_All_{
												All: &corev1.Condition_All{
													Of: []*corev1.Condition{
														{
															Type: &corev1.Condition_Match{
																Match: "1 = 1",
															},
														},
														{
															Type: &corev1.Condition_Match{
																Match: "1 + 1",
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateDevice(ctx, &corev1.Device{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Device_Spec{
				State: corev1.Device_Spec_ACTIVE,
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		dev := createDevice(umetav1.GetObjectReference(usr))

		list, err := srv.ListDevice(ctx, &corev1.ListDeviceOptions{})
		assert.Nil(t, err, "%+v", err)

		found := false
		for _, itm := range list.Items {
			if itm.Metadata.Uid == dev.Metadata.Uid {
				found = true
			}
		}
		assert.True(t, found)
	}

	{
		devUsr := createDevice(umetav1.GetObjectReference(usr))
		devUsr2 := createDevice(umetav1.GetObjectReference(usr2))

		list, err := srv.ListDevice(ctx, &corev1.ListDeviceOptions{
			UserRef: umetav1.GetObjectReference(usr),
		})
		assert.Nil(t, err, "%+v", err)

		foundUsr := false
		for _, itm := range list.Items {
			assert.Equal(t, usr.Metadata.Uid, itm.Status.UserRef.Uid)
			assert.NotEqual(t, devUsr2.Metadata.Uid, itm.Metadata.Uid)
			if itm.Metadata.Uid == devUsr.Metadata.Uid {
				foundUsr = true
			}
		}
		assert.True(t, foundUsr)

		listUsr2, err := srv.ListDevice(ctx, &corev1.ListDeviceOptions{
			UserRef: umetav1.GetObjectReference(usr2),
		})
		assert.Nil(t, err, "%+v", err)

		foundUsr2 := false
		for _, itm := range listUsr2.Items {
			assert.Equal(t, usr2.Metadata.Uid, itm.Status.UserRef.Uid)
			if itm.Metadata.Uid == devUsr2.Metadata.Uid {
				foundUsr2 = true
			}
		}
		assert.True(t, foundUsr2)
	}

	{
		_, err := srv.ListDevice(ctx, &corev1.ListDeviceOptions{
			UserRef: &metav1.ObjectReference{},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		dev := createDevice(umetav1.GetObjectReference(usr))

		_, err := srv.DeleteDevice(ctx, &metav1.DeleteOptions{Uid: dev.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.GetDevice(ctx, &metav1.GetOptions{Uid: dev.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		_, err := srv.DeleteDevice(ctx, &metav1.DeleteOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
}

func TestDeviceUpdatePreservesStatus(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s := newFakeServer(tst.C)
	item, err := s.octeliumC.CoreC().CreateDevice(t.Context(), &corev1.Device{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec:     &corev1.Device_Spec{State: corev1.Device_Spec_ACTIVE},
		Status:   &corev1.Device_Status{UserRef: &metav1.ObjectReference{Name: "owner", Uid: "7f0da666-37af-4cf9-8d0f-995d82877e70"}},
	})
	require.Nil(t, err)
	before := proto.Clone(item.Status)
	req := proto.Clone(item).(*corev1.Device)
	req.Spec.State = corev1.Device_Spec_REJECTED
	req.Status = &corev1.Device_Status{UserRef: &metav1.ObjectReference{Name: "forged-owner"}}
	got, err := s.UpdateDevice(t.Context(), req)
	require.Nil(t, err)
	assert.Equal(t, corev1.Device_Spec_REJECTED, got.Spec.State)
	assert.True(t, proto.Equal(before, got.Status))
}

func TestDeviceStateValidation(t *testing.T) {
	for _, state := range []corev1.Device_Spec_State{
		corev1.Device_Spec_ACTIVE,
		corev1.Device_Spec_PENDING,
		corev1.Device_Spec_REJECTED,
		corev1.Device_Spec_STATE_UNKNOWN,
		-1, 4, 1000, math.MinInt32, math.MaxInt32,
	} {
		t.Run(state.String(), func(t *testing.T) {
			calls := 0
			s := newTstServer(func(method string, req, resp any) error {
				calls++
				return status.Error(codes.Unavailable, "backend")
			})
			item := &corev1.Device{
				Metadata: &metav1.Metadata{Name: "device"},
				Spec:     &corev1.Device_Spec{State: state},
			}
			err := s.validateDevice(t.Context(), item)
			switch state {
			case corev1.Device_Spec_ACTIVE, corev1.Device_Spec_PENDING, corev1.Device_Spec_REJECTED:
				assert.Nil(t, err)
			default:
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				_, err = s.UpdateDevice(t.Context(), item)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			}
			assert.Zero(t, calls)
		})
	}
}
