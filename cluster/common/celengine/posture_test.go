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

package celengine

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestConditionDevicePosture(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv, err := New(ctx, &Opts{})
	assert.Nil(t, err)

	getInput := func(posture *corev1.Device_Status_Posture) map[string]any {
		ret, err := pbutils.ConvertToMap(&corev1.RequestContext{
			Device: &corev1.Device{
				Status: &corev1.Device_Status{
					Posture: posture,
				},
			},
		})
		assert.Nil(t, err)

		return map[string]any{
			"ctx": ret,
		}
	}

	reported := getInput(&corev1.Device_Status_Posture{
		RiskLevel:      corev1.Device_Status_Posture_LOW,
		Score:          proto.Uint32(85),
		FailingChecks:  proto.Uint32(0),
		ActiveThreats:  proto.Uint32(0),
		Compliant:      corev1.Device_Status_Posture_GRACE_PERIOD,
		DiskEncryption: corev1.Device_Status_Posture_PASS,
		Firewall:       corev1.Device_Status_Posture_FAIL,
		Ownership:      corev1.Device_Status_Posture_COMPANY,
		DeviceClass:    corev1.Device_Status_Posture_WORKSTATION,
		Os: &corev1.Device_Status_Posture_OS{
			Type:    corev1.Device_Status_MAC,
			Version: "15.0",
			Major:   proto.Uint32(15),
			Minor:   proto.Uint32(0),
		},
	})

	unreported := getInput(&corev1.Device_Status_Posture{})

	const prefix = "ctx.device.status.posture."

	for _, tc := range []struct {
		cond     string
		opa      string
		reported bool
	}{
		{cond: `score >= 70`, reported: true},
		{cond: `score >= 90`},
		{cond: `score < 70`},
		{cond: `failingChecks == 0`, reported: true},
		{cond: `activeThreats == 0`, reported: true},
		{cond: `activeThreats > 0`},
		{cond: `os.major >= 15`, reported: true},
		{cond: `os.minor == 0`, reported: true},
		{cond: `os.minor >= 1`},
		{cond: `os.type == "MAC"`, reported: true},
		{cond: `riskLevel == "LOW"`, reported: true},
		{cond: `diskEncryption == "PASS"`, reported: true},
		{cond: `firewall == "PASS"`},
		{cond: `compliant == "PASS"`},
		{cond: `compliant == "GRACE_PERIOD"`, reported: true},
		{cond: `ownership == "COMPANY"`, reported: true},
		{cond: `deviceClass == "WORKSTATION"`, reported: true},
	} {
		t.Run(tc.cond, func(t *testing.T) {
			celCond := &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: prefix + tc.cond,
				},
			}

			opaCond := &corev1.Condition{
				Type: &corev1.Condition_Opa{
					Opa: &corev1.Condition_OPA{
						Type: &corev1.Condition_OPA_Inline{
							Inline: fmt.Sprintf("package octelium.condition\n\nmatch if {\n\tinput.%s%s\n}\n",
								prefix, tc.cond),
						},
					},
				},
			}

			for _, cond := range []*corev1.Condition{celCond, opaCond} {
				res, err := srv.EvalCondition(ctx, cond, reported)
				assert.Nil(t, err, "%+v", err)
				assert.Equal(t, tc.reported, res)

				res, err = srv.EvalCondition(ctx, cond, unreported)
				assert.Nil(t, err, "%+v", err)
				assert.False(t, res, "a signal that was not reported must not match")
			}
		})
	}

	t.Run("VersionComparison", func(t *testing.T) {
		res, err := srv.EvalCondition(ctx, &corev1.Condition{
			Type: &corev1.Condition_Match{
				Match: prefix + `os.major > 14 || (` + prefix + `os.major == 14 && ` + prefix + `os.minor >= 5)`,
			},
		}, reported)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, res)
	})

	t.Run("Binding", func(t *testing.T) {
		const assurance = `ctx.device.status.binding.assurance in ["PROVIDER_ID", "SIGNED", "HARDWARE"]`

		getBindingInput := func(binding *corev1.Device_Status_Binding,
			proof *corev1.Session_Status_DeviceProof) map[string]any {
			ret, err := pbutils.ConvertToMap(&corev1.RequestContext{
				Device: &corev1.Device{
					Status: &corev1.Device_Status{
						Binding: binding,
					},
				},
				Session: &corev1.Session{
					Status: &corev1.Session_Status{
						DeviceProof: proof,
					},
				},
			})
			assert.Nil(t, err)

			return map[string]any{
				"ctx": ret,
			}
		}

		strong := getBindingInput(&corev1.Device_Status_Binding{
			Assurance:      corev1.Device_Status_Binding_PROVIDER_ID,
			IsOwnerMatched: true,
		}, &corev1.Session_Status_DeviceProof{
			Type: corev1.Session_Status_DeviceProof_HARDWARE_KEY,
		})
		weak := getBindingInput(&corev1.Device_Status_Binding{
			Assurance: corev1.Device_Status_Binding_IDENTIFIER,
		}, nil)
		empty := getBindingInput(&corev1.Device_Status_Binding{}, nil)

		for _, tc := range []struct {
			expr string
			opa  string
			want bool
		}{
			{
				expr: assurance,
				opa:  `input.` + assurance,
				want: true,
			},
			{
				expr: `ctx.device.status.binding.isOwnerMatched`,
				opa:  `input.ctx.device.status.binding.isOwnerMatched`,
				want: true,
			},
			{
				expr: `ctx.session.status.deviceProof.type == "HARDWARE_KEY"`,
				opa:  `input.ctx.session.status.deviceProof.type == "HARDWARE_KEY"`,
				want: true,
			},
			{
				expr: `ctx.session.status.deviceProof.type == "PROBE"`,
				opa:  `input.ctx.session.status.deviceProof.type == "PROBE"`,
			},
		} {
			celCond := &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: tc.expr,
				},
			}
			opaCond := &corev1.Condition{
				Type: &corev1.Condition_Opa{
					Opa: &corev1.Condition_OPA{
						Type: &corev1.Condition_OPA_Inline{
							Inline: fmt.Sprintf("package octelium.condition\n\nmatch if {\n\t%s\n}\n", tc.opa),
						},
					},
				},
			}

			for _, cond := range []*corev1.Condition{celCond, opaCond} {
				res, err := srv.EvalCondition(ctx, cond, strong)
				assert.Nil(t, err, "%+v", err)
				assert.Equal(t, tc.want, res, "%s", tc.expr)

				for _, input := range []map[string]any{weak, empty} {
					res, err = srv.EvalCondition(ctx, cond, input)
					assert.Nil(t, err, "%+v", err)
					assert.False(t, res, "%s", tc.expr)
				}
			}
		}
	})

	t.Run("GracePeriodAccepted", func(t *testing.T) {
		const set = `["PASS", "GRACE_PERIOD"]`

		res, err := srv.EvalCondition(ctx, &corev1.Condition{
			Type: &corev1.Condition_Match{
				Match: prefix + `compliant in ` + set,
			},
		}, reported)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, res)

		res, err = srv.EvalCondition(ctx, &corev1.Condition{
			Type: &corev1.Condition_Match{
				Match: prefix + `compliant in ` + set,
			},
		}, unreported)
		assert.Nil(t, err, "%+v", err)
		assert.False(t, res)

		res, err = srv.EvalCondition(ctx, &corev1.Condition{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{
						Inline: fmt.Sprintf("package octelium.condition\n\nmatch if {\n\tinput.%scompliant in %s\n}\n",
							prefix, set),
					},
				},
			},
		}, reported)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, res)
	})
}
