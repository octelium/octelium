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

/*
import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/policyv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestOPA(t *testing.T) {

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

	network, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	networkK8s, err := fakeC.OcteliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Name: network.Metadata.Name})
	assert.Nil(t, err)

	_, err = fakeC.OcteliumC.CoreC().UpdateNamespace(ctx, networkK8s)
	assert.Nil(t, err)

	{
		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		opaScript := `
package octelium.condition

default match = false
match {
	input.k1 == "v1"
	input.k2 > 3
}
		`

		match, err := srv.isMatchedOPA(ctx, opaScript, map[string]any{
			"k1": "v1",
			"k2": 5,
		})
		assert.Nil(t, err)
		assert.True(t, match)
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
		assert.Nil(t, err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svcV)

		usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		opaScript := `
package octelium.condition

default match = false
match {
	input.ctx.user.metadata.name == input.ctx.session.status.userRef.name
}
		`

		svcV.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Opa{
										Opa: &corev1.Condition_OPA{
											Type: &corev1.Condition_OPA_Inline{
												Inline: opaScript,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Service: svcV,
			Session: usr.Session,
		}

		reqCtxMap, err := reqCtxToMap(reqCtx)
		assert.Nil(t, err)
		match, err := srv.isMatchedOPA(ctx, opaScript, map[string]any{
			"ctx": reqCtxMap,
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, match)
	}

}
*/
