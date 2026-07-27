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

package svccontroller

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func sessionHasUpstreamForSvc(sess *corev1.Session, svc *corev1.Service) bool {
	if sess.Status == nil || sess.Status.Connection == nil {
		return false
	}
	for _, u := range sess.Status.Connection.Upstreams {
		if u.ServiceRef != nil && u.ServiceRef.Uid == svc.Metadata.Uid {
			return true
		}
	}
	return false
}

func TestHandleSessionUpstreamLifecycle(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	os.Setenv("OCTELIUM_REGION_NAME", "default")
	defer os.Unsetenv("OCTELIUM_REGION_NAME")

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err, "%+v", err)

	hostUsr, err := adminSrv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err, "%+v", err)

	c := NewController(fakeC.OcteliumC, fakeC.K8sC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), netw.Metadata.Name),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					User: hostUsr.Metadata.Name,
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)

	sess, err := fakeC.OcteliumC.CoreC().CreateSession(ctx, &corev1.Session{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Session_Spec{
			State:     corev1.Session_Spec_ACTIVE,
			ExpiresAt: pbutils.Timestamp(time.Now().Add(time.Hour)),
		},
		Status: &corev1.Session_Status{
			UserRef: umetav1.GetObjectReference(hostUsr),
			Type:    corev1.Session_Status_CLIENT,
			Connection: &corev1.Session_Status_Connection{
				ServiceOptions: &corev1.Session_Status_Connection_ServiceOptions{
					ServeAll: true,
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	err = c.handleUpdateSessionUpstream(ctx, svcV)
	assert.Nil(t, err, "%+v", err)

	{
		res, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, sessionHasUpstreamForSvc(res, svc))
	}

	err = c.handleDeleteSessionUpstream(ctx, svcV)
	assert.Nil(t, err, "%+v", err)

	{
		res, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, sessionHasUpstreamForSvc(res, svc))
	}
}

func TestHandleSessionUpstreamNoUserListener(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	c := NewController(fakeC.OcteliumC, fakeC.K8sC)

	svc := tests.GenService("default")

	assert.Nil(t, c.handleUpdateSessionUpstream(ctx, svc))
	assert.Nil(t, c.handleDeleteSessionUpstream(ctx, svc))
}
