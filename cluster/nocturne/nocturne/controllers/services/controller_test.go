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
	"os"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestServiceLock(t *testing.T) {
	c := &Controller{serviceLocks: make(map[string]*serviceLock)}
	svc1 := &corev1.Service{Metadata: &metav1.Metadata{Uid: "svc-1"}}
	svc2 := &corev1.Service{Metadata: &metav1.Metadata{Uid: "svc-2"}}

	unlock := c.lockService(svc1)

	acquiredSame := make(chan func(), 1)
	go func() {
		acquiredSame <- c.lockService(svc1)
	}()

	select {
	case sameUnlock := <-acquiredSame:
		sameUnlock()
		assert.Fail(t, "the same Service lock was acquired concurrently")
	case <-time.After(50 * time.Millisecond):
	}

	acquiredOther := make(chan func(), 1)
	go func() {
		acquiredOther <- c.lockService(svc2)
	}()

	select {
	case otherUnlock := <-acquiredOther:
		otherUnlock()
	case <-time.After(time.Second):
		assert.Fail(t, "a different Service lock was blocked")
	}

	unlock()
	select {
	case sameUnlock := <-acquiredSame:
		sameUnlock()
	case <-time.After(time.Second):
		assert.Fail(t, "the same Service lock was not released")
	}
}

func TestController(t *testing.T) {

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
	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	os.Setenv("OCTELIUM_REGION_NAME", "default")
	defer os.Unsetenv("OCTELIUM_REGION_NAME")

	c := NewController(fakeC.OcteliumC, fakeC.K8sC)
	svc, err := adminSrv.CreateService(ctx, tests.GenService(netw.Metadata.Name))
	assert.Nil(t, err)
	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	err = c.OnAdd(ctx, svcV)
	assert.Nil(t, err)

	err = c.OnAdd(ctx, svcV)
	assert.Nil(t, err)

	rdpReq := tests.GenService(netw.Metadata.Name)
	rdpReq.Spec.Mode = corev1.Service_Spec_RDP_WEB
	rdpReq.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "rdp://localhost",
	}
	rdpSvc, err := adminSrv.CreateService(ctx, rdpReq)
	assert.Nil(t, err)

	rdpPodSpec := c.newPodSpec(rdpSvc)
	assert.Equal(t, 1, len(rdpPodSpec.Containers))
	assert.Equal(t, "vigil", rdpPodSpec.Containers[0].Name)

	err = c.OnDelete(ctx, svcV)
	assert.Nil(t, err)
}
