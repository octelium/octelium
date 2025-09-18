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

package resources

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/stretchr/testify/assert"
)

func TestGetListeners(t *testing.T) {

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
	usr := tests.GenUser(nil)

	doCreateSvc := func() *corev1.Service {
		svc := tests.GenService("default")
		svc.Spec.IsPublic = true
		svc.Spec.Mode = corev1.Service_Spec_HTTP
		svc, err = adminSrv.CreateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)
		ret, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		return ret
	}

	usr, err = adminSrv.CreateUser(ctx, usr)
	assert.Nil(t, err)

	_, err = GetListeners("example.com", nil, nil)
	assert.Nil(t, err)
	_, err = GetListeners("example.com", nil, nil)
	assert.Nil(t, err)

	var svcList []*corev1.Service
	for i := 0; i < 100; i++ {
		svcList = append(svcList, doCreateSvc())
	}

	_, err = GetListeners("example.com", svcList, nil)
	assert.Nil(t, err)
	_, err = GetListeners("example.com", svcList, nil)
	assert.Nil(t, err)

	doCreateCrt := func(name string) *corev1.Secret {
		ca, err := utils_cert.GenerateCARoot()
		crtPEM, err := ca.GetCertPEM()
		assert.Nil(t, err)
		crtPrivatePEM, err := ca.GetPrivateKeyPEM()
		assert.Nil(t, err)

		crt := &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: name,
			},
			Spec:   &corev1.Secret_Spec{},
			Status: &corev1.Secret_Status{},
		}

		ucorev1.ToSecret(crt).SetCertificate(crtPEM, crtPrivatePEM)

		ret, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, crt)
		assert.Nil(t, err)
		return ret
	}

	_, err = GetListeners("example.com", svcList, nil)
	assert.Nil(t, err)
	_, err = GetListeners("example.com", svcList, []*corev1.Secret{
		doCreateCrt("cluster"),
	})
	assert.Nil(t, err)
}
