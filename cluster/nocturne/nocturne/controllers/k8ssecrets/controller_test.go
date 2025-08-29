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

package k8ssecretcontroller

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestController(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		_, _ = fakeC.OcteliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{
			Name: "crt-ns-default",
		})
	}

	{
		crt, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		k8sSec := &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      "cert-cluster",
				Namespace: "octelium",
			},
			Data: map[string][]byte{
				"tls.crt": crt.MustGetCertPEM(),
				"tls.key": crt.MustGetPrivateKeyPEM(),
			},
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.Nil(t, err)

		sec, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
			Name: "crt-ns-default",
		})
		assert.Nil(t, err)

		assert.Equal(t, "true", sec.Metadata.SystemLabels["octelium-cert"])
		assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
		assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())

	}

	{
		crt, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		ns := utilrand.GetRandomStringCanonical(8)
		k8sSec := &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      fmt.Sprintf("cert-ns-%s", ns),
				Namespace: "octelium",
			},
			Data: map[string][]byte{
				"tls.crt": crt.MustGetCertPEM(),
				"tls.key": crt.MustGetPrivateKeyPEM(),
			},
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.Nil(t, err)

		sec, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
			Name: fmt.Sprintf("crt-ns-%s", ns),
		})
		assert.Nil(t, err)

		assert.Equal(t, "true", sec.Metadata.SystemLabels["octelium-cert"])
		assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
		assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())

	}

	{

		crt, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		k8sSec := &k8scorev1.Secret{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      "cert-cluster",
				Namespace: "octelium",
			},
			Data: map[string][]byte{
				"tls.crt": crt.MustGetCertPEM(),
				"tls.key": crt.MustGetPrivateKeyPEM(),
			},
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.Nil(t, err)

		{
			sec, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: "crt-ns-default",
			})
			assert.Nil(t, err)
			assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
			assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
		}

		crt, err = utils_cert.GenerateCARoot()
		assert.Nil(t, err)

		k8sSec.Data = map[string][]byte{
			"tls.crt": crt.MustGetCertPEM(),
			"tls.key": crt.MustGetPrivateKeyPEM(),
		}

		err = setCert(ctx, fakeC.OcteliumC, k8sSec)
		assert.Nil(t, err)

		{
			sec, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: "crt-ns-default",
			})
			assert.Nil(t, err)
			assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
			assert.Equal(t, string(k8sSec.Data["tls.key"]), ucorev1.ToSecret(sec).GetValueStr())
		}
	}
}
