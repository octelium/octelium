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

package genesis

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"

	nadclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"

	fakenad "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"

	k8scorev1 "k8s.io/api/core/v1"

	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	fakek8s "k8s.io/client-go/kubernetes/fake"

	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8stesting "k8s.io/client-go/testing"
)

type FakeClient struct {
	K8sC kubernetes.Interface
	NadC nadclientset.Interface
}

func now() k8smetav1.Time {
	return k8smetav1.Time{
		time.Now(),
	}
}

func newFakeClient() *FakeClient {
	k8sC := fakek8s.NewSimpleClientset()

	k8sC.PrependReactor("*", "*", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		switch {
		case action.Matches("create", "secrets"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Secret)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(vutils.UUIDv4())
		case action.Matches("create", "pods"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Pod)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(vutils.UUIDv4())
		case action.Matches("create", "nodes"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Node)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(vutils.UUIDv4())
		}
		return
	})

	return &FakeClient{
		K8sC: k8sC,
		NadC: fakenad.NewSimpleClientset(),
	}
}

func setClusterConfigRegion(ctx context.Context, k8sC kubernetes.Interface, region *corev1.Region, db string) error {

	dataMap := map[string][]byte{
		"region": pbutils.MarshalMust(region),
		"bootstrap": pbutils.MarshalMust(&cbootstrapv1.Config{
			Spec: &cbootstrapv1.Config_Spec{
				PrimaryStorage: &cbootstrapv1.Config_Spec_PrimaryStorage{
					Type: &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_{
						Postgresql: &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql{
							Database: db,
						},
					},
				},
				SecondaryStorage: &cbootstrapv1.Config_Spec_SecondaryStorage{
					Type: &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_{
						Redis: &cbootstrapv1.Config_Spec_SecondaryStorage_Redis{},
					},
				},
			},
		}),
	}

	{

		if secret, err := k8sC.CoreV1().Secrets("default").Get(ctx, "octelium-init", k8smetav1.GetOptions{}); err == nil {
			secret.Data = dataMap
			_, err := k8sC.CoreV1().Secrets("default").Update(ctx, secret, k8smetav1.UpdateOptions{})
			if err != nil {
				return err
			}
		} else if k8serr.IsNotFound(err) {
			_, err := k8sC.CoreV1().Secrets("default").Create(ctx, &k8scorev1.Secret{
				ObjectMeta: k8smetav1.ObjectMeta{
					Name: "octelium-init",
				},
				Data: dataMap,
			}, k8smetav1.CreateOptions{})
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func TestRunInit(t *testing.T) {

	ldflags.TestMode = "true"
	ldflags.PrivateRegistry = "false"

	os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")

	os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
	os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
	os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")

	ctx := context.Background()
	dbName := fmt.Sprintf("octelium%s", utilrand.GetRandomStringLowercase(6))

	os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")

	os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
	os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
	os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")

	db, err := postgresutils.NewDBWithNODB()
	assert.Nil(t, err)

	defer db.Close()

	// ctx := context.Background()
	// c := newFakeClient()

	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s;", dbName))
	assert.Nil(t, err)

	os.Setenv("OCTELIUM_POSTGRES_DATABASE", dbName)

	region := &corev1.Region{
		Kind: "Region",
		Metadata: &metav1.Metadata{
			Name: "default",
		},
		Spec:   &corev1.Region_Spec{},
		Status: &corev1.Region_Status{},
	}

	{
		c := newFakeClient()
		g := &Genesis{
			k8sC: c.K8sC,
			nadC: c.NadC,
		}

		err := setClusterConfigRegion(ctx, g.k8sC, region, dbName)
		assert.Nil(t, err)

		err = g.RunInit(ctx)
		assert.Nil(t, err, "%+v", err)

		{
			sec, err := g.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: vutils.ClusterCertSecretName,
			})
			assert.Nil(t, err)

			assert.True(t, vutils.IsCertReady(sec))
		}

		region, err = g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Name: region.Metadata.Name,
		})
		assert.Nil(t, err)

		{
			svcList, err := g.getAllServices(ctx, region)
			assert.Nil(t, err)
			assert.True(t, len(svcList) > 0)
		}

		{
			err = g.RunUpgrade(ctx)
			assert.Nil(t, err, "%+v", err)
		}

		{
			err = g.RunUpgrade(ctx)
			assert.Nil(t, err, "%+v", err)
		}
	}
}
