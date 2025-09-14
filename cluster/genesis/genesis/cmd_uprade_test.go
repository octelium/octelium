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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestRunUpgrade(t *testing.T) {

	tests.InitLog()
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
