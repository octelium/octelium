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

package geoipctl

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestController(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	const prefixURL = `https://raw.githubusercontent.com/maxmind/MaxMind-DB/refs/heads/main/test-data`

	getDB := func(db string) []byte {
		resp, err := resty.New().R().Get(fmt.Sprintf("%s/%s", prefixURL, db))
		assert.Nil(t, err)
		return resp.Body()
	}

	cfg, err := fakeC.OcteliumC.CoreC().CreateConfig(ctx, &corev1.Config{
		Metadata: &metav1.Metadata{
			Name: "my-mmdb",
		},
		Spec:   &corev1.Config_Spec{},
		Status: &corev1.Config_Status{},
		Data: &corev1.Config_Data{
			Type: &corev1.Config_Data_ValueBytes{
				ValueBytes: getDB("GeoIP2-Enterprise-Test.mmdb"),
			},
		},
	})
	assert.Nil(t, err)

	ctl, err := New(ctx, &Opts{
		OcteliumC:  fakeC.OcteliumC,
		ConfigName: cfg.Metadata.Name,
	})
	assert.Nil(t, err)

	err = ctl.setConfig(ctx, cfg)
	assert.Nil(t, err)

	{
		res := ctl.ResolveStr("214.78.120.1")
		assert.NotNil(t, res)
		assert.NotNil(t, res.City)
		assert.NotNil(t, res.Country)
		assert.NotNil(t, res.Timezone)
		assert.NotNil(t, res.Coordinates)
		assert.NotNil(t, res.Network)
		assert.NotEmpty(t, res.PostalCode)
		assert.NotEmpty(t, res.Ip)

	}

	{
		cfg.Data = &corev1.Config_Data{
			Type: &corev1.Config_Data_ValueBytes{
				ValueBytes: getDB("GeoIP2-City-Test.mmdb"),
			},
		}

		cfg, err = fakeC.OcteliumC.CoreC().UpdateConfig(ctx, cfg)
		assert.Nil(t, err)

		err = ctl.setConfig(ctx, cfg)
		assert.Nil(t, err)

		{
			res := ctl.ResolveStr("214.78.120.1")
			assert.NotNil(t, res)
			assert.NotNil(t, res.City)
			assert.NotNil(t, res.Country)
			assert.NotNil(t, res.Timezone)
			assert.NotNil(t, res.Coordinates)
			assert.NotEmpty(t, res.PostalCode)
			assert.NotEmpty(t, res.Ip)

		}

	}

	{
		cfg.Data = &corev1.Config_Data{
			Type: &corev1.Config_Data_ValueBytes{
				ValueBytes: getDB("GeoIP2-Country-Test.mmdb"),
			},
		}

		cfg, err = fakeC.OcteliumC.CoreC().UpdateConfig(ctx, cfg)
		assert.Nil(t, err)

		err = ctl.setConfig(ctx, cfg)
		assert.Nil(t, err)

		{
			res := ctl.ResolveStr("214.78.120.1")
			assert.NotNil(t, res)
			assert.Nil(t, res.City)
			assert.NotNil(t, res.Country)
			assert.Nil(t, res.Timezone)
			assert.Empty(t, res.PostalCode)
			assert.NotEmpty(t, res.Ip)

		}

	}
}
