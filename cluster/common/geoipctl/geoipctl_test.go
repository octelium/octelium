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
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestDecompress(t *testing.T) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	want := []byte{0, 1, 2, 3, 0xff}
	_, err := writer.Write(want)
	assert.Nil(t, err)
	assert.Nil(t, writer.Close())
	res, err := decompress(buf.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, want, res)
	for _, data := range [][]byte{nil, []byte("invalid"), buf.Bytes()[:len(buf.Bytes())-4]} {
		res, err := decompress(data)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

type geoIPCoreC struct {
	rcorev1.ResourceServiceClient
	err error
}

func (c *geoIPCoreC) GetSecret(ctx context.Context, req *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Secret, error) {
	return &corev1.Secret{Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "test-secret"}}}, c.err
}

func (c *geoIPCoreC) GetConfig(ctx context.Context, req *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Config, error) {
	return &corev1.Config{Metadata: &metav1.Metadata{Name: req.Name}}, c.err
}

type geoIPOcteliumC struct {
	octeliumc.ClientInterface
	c *geoIPCoreC
}

func (c *geoIPOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.c
}

func TestControllerConfigErrors(t *testing.T) {
	ctx := context.Background()
	c := &geoIPCoreC{}
	ctl, err := New(ctx, &Opts{OcteliumC: &geoIPOcteliumC{c: c}, ConfigName: "selected"})
	assert.Nil(t, err)
	assert.Nil(t, ctl.Close())
	assert.Nil(t, ctl.ResolveStr("invalid"))
	assert.Nil(t, ctl.setConfig(ctx, nil))
	assert.Nil(t, ctl.setConfig(ctx, &corev1.Config{}))
	assert.Nil(t, ctl.setConfig(ctx, &corev1.Config{Metadata: &metav1.Metadata{Name: "other"}}))
	assert.NotNil(t, ctl.setConfig(ctx, &corev1.Config{Metadata: &metav1.Metadata{Name: "selected"}}))
	assert.NotNil(t, ctl.SetConfig(ctx, &corev1.Config{Metadata: &metav1.Metadata{Name: "new-selected"}}))
	assert.Equal(t, "new-selected", ctl.name)
	c.err = fmt.Errorf("config unavailable")
	err = ctl.Set(ctx, &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_FromConfig{FromConfig: "selected"}})
	assert.ErrorIs(t, err, c.err)
	assert.Nil(t, ctl.Set(ctx, nil))
	assert.Empty(t, ctl.name)
	assert.Nil(t, ctl.Set(ctx, &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{}))
}

func TestUpstreamAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth map[string]any
	}{
		{"Basic", map[string]any{"basic": map[string]any{"username": "user", "password": map[string]any{"fromSecret": "password"}}}},
		{"Bearer", map[string]any{"bearer": map[string]any{"fromSecret": "password"}}},
		{"Custom", map[string]any{"custom": map[string]any{"header": "X-Secret", "value": map[string]any{"fromSecret": "password"}}}},
		{"Query", map[string]any{"query": map[string]any{"key": "secret", "value": map[string]any{"fromSecret": "password"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				switch tc.name {
				case "Basic":
					user, password, ok := req.BasicAuth()
					assert.True(t, ok)
					assert.Equal(t, "user", user)
					assert.Equal(t, "test-secret", password)
				case "Bearer":
					assert.Equal(t, "Bearer test-secret", req.Header.Get("Authorization"))
				case "Custom":
					assert.Equal(t, "test-secret", req.Header.Get("X-Secret"))
				case "Query":
					assert.Equal(t, "test-secret", req.URL.Query().Get("secret"))
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			t.Cleanup(srv.Close)
			c := &geoIPCoreC{}
			ctl, err := New(context.Background(), &Opts{OcteliumC: &geoIPOcteliumC{c: c}})
			assert.Nil(t, err)
			upstream := &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream{}
			err = pbutils.UnmarshalFromMap(map[string]any{"url": srv.URL, "auth": tc.auth}, upstream)
			assert.Nil(t, err)
			assert.ErrorContains(t, ctl.setUpstream(context.Background(), upstream), "404")
			assert.EqualValues(t, 1, calls.Load())
			c.err = fmt.Errorf("secret unavailable")
			assert.ErrorIs(t, ctl.setUpstream(context.Background(), upstream), c.err)
			assert.EqualValues(t, 1, calls.Load())
		})
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

	{
		err = ctl.Set(ctx, &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{
			Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_{
				Upstream: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream{
					Url: fmt.Sprintf("%s/GeoIP2-City-Test.mmdb", prefixURL),
				},
			},
		})
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
		ctl.Unset()
		res := ctl.ResolveStr("214.78.120.1")
		assert.Nil(t, res)
		assert.Nil(t, ctl.db)
		assert.Empty(t, ctl.name)
	}

	{
		err = ctl.Run(ctx)
		assert.Nil(t, err)

		cfg, err := fakeC.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{
			Name: cfg.Metadata.Name,
		})
		assert.Nil(t, err)

		err = ctl.SetConfig(ctx, cfg)
		assert.Nil(t, err)

		res := ctl.ResolveStr("214.78.120.1")
		assert.NotNil(t, res)
		assert.Nil(t, res.City)

		cfg.Data = &corev1.Config_Data{
			Type: &corev1.Config_Data_ValueBytes{
				ValueBytes: getDB("GeoIP2-City-Test.mmdb"),
			},
		}

		cfg, err = fakeC.OcteliumC.CoreC().UpdateConfig(ctx, cfg)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		{
			res := ctl.ResolveStr("214.78.120.1")
			assert.NotNil(t, res)
			assert.NotNil(t, res.City)
		}
	}
}
