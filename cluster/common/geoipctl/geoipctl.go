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
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/oschwald/geoip2-golang/v2"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Opts struct {
	ConfigName string
	OcteliumC  octeliumc.ClientInterface
}

type Controller struct {
	octeliumC octeliumc.ClientInterface
	mu        sync.RWMutex
	db        *geoip2.Reader
	name      string
}

func New(ctx context.Context, o *Opts) (*Controller, error) {
	ret := &Controller{
		octeliumC: o.OcteliumC,
		name:      o.ConfigName,
	}

	return ret, nil
}

func (c *Controller) Run(ctx context.Context) error {

	if c.name != "" {
		if cfg, err := c.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{
			Name: c.name,
		}); err == nil {
			if err := c.setConfig(ctx, cfg); err != nil {
				zap.L().Warn("Could not set mmdb config",
					zap.Error(err), zap.String("config", cfg.Metadata.Name))
			}
		}
	}

	if err := watchers.NewCoreV1(c.octeliumC).Config(ctx, nil,
		func(ctx context.Context, item *corev1.Config) error {
			return c.setConfig(ctx, item)
		}, func(ctx context.Context, new, old *corev1.Config) error {
			return c.setConfig(ctx, new)
		}, func(ctx context.Context, item *corev1.Config) error {
			c.mu.Lock()
			if item.Metadata.Name == c.name {
				c.db = nil
			}
			c.mu.Unlock()
			return nil
		}); err != nil {
		return err
	}

	return nil
}

func (c *Controller) setConfig(ctx context.Context, cfg *corev1.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.doSetConfig(ctx, cfg)
}

func (c *Controller) doSetConfig(_ context.Context, cfg *corev1.Config) error {

	var err error

	if cfg == nil || cfg.Metadata == nil || cfg.Metadata.Name != c.name {
		return nil
	}

	if cfg.Data == nil || len(cfg.Data.GetValueBytes()) == 0 {
		return errors.Errorf("Could not find config content")
	}

	c.db, err = geoip2.OpenBytes(cfg.Data.GetValueBytes())
	if err != nil {
		return err
	}

	zap.L().Debug("Loaded MMDB", zap.Any("metadata", c.db.Metadata()))

	return nil
}

func (c *Controller) Close() error {
	return c.db.Close()
}

func (c *Controller) Resolve(addr netip.Addr) *corev1.GeoIP {

	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.db == nil {
		return nil
	}

	ret := &corev1.GeoIP{
		Ip: addr.String(),
		IpVersion: func() corev1.GeoIP_IPVersion {
			switch {
			case addr.Is6():
				return corev1.GeoIP_V6
			case addr.Is4():
				return corev1.GeoIP_V4
			default:
				return corev1.GeoIP_IP_VERSION_UNKNOWN
			}
		}(),
	}

	if val, err := c.db.Enterprise(addr); err == nil && val.HasData() {
		zap.L().Debug("Found mmdb enterprise entry", zap.Any("val", val))
		if val.Country.HasData() {
			ret.Country = &corev1.GeoIP_Country{
				Name: val.Country.Names.English,
				Code: val.Country.ISOCode,
			}
		}

		if val.City.HasData() {
			ret.City = &corev1.GeoIP_City{
				Name: val.City.Names.English,
			}
		}

		if val.Continent.HasData() {
			ret.Continent = &corev1.GeoIP_Continent{
				Name: val.Continent.Names.English,
				Code: val.Continent.Code,
			}
		}

		if val.Postal.HasData() {
			ret.PostalCode = val.Postal.Code
		}

		if val.Location.HasData() {
			ret.Timezone = &corev1.GeoIP_Timezone{
				Id: val.Location.TimeZone,
			}
		}

		if val.Location.HasCoordinates() {
			ret.Coordinates = &corev1.GeoIP_Coordinates{
				Latitude:       *val.Location.Latitude,
				Longitude:      *val.Location.Longitude,
				AccuracyRadius: float64(val.Location.AccuracyRadius),
			}
		}

		if val.Traits.HasData() {
			ret.Network = &corev1.GeoIP_Network{
				Asn:          int64(val.Traits.AutonomousSystemNumber),
				Organization: val.Traits.Organization,
				Domain:       val.Traits.Domain,
				Isp:          val.Traits.ISP,
			}
		}
	} else if val, err := c.db.City(addr); err == nil && val.HasData() {
		zap.L().Debug("Found mmdb city entry", zap.Any("val", val))
		if val.Country.HasData() {
			ret.Country = &corev1.GeoIP_Country{
				Name: val.Country.Names.English,
				Code: val.Country.ISOCode,
			}
		}

		if val.City.HasData() {
			ret.City = &corev1.GeoIP_City{
				Name: val.City.Names.English,
			}
		}

		if val.Continent.HasData() {
			ret.Continent = &corev1.GeoIP_Continent{
				Name: val.Continent.Names.English,
				Code: val.Continent.Code,
			}
		}

		if val.Postal.HasData() {
			ret.PostalCode = val.Postal.Code
		}

		if val.Location.HasData() {
			ret.Timezone = &corev1.GeoIP_Timezone{
				Id: val.Location.TimeZone,
			}

		}

		if val.Location.HasCoordinates() {
			ret.Coordinates = &corev1.GeoIP_Coordinates{
				Latitude:       *val.Location.Latitude,
				Longitude:      *val.Location.Longitude,
				AccuracyRadius: float64(val.Location.AccuracyRadius),
			}
		}

	} else if val, err := c.db.Country(addr); err == nil && val.HasData() {
		zap.L().Debug("Found mmdb country entry", zap.Any("val", val))
		if val.Country.HasData() {
			ret.Country = &corev1.GeoIP_Country{
				Name: val.Country.Names.English,
				Code: val.Country.ISOCode,
			}
		}

		if val.Continent.HasData() {
			ret.Continent = &corev1.GeoIP_Continent{
				Name: val.Continent.Names.English,
				Code: val.Continent.Code,
			}
		}
	}

	return ret
}

func (c *Controller) ResolveStr(addrStr string) *corev1.GeoIP {
	if addr, err := netip.ParseAddr(addrStr); err == nil {
		return c.Resolve(addr)
	}
	return nil
}

func (c *Controller) SetConfig(ctx context.Context, cfg *corev1.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.name = cfg.Metadata.Name
	return c.doSetConfig(ctx, cfg)
}

func (c *Controller) Unset() {
	c.mu.Lock()
	c.name = ""
	c.db = nil
	c.mu.Unlock()
}

func (c *Controller) Set(ctx context.Context, cfg *corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB) error {
	if cfg == nil {
		c.Unset()
		return nil
	}

	switch cfg.Type.(type) {
	case *corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_FromConfig:
		res, err := c.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{
			Name: cfg.GetFromConfig(),
		})
		if err != nil {
			return err
		}
		return c.setConfig(ctx, res)
	case *corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_:
		return c.setUpstream(ctx, cfg.GetUpstream())
	default:
		c.Unset()
	}

	return nil
}

func (c *Controller) setUpstream(ctx context.Context,
	upstream *corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream) error {
	httpC := resty.New().SetRetryCount(20).
		SetRetryWaitTime(500 * time.Millisecond).SetRetryMaxWaitTime(2 * time.Second).
		AddRetryCondition(func(r *resty.Response, err error) bool {
			if r.StatusCode() >= 500 && r.StatusCode() < 600 {
				return true
			}
			return false
		}).
		AddRetryHook(func(r *resty.Response, err error) {
			zap.L().Debug("Retrying....", zap.Error(err))
		}).SetTimeout(100 * time.Second).SetLogger(zap.S())

	resp, err := httpC.R().SetContext(ctx).Get(upstream.Url)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return errors.Errorf("fetching mmdb is not successful: status code: %d", resp.StatusCode())
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	body := resp.Body()
	contentType := resp.Header().Get("Content-Type")
	var mmdbBytes []byte

	switch {
	case strings.HasSuffix(resp.Request.RawRequest.URL.Path, ".gz") ||
		strings.HasSuffix(resp.Request.RawRequest.URL.Path, ".gzip") ||
		strings.Contains(contentType, "gzip"):
		mmdbBytes, err = decompress(body)
		if err != nil {
			mmdbBytes = body
		}
	default:
		mmdbBytes = body
	}

	c.db, err = geoip2.OpenBytes(mmdbBytes)
	if err != nil {
		return err
	}

	return nil
}

func decompress(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(io.Reader(bytes.NewReader(data)))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	return io.ReadAll(gr)
}
