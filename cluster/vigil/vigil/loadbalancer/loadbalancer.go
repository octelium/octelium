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

package loadbalancer

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type LBManager struct {
	octeliumC octeliumc.ClientInterface

	cache  *cache
	vCache *vcache.Cache
}

func NewLbManager(octeliumC octeliumc.ClientInterface, vCache *vcache.Cache) *LBManager {
	return &LBManager{
		octeliumC: octeliumC,
		cache:     newCache(),
		vCache:    vCache,
	}
}

type Upstream struct {
	HostPort string
	URL      *url.URL
	IsUser   bool
	SNIHost  string
	Host     string
	Port     int

	IsESSH           bool
	Ed25519PublicKey []byte
	SessionRef       *metav1.ObjectReference
}

var ErrNoUpstream = errors.Errorf("No upstreams found")

func (l *LBManager) getUpstreamFromSvc(ctx context.Context,
	svc *corev1.Service, cfg *corev1.Service_Spec_Config) (*Upstream, error) {

	upstrs := ucorev1.ToService(svc).GetAllUpstreamEndpointsByConfig(cfg)
	if len(upstrs) == 0 {
		return nil, ErrNoUpstream
	}

	u := upstrs[utilrand.GetRandomRangeMath(0, len(upstrs)-1)]

	murl, err := url.Parse(u.Url)
	if err != nil {
		return nil, err
	}
	url := &url.URL{
		Scheme: murl.Scheme,
		Host:   murl.Host,
	}

	if u.User == "" {
		return &Upstream{
			HostPort: net.JoinHostPort(url.Hostname(), fmt.Sprintf("%d", ucorev1.EndpointRealPort(u))),
			Host:     url.Hostname(),
			Port:     ucorev1.EndpointRealPort(u),
			SNIHost:  getSNIHost(url.Hostname()),
			URL:      url,
		}, nil
	}

	sess := l.cache.getByUserName(u.User, svc)
	if sess == nil {
		return nil, ErrNoUpstream
	}

	upstream := ucorev1.ToService(svc).GetSessionUpstream(ucorev1.ToSession(sess))
	if upstream == nil {
		return nil, ErrNoUpstream
	}

	conn := sess.Status.Connection

	if len(conn.Addresses) == 0 {
		zap.L().Warn("Connection has no addrs", zap.Any("sess", sess))
		return nil, ErrNoUpstream
	}

	connAddr := umetav1.ToDualStackNetwork(conn.Addresses[0]).ToIP()

	var host string
	switch {
	case ucorev1.ToSession(sess).HasV6():
		host = connAddr.Ipv6
	case ucorev1.ToSession(sess).HasV4():
		host = connAddr.Ipv4
	}

	port := int(upstream.Port)

	ret := &Upstream{
		HostPort:         net.JoinHostPort(host, fmt.Sprintf("%d", port)),
		Host:             host,
		Port:             port,
		IsUser:           true,
		SNIHost:          getSNIHost(url.Hostname()),
		IsESSH:           ucorev1.ToService(svc).IsESSH(),
		Ed25519PublicKey: conn.Ed25519PublicKey,
		SessionRef:       umetav1.GetObjectReference(sess),
		URL:              url,
	}

	return ret, nil
}

func (l *LBManager) GetUpstream(ctx context.Context, authResp *coctovigilv1.AuthenticateAndAuthorizeResponse) (*Upstream, error) {

	if authResp == nil || authResp.RequestContext == nil || authResp.RequestContext.Service == nil {
		return nil, ErrNoUpstream
	}

	return l.getUpstreamFromSvc(ctx, authResp.RequestContext.Service, vigilutils.GetServiceConfig(ctx, authResp))
}

func getSNIHost(arg string) string {
	if govalidator.IsIP(arg) {
		return ""
	}
	return arg
}

func (c *LBManager) onAdd(ctx context.Context, sess *corev1.Session) error {

	svc := c.vCache.GetService()

	if ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(sess)) {
		c.cache.setSession(sess)
	}

	return nil
}

func (c *LBManager) OnUpdate(ctx context.Context, new, old *corev1.Session) error {

	return c.onSessionUpdate(ctx, new, old)
}

func (c *LBManager) onDelete(ctx context.Context, sess *corev1.Session) error {

	c.cache.deleteSession(sess)

	return nil
}

func (s *LBManager) onSessionUpdate(ctx context.Context, new, old *corev1.Session) error {
	svc := s.vCache.GetService()
	if pbutils.IsEqual(new.Status.Connection, old.Status.Connection) {
		// zap.L().Debug("No need to change lb upstreams", zap.String("sessUID", new.Metadata.Uid))
		return nil
	}

	switch {
	case ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(new)):
		s.cache.setSession(new)
	case !ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(new)) &&
		ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(old)):
		s.cache.deleteSession(new)
	default:
		// zap.L().Debug("No need to use lbManager for sess update", zap.String("sessUID", new.Metadata.Uid))
	}

	return nil
}

func (s *LBManager) Run(ctx context.Context) error {

	if err := watchers.NewCoreV1(s.octeliumC).Session(ctx, nil,
		s.onAdd, s.onSessionUpdate, s.onDelete); err != nil {
		return err
	}

	return nil
}

func (c *LBManager) SetSession(sess *corev1.Session) {
	svc := c.vCache.GetService()

	if ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(sess)) {
		c.cache.setSession(sess)
	}
}

func (c *LBManager) DeleteSession(sess *corev1.Session) {
	c.cache.deleteSession(sess)
}
