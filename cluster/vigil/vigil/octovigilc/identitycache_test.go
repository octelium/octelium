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

package octovigilc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/octovigilc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/octovigil/octovigil"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestIdentityCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &identityCache{}
		now := time.Now()
		assert.Nil(t, c.get(1, now))
		assert.Zero(t, c.len())

		i := &identity{fingerprint: []byte("fingerprint"), expiresAt: now.Add(identityCacheTTL)}
		c.set(1, i, now)
		assert.Same(t, i, c.get(1, now))
		assert.Nil(t, c.get(2, now))
		assert.Equal(t, []byte("fingerprint"), c.get(1, now).getFingerprint())
		assert.Nil(t, c.get(2, now).getFingerprint())

		time.Sleep(identityCacheTTL - time.Nanosecond)
		assert.Same(t, i, c.get(1, time.Now()))
		time.Sleep(time.Nanosecond)
		assert.Nil(t, c.get(1, time.Now()))
		assert.Equal(t, 1, c.len())

		j := &identity{expiresAt: time.Now().Add(identityCacheTTL)}
		c.set(1, j, time.Now())
		assert.Same(t, j, c.get(1, time.Now()))
		assert.Equal(t, 1, c.len())
	})
}

func TestIdentityCacheEviction(t *testing.T) {
	now := time.Now()
	c := &identityCache{}
	for key := range uint64(identityCacheMaxEntries) {
		c.set(key, &identity{expiresAt: now.Add(identityCacheTTL)}, now)
	}
	assert.Equal(t, identityCacheMaxEntries, c.len())

	replaced := &identity{expiresAt: now.Add(identityCacheTTL)}
	c.set(0, replaced, now)
	assert.Equal(t, identityCacheMaxEntries, c.len())
	assert.Same(t, replaced, c.get(0, now))

	for key := uint64(identityCacheMaxEntries); key < 2*identityCacheMaxEntries; key++ {
		i := &identity{expiresAt: now.Add(identityCacheTTL)}
		c.set(key, i, now)
		assert.Equal(t, identityCacheMaxEntries, c.len())
		assert.Same(t, i, c.get(key, now))
	}

	c = &identityCache{}
	for key := range uint64(identityCacheMaxEntries) {
		expiresAt := now.Add(identityCacheTTL)
		if key%2 == 0 {
			expiresAt = now
		}
		c.set(key, &identity{expiresAt: expiresAt}, now)
	}
	for key := uint64(identityCacheMaxEntries); key < identityCacheMaxEntries+identityCacheMaxEntries/4; key++ {
		c.set(key, &identity{expiresAt: now.Add(identityCacheTTL)}, now)
	}
	assert.Equal(t, identityCacheMaxEntries, c.len())
	var fresh int
	for key := range uint64(identityCacheMaxEntries) {
		if key%2 == 1 && c.get(key, now) != nil {
			fresh++
		}
	}
	assert.Greater(t, fresh, identityCacheMaxEntries/2-identityCacheMaxEntries/16)
}

func TestGetAccessToken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
		token   string
	}{
		{"Nil", nil, ""},
		{"Empty", map[string]string{}, ""},
		{"Custom", map[string]string{"x-octelium-auth": "custom"}, "custom"},
		{"CustomFirst", map[string]string{"x-octelium-auth": "custom", "cookie": "octelium_auth=cookie", "authorization": "Bearer bearer"}, "custom"},
		{"EmptyCustom", map[string]string{"x-octelium-auth": "", "cookie": "octelium_auth=cookie"}, "cookie"},
		{"Cookie", map[string]string{"cookie": "other=value; octelium_auth=cookie; final=value"}, "cookie"},
		{"QuotedCookie", map[string]string{"cookie": `octelium_auth="cookie"`}, "cookie"},
		{"CookieFirst", map[string]string{"cookie": "octelium_auth=cookie", "authorization": "Bearer bearer"}, "cookie"},
		{"EmptyCookie", map[string]string{"cookie": "octelium_auth=", "authorization": "Bearer bearer"}, "bearer"},
		{"UnrelatedCookie", map[string]string{"cookie": "other=value", "authorization": "Bearer bearer"}, "bearer"},
		{"Bearer", map[string]string{"authorization": "Bearer bearer"}, "bearer"},
		{"EmptyBearer", map[string]string{"authorization": "Bearer "}, ""},
		{"BearerWhitespace", map[string]string{"authorization": "Bearer  token "}, " token "},
		{"MissingBearerSpace", map[string]string{"authorization": "Bearer"}, ""},
		{"Basic", map[string]string{"authorization": "Basic dXNlcjpwYXNz"}, ""},
		{"LowercaseScheme", map[string]string{"authorization": "bearer token"}, ""},
		{"DifferentCookieName", map[string]string{"cookie": "octelium_auth_extra=token"}, ""},
		{"InvalidCookie", map[string]string{"cookie": "octelium_auth=bad\x00token"}, ""},
		{"CaseSensitiveHeader", map[string]string{"Authorization": "Bearer token"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.token, getAccessToken(tc.headers))
		})
	}
}

func TestSetClusterNetwork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cc      *corev1.ClusterConfig
		isErr   bool
		clients []string
	}{
		{"NilConfig", nil, false, nil},
		{"NilStatus", &corev1.ClusterConfig{}, false, nil},
		{"NilNetwork", &corev1.ClusterConfig{Status: &corev1.ClusterConfig_Status{}}, false, nil},
		{"NilClusterNetwork", &corev1.ClusterConfig{Status: &corev1.ClusterConfig_Status{
			Network: &corev1.ClusterConfig_Status_Network{},
		}}, false, nil},
		{"Empty", newTestClusterConfig("", ""), false, nil},
		{"V4", newTestClusterConfig("10.0.0.0/16", ""), false, []string{"10.0.0.0", "10.0.0.1", "10.0.255.255"}},
		{"V6", newTestClusterConfig("", "fd00::/64"), false, []string{"fd00::", "fd00::1", "fd00::ffff:ffff:ffff:ffff"}},
		{"DualStack", newTestClusterConfig("10.0.0.0/16", "fd00::/64"), false,
			[]string{"10.0.0.0", "10.0.0.1", "10.0.255.255", "fd00::", "fd00::1", "fd00::ffff:ffff:ffff:ffff"}},
		{"InvalidV4", newTestClusterConfig("10.0.0.1", "fd00::/64"), true, nil},
		{"InvalidV6", newTestClusterConfig("10.0.0.0/16", "fd00::/129"), true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{}
			err := c.setClusterNetwork(tc.cc)
			if tc.isErr {
				assert.NotNil(t, err)
				return
			}
			assert.Nil(t, err)

			for _, address := range []string{
				"10.0.0.0", "10.0.0.1", "10.0.255.255", "10.1.0.1", "9.255.255.255",
				"fd00::", "fd00::1", "fd00::ffff:ffff:ffff:ffff", "fd00:0:0:1::1", "fc00::1",
				"::ffff:10.0.0.1", "10.0.0.1:1234", "[fd00::1]", "", "invalid",
			} {
				assert.Equal(t, slices.Contains(tc.clients, address), c.isAddressFromClient(address), address)
			}
		})
	}
}

func TestGetIdentityCacheKey(t *testing.T) {
	newRequest := func(address string, headers map[string]string) *coctovigilv1.DownstreamRequest {
		return &coctovigilv1.DownstreamRequest{
			Source: &coctovigilv1.DownstreamRequest_Source{Address: address, Port: 1234},
			Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
				Http: &corev1.RequestContext_Request_HTTP{Path: "/", Headers: headers},
			}},
		}
	}
	newGRPCRequest := func(address string, headers map[string]string) *coctovigilv1.DownstreamRequest {
		return &coctovigilv1.DownstreamRequest{
			Source: &coctovigilv1.DownstreamRequest_Source{Address: address, Port: 5678},
			Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Grpc{
				Grpc: &corev1.RequestContext_Request_GRPC{Http: &corev1.RequestContext_Request_HTTP{
					Path: "/pkg.Service/Method", Headers: headers,
				}},
			}},
		}
	}

	c := newTestIdentityClient(nil)
	assertKey := func(want uint64, wantToken string, reqs ...*coctovigilv1.DownstreamRequest) {
		t.Helper()
		for _, req := range reqs {
			key, accessToken := c.getIdentityCacheKey(req)
			assert.Equal(t, want, key, "%v", req)
			assert.Equal(t, wantToken, accessToken, "%v", req)
		}
	}

	client, accessToken := c.getIdentityCacheKey(newRequest("10.0.0.1", nil))
	assert.Empty(t, accessToken)
	assertKey(client, "",
		newRequest("10.0.0.1", map[string]string{}),
		newRequest("10.0.0.1", map[string]string{"authorization": "Bearer application"}),
		newRequest("10.0.0.1", map[string]string{"authorization": "Bearer other"}),
		newRequest("10.0.0.1", map[string]string{"x-octelium-auth": "token"}),
		newRequest("10.0.0.1", map[string]string{"cookie": "a=b; octelium_auth=token"}),
		newGRPCRequest("10.0.0.1", map[string]string{"authorization": "Bearer application"}),
		&coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "10.0.0.1"}},
		&coctovigilv1.DownstreamRequest{
			Source: &coctovigilv1.DownstreamRequest_Source{Address: "10.0.0.1"},
			Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Postgres_{
				Postgres: &corev1.RequestContext_Request_Postgres{},
			}},
		},
	)

	clientV6, accessToken := c.getIdentityCacheKey(newRequest("fd00::1", nil))
	assert.Empty(t, accessToken)
	assertKey(clientV6, "",
		newRequest("fd00::1", map[string]string{"authorization": "Bearer application"}),
		newGRPCRequest("fd00::1", map[string]string{"x-octelium-auth": "token"}),
	)

	token, accessToken := c.getIdentityCacheKey(newRequest("192.0.2.1", map[string]string{"x-octelium-auth": "token"}))
	assert.Equal(t, "token", accessToken)
	assertKey(token, "token",
		newRequest("192.0.2.1", map[string]string{"cookie": "a=b; octelium_auth=token"}),
		newRequest("192.0.2.1", map[string]string{"authorization": "Bearer token"}),
		newRequest("192.0.2.1", map[string]string{"x-octelium-auth": "token", "x-other": "value", "cookie": "a=b"}),
		newRequest("192.0.2.2", map[string]string{"x-octelium-auth": "token"}),
		newRequest("10.1.0.1", map[string]string{"x-octelium-auth": "token"}),
		newRequest("fd00:0:0:1::1", map[string]string{"x-octelium-auth": "token"}),
		newRequest("::ffff:10.0.0.1", map[string]string{"x-octelium-auth": "token"}),
		newRequest("", map[string]string{"x-octelium-auth": "token"}),
		newRequest("invalid", map[string]string{"x-octelium-auth": "token"}),
		newGRPCRequest("192.0.2.3", map[string]string{"x-octelium-auth": "token"}),
	)

	noToken, accessToken := c.getIdentityCacheKey(newRequest("192.0.2.1", nil))
	assert.Empty(t, accessToken)
	assertKey(noToken, "",
		newRequest("192.0.2.1", map[string]string{"cookie": "a=b", "authorization": "Basic dXNlcjpwYXNz"}),
		newRequest("192.0.2.2", nil),
		nil,
		&coctovigilv1.DownstreamRequest{},
		&coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "192.0.2.1"}},
	)

	keys := map[uint64]string{client: "Client", clientV6: "ClientV6", token: "Token", noToken: "NoToken"}
	for name, req := range map[string]*coctovigilv1.DownstreamRequest{
		"OtherClient":                  newRequest("10.0.0.2", map[string]string{"x-octelium-auth": "token"}),
		"OtherClientV6":                newRequest("fd00::2", nil),
		"OtherToken":                   newRequest("192.0.2.1", map[string]string{"x-octelium-auth": "other"}),
		"ClientAddressAsToken":         newRequest("192.0.2.1", map[string]string{"x-octelium-auth": "10.0.0.1"}),
		"PrefixedClientAddressAsToken": newRequest("192.0.2.1", map[string]string{"x-octelium-auth": "\x0110.0.0.1"}),
		"ClientAddressAndToken":        newRequest("10.0.0.4", map[string]string{"x-octelium-auth": "token"}),
	} {
		key, _ := c.getIdentityCacheKey(req)
		prev, ok := keys[key]
		assert.False(t, ok, "%s has the key of %s", name, prev)
		keys[key] = name
	}

	unconfigured := &Client{}
	key, accessToken := unconfigured.getIdentityCacheKey(newRequest("10.0.0.1", map[string]string{"x-octelium-auth": "token"}))
	assert.Equal(t, token, key)
	assert.Equal(t, "token", accessToken)
	key, accessToken = unconfigured.getIdentityCacheKey(newRequest("10.0.0.1", nil))
	assert.Equal(t, noToken, key)
	assert.Empty(t, accessToken)
}

type tstIdentityServer struct {
	mu         sync.Mutex
	isLegacy   bool
	identities map[string]*corev1.RequestContext
	sent       []*coctovigilv1.AuthenticateAndAuthorizeRequest
	full       []*coctovigilv1.AuthenticateAndAuthorizeResponse
	byID       map[string]*coctovigilv1.AuthenticateAndAuthorizeResponse
	omitted    int
	override   func(*coctovigilv1.AuthenticateAndAuthorizeResponse)
}

func getTestIdentityFingerprint(i *corev1.RequestContext) []byte {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(&corev1.RequestContext{
		Session: i.Session, User: i.User, Groups: i.Groups, Device: i.Device, Namespace: i.Namespace,
	})
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

func (s *tstIdentityServer) authenticate(ctx context.Context, in *coctovigilv1.AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sent = append(s.sent, pbutils.Clone(in).(*coctovigilv1.AuthenticateAndAuthorizeRequest))
	ret := &coctovigilv1.AuthenticateAndAuthorizeResponse{}
	identity := s.identities[getTestIdentityKey(in.Request)]
	if identity != nil {
		ret.IsAuthenticated = true
		ret.IsAuthorized = true
		ret.ServiceConfigName = "named"
		ret.RequestContext = pbutils.Clone(identity).(*corev1.RequestContext)
		if !in.OmitRequest {
			ret.RequestContext.Request = in.Request.GetRequest()
		}
	}
	s.full = append(s.full, pbutils.Clone(ret).(*coctovigilv1.AuthenticateAndAuthorizeResponse))
	if id := in.Request.GetRequest().GetHttp().GetHeaders()["x-request-id"]; id != "" {
		if s.byID == nil {
			s.byID = make(map[string]*coctovigilv1.AuthenticateAndAuthorizeResponse)
		}
		s.byID[id] = s.full[len(s.full)-1]
	}

	if !s.isLegacy && in.OmitUnchangedIdentity && identity != nil && identity.Session != nil {
		ret.IdentityFingerprint = getTestIdentityFingerprint(identity)
		if bytes.Equal(ret.IdentityFingerprint, in.IdentityFingerprint) {
			ret.RequestContext.Session = nil
			ret.RequestContext.User = nil
			ret.RequestContext.Groups = nil
			ret.RequestContext.Device = nil
			ret.RequestContext.Namespace = nil
			ret.IsIdentityOmitted = true
			s.omitted++
		}
	}
	if s.override != nil {
		s.override(ret)
	}

	return pbutils.Clone(ret).(*coctovigilv1.AuthenticateAndAuthorizeResponse), nil
}

func (s *tstIdentityServer) setIdentity(key string, i *corev1.RequestContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[key] = i
}

func (s *tstIdentityServer) last() (*coctovigilv1.AuthenticateAndAuthorizeRequest, *coctovigilv1.AuthenticateAndAuthorizeResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent[len(s.sent)-1], s.full[len(s.full)-1]
}

func newTestIdentity(name string, version int) *corev1.RequestContext {
	rv := fmt.Sprintf("%s-%d", name, version)
	return &corev1.RequestContext{
		Session: &corev1.Session{Metadata: &metav1.Metadata{Uid: name + "-session", ResourceVersion: rv}},
		User:    &corev1.User{Metadata: &metav1.Metadata{Uid: name + "-user", ResourceVersion: rv}, Spec: &corev1.User_Spec{Groups: []string{"g1", "g2"}}},
		Groups: []*corev1.Group{
			{Metadata: &metav1.Metadata{Uid: "g1", ResourceVersion: rv}},
			{Metadata: &metav1.Metadata{Uid: "g2", ResourceVersion: rv}},
		},
		Device:    &corev1.Device{Metadata: &metav1.Metadata{Uid: name + "-device", ResourceVersion: rv}},
		Namespace: &corev1.Namespace{Metadata: &metav1.Metadata{Uid: "namespace", ResourceVersion: rv}},
	}
}

func newTestClusterConfig(v4, v6 string) *corev1.ClusterConfig {
	return &corev1.ClusterConfig{Status: &corev1.ClusterConfig_Status{
		Network: &corev1.ClusterConfig_Status_Network{
			ClusterNetwork: &metav1.DualStackNetwork{V4: v4, V6: v6},
		},
	}}
}

func newTestIdentityClient(internalC coctovigilv1.InternalServiceClient) *Client {
	c := &Client{svcUID: "service", remoteC: &tstRemoteC{internalC: internalC}}
	if err := c.setClusterNetwork(newTestClusterConfig("10.0.0.0/16", "fd00::/64")); err != nil {
		panic(err)
	}
	return c
}

func getTestIdentityKey(req *coctovigilv1.DownstreamRequest) string {
	if addr, err := netip.ParseAddr(req.GetSource().GetAddress()); err == nil &&
		(netip.MustParsePrefix("10.0.0.0/16").Contains(addr) || netip.MustParsePrefix("fd00::/64").Contains(addr)) {
		return req.GetSource().GetAddress() + "/"
	}
	return "/" + getAccessToken(req.GetRequest().GetHttp().GetHeaders())
}

func newTestToken(name string) string {
	sum := sha256.Sum256([]byte(name))
	b, err := pbutils.Marshal(&authv1.TokenT0{
		Signature: append(sum[:], sum[:]...),
		Content: &authv1.TokenT0_Content{
			Type:    authv1.TokenT0_Content_ACCESS_TOKEN,
			KeyID:   sum[:16],
			Subject: sum[16:],
			TokenID: sum[8:24],
		},
	})
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(append([]byte{0x1}, b...))
}

func newTestTokenAlias(token string, i int) string {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		panic(err)
	}
	b = protowire.AppendVarint(protowire.AppendTag(b, 15, protowire.VarintType), uint64(i))
	return base64.RawURLEncoding.EncodeToString(b)
}

func newTestIdentityRequest(address, token string) *AuthenticateAndAuthorizeRequest {
	headers := map[string]string{"x-tenant": "tenant"}
	if token != "" {
		headers["authorization"] = "Bearer " + token
	}
	return &AuthenticateAndAuthorizeRequest{
		Request: &coctovigilv1.DownstreamRequest{
			Source: &coctovigilv1.DownstreamRequest_Source{Address: address, Port: 1234},
			Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
				Http: &corev1.RequestContext_Request_HTTP{Path: "/", Headers: headers},
			}},
		},
		Service: &corev1.Service{Metadata: &metav1.Metadata{Uid: "service", ResourceVersion: "service-rv"}},
	}
}

func TestRemoteIdentity(t *testing.T) {
	tokenA, tokenB := newTestToken("a"), newTestToken("b")
	for _, isLegacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("Legacy%t", isLegacy), func(t *testing.T) {
			srv := &tstIdentityServer{isLegacy: isLegacy, identities: map[string]*corev1.RequestContext{
				"10.0.0.1/":  newTestIdentity("client", 1),
				"10.0.0.2/":  newTestIdentity("other", 1),
				"fd00::1/":   newTestIdentity("v6", 1),
				"/" + tokenA: newTestIdentity("tokenA", 1),
				"/" + tokenB: newTestIdentity("tokenB", 1),
				"10.0.0.3/":  {Namespace: newTestIdentity("anonymous", 1).Namespace},
				"/none":      nil,
			}}
			c := newTestIdentityClient(&tstInternalErrC{authenticate: srv.authenticate})

			prevResps := make(map[string]*coctovigilv1.AuthenticateAndAuthorizeResponse)
			do := func(address, token string, isOmitted bool, fingerprint []byte) *coctovigilv1.AuthenticateAndAuthorizeResponse {
				t.Helper()
				req := newTestIdentityRequest(address, token)
				orig := pbutils.Clone(req.Request).(*coctovigilv1.DownstreamRequest)
				prevResp := prevResps[getTestIdentityKey(req.Request)]
				omittedBefore := srv.omitted
				resp, err := c.AuthenticateAndAuthorize(t.Context(), req)
				require.Nil(t, err)
				sent, full := srv.last()
				assert.True(t, sent.OmitUnchangedIdentity)
				assert.True(t, sent.OmitRequest)
				assert.Equal(t, fingerprint, sent.IdentityFingerprint)
				assert.Equal(t, isOmitted, srv.omitted == omittedBefore+1)
				assert.Empty(t, resp.IdentityFingerprint)
				assert.False(t, resp.IsIdentityOmitted)
				if full.RequestContext != nil {
					full.RequestContext.Request = orig.Request
					full.RequestContext.Service = req.Service
				}
				assert.True(t, pbutils.IsEqual(full, resp))
				assert.True(t, pbutils.IsEqual(orig, req.Request))
				if resp.RequestContext != nil {
					assert.Same(t, req.Request.Request, resp.RequestContext.Request)
				}
				if isOmitted {
					assert.Same(t, prevResp.RequestContext.Session, resp.RequestContext.Session)
					assert.Same(t, prevResp.RequestContext.User, resp.RequestContext.User)
					assert.Same(t, prevResp.RequestContext.Device, resp.RequestContext.Device)
					assert.Same(t, prevResp.RequestContext.Namespace, resp.RequestContext.Namespace)
					assert.Same(t, prevResp.RequestContext.Groups[0], resp.RequestContext.Groups[0])
					assert.NotSame(t, &prevResp.RequestContext.Groups[0], &resp.RequestContext.Groups[0])
				}
				if resp.RequestContext.GetSession() != nil {
					prevResps[getTestIdentityKey(req.Request)] = resp
				}
				return resp
			}
			fp := func(name string, version int) []byte {
				if isLegacy {
					return nil
				}
				return getTestIdentityFingerprint(newTestIdentity(name, version))
			}

			do("10.0.0.1", "", false, nil)
			do("10.0.0.1", "", !isLegacy, fp("client", 1))
			do("10.0.0.1", "", !isLegacy, fp("client", 1))
			do("10.0.0.1", "application", !isLegacy, fp("client", 1))
			do("10.0.0.1", tokenB, !isLegacy, fp("client", 1))
			do("10.0.0.2", "", false, nil)
			do("10.0.0.2", "", !isLegacy, fp("other", 1))
			do("10.0.0.1", "", !isLegacy, fp("client", 1))
			do("fd00::1", "application", false, nil)
			do("fd00::1", "other", !isLegacy, fp("v6", 1))

			srv.setIdentity("10.0.0.1/", newTestIdentity("client", 2))
			do("10.0.0.1", "", false, fp("client", 1))
			do("10.0.0.1", "", !isLegacy, fp("client", 2))

			srv.setIdentity("10.0.0.1/", newTestIdentity("other", 1))
			do("10.0.0.1", "", false, fp("client", 2))
			do("10.0.0.1", "", !isLegacy, fp("other", 1))

			srv.setIdentity("10.0.0.1/", nil)
			resp := do("10.0.0.1", "", false, fp("other", 1))
			assert.False(t, resp.IsAuthenticated)
			srv.setIdentity("10.0.0.1/", newTestIdentity("other", 1))
			do("10.0.0.1", "", !isLegacy, fp("other", 1))

			do("192.0.2.9", tokenA, false, nil)
			do("192.0.2.9", tokenA, !isLegacy, fp("tokenA", 1))
			do("192.0.2.9", tokenB, false, nil)
			do("192.0.2.9", tokenB, !isLegacy, fp("tokenB", 1))
			do("192.0.2.9", tokenA, !isLegacy, fp("tokenA", 1))
			do("192.0.2.8", tokenA, !isLegacy, fp("tokenA", 1))
			do("10.1.0.1", tokenA, !isLegacy, fp("tokenA", 1))
			do("fd00:0:0:1::1", tokenB, !isLegacy, fp("tokenB", 1))
			do("192.0.2.9", "", false, nil)

			do("10.0.0.3", "", false, nil)
			do("10.0.0.3", "", false, nil)
			do("192.0.2.1", "none", false, nil)
			do("192.0.2.1", "none", false, nil)

			if isLegacy {
				assert.Zero(t, c.identities.len())
			} else {
				assert.Equal(t, 5, c.identities.len())
			}
		})
	}
}

func TestRemoteIdentityTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := &tstIdentityServer{identities: map[string]*corev1.RequestContext{
			"10.0.0.1/": newTestIdentity("client", 1),
		}}
		c := newTestIdentityClient(&tstInternalErrC{authenticate: srv.authenticate})
		fingerprint := getTestIdentityFingerprint(newTestIdentity("client", 1))
		do := func() []byte {
			_, err := c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("10.0.0.1", ""))
			require.Nil(t, err)
			sent, _ := srv.last()
			return sent.IdentityFingerprint
		}

		assert.Nil(t, do())
		time.Sleep(identityCacheTTL - time.Second)
		assert.Equal(t, fingerprint, do())
		time.Sleep(time.Second)
		assert.Nil(t, do())
		assert.Equal(t, fingerprint, do())
		assert.Equal(t, 2, srv.omitted)
	})
}

func TestRemoteIdentityInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		isCached bool
		override func(*coctovigilv1.AuthenticateAndAuthorizeResponse)
	}{
		{"NotCached", false, func(resp *coctovigilv1.AuthenticateAndAuthorizeResponse) {
			resp.IsIdentityOmitted = true
		}},
		{"OtherFingerprint", true, func(resp *coctovigilv1.AuthenticateAndAuthorizeResponse) {
			resp.IdentityFingerprint = []byte("other")
		}},
		{"NoFingerprint", true, func(resp *coctovigilv1.AuthenticateAndAuthorizeResponse) {
			resp.IdentityFingerprint = nil
		}},
		{"NoRequestContext", true, func(resp *coctovigilv1.AuthenticateAndAuthorizeResponse) {
			resp.RequestContext = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &tstIdentityServer{identities: map[string]*corev1.RequestContext{
				"10.0.0.1/": newTestIdentity("client", 1),
			}}
			c := newTestIdentityClient(&tstInternalErrC{authenticate: srv.authenticate})
			if tc.isCached {
				_, err := c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("10.0.0.1", ""))
				require.Nil(t, err)
			}
			srv.override = tc.override
			body := []byte(`{"key":"value"}`)
			req := newTestIdentityRequest("10.0.0.1", "")
			h := req.Request.Request.GetHttp()
			h.Body = body
			h.BodyMap = pbutils.MapToStructMust(map[string]any{"key": "value"})
			resp, err := c.AuthenticateAndAuthorize(t.Context(), req)
			assert.NotNil(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, body, h.Body)
		})
	}

	srv := &tstIdentityServer{identities: map[string]*corev1.RequestContext{
		"10.0.0.1/": newTestIdentity("client", 1),
	}}
	internal := &tstInternalErrC{authenticate: srv.authenticate}
	c := newTestIdentityClient(internal)
	_, err := c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("10.0.0.1", ""))
	require.Nil(t, err)
	key, _ := c.getIdentityCacheKey(newTestIdentityRequest("10.0.0.1", "").Request)
	cached := c.identities.get(key, time.Now())
	require.NotNil(t, cached)
	internal.authenticate = func(ctx context.Context, in *coctovigilv1.AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
		return nil, status.Error(codes.Unavailable, "unavailable")
	}
	_, err = c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("10.0.0.1", ""))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Same(t, cached, c.identities.get(key, time.Now()))
}

func TestRemoteIdentityConcurrent(t *testing.T) {
	srv := &tstIdentityServer{identities: make(map[string]*corev1.RequestContext)}
	var mu sync.Mutex
	versions := make(map[string]int)
	keys := []string{"10.0.0.1/", "10.0.0.2/", "fd00::1/", "fd00::2/", "/" + newTestToken("a"), "/" + newTestToken("b")}
	for _, key := range keys {
		versions[key] = 1
		srv.identities[key] = newTestIdentity(key, 1)
	}

	c := newTestIdentityClient(&tstInternalErrC{authenticate: srv.authenticate})

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(i), 2))
			for j := range 200 {
				key := keys[r.IntN(len(keys))]
				if r.IntN(20) == 0 {
					mu.Lock()
					versions[key]++
					srv.setIdentity(key, newTestIdentity(key, versions[key]))
					mu.Unlock()
				}
				id := fmt.Sprintf("%d-%d", i, j)
				address, token, _ := strings.Cut(key, "/")
				if address == "" {
					address = []string{"192.0.2.1", "192.0.2.2"}[r.IntN(2)]
				} else if r.IntN(2) == 0 {
					token = fmt.Sprintf("application-%d", r.IntN(1000))
				}
				req := newTestIdentityRequest(address, token)
				req.Request.Request.GetHttp().Headers["x-request-id"] = id
				resp, err := c.AuthenticateAndAuthorize(t.Context(), req)
				if !assert.Nil(t, err) {
					return
				}
				srv.mu.Lock()
				want := srv.byID[id]
				srv.mu.Unlock()
				assert.Same(t, req.Request.Request, resp.RequestContext.Request)
				assert.Same(t, req.Service, resp.RequestContext.Service)
				got := pbutils.Clone(resp).(*coctovigilv1.AuthenticateAndAuthorizeResponse)
				got.RequestContext.Request = nil
				got.RequestContext.Service = nil
				assert.True(t, pbutils.IsEqual(want, got))
			}
		})
	}
	wg.Wait()
	assert.Greater(t, srv.omitted, 32*200/2)
}

func TestRemoteIdentityApplicationTokens(t *testing.T) {
	srv := &tstIdentityServer{identities: map[string]*corev1.RequestContext{
		"10.0.0.1/": newTestIdentity("client", 1),
		"fd00::1/":  newTestIdentity("v6", 1),
		"10.0.0.2/": newTestIdentity("other", 1),
	}}
	c := newTestIdentityClient(&tstInternalErrC{authenticate: srv.authenticate})

	_, err := c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("10.0.0.2", ""))
	require.Nil(t, err)
	otherKey, _ := c.getIdentityCacheKey(newTestIdentityRequest("10.0.0.2", "").Request)
	other := c.identities.get(otherKey, time.Now())
	require.NotNil(t, other)

	for _, address := range []string{"10.0.0.1", "fd00::1"} {
		for i := range identityCacheMaxEntries + 1 {
			token := fmt.Sprintf("application-%d", i)
			req := newTestIdentityRequest(address, "")
			headers := req.Request.Request.GetHttp().Headers
			switch i % 4 {
			case 0:
				headers["authorization"] = "Bearer " + token
			case 1:
				headers["x-octelium-auth"] = token
			case 2:
				headers["cookie"] = "other=value; octelium_auth=" + token
			default:
				headers["authorization"] = "Bearer " + newTestToken(token)
			}
			omittedBefore := srv.omitted
			resp, err := c.AuthenticateAndAuthorize(t.Context(), req)
			require.Nil(t, err)
			assert.Equal(t, i > 0, srv.omitted == omittedBefore+1)
			assert.True(t, pbutils.IsEqual(srv.identities[address+"/"].Session, resp.RequestContext.Session))
		}
	}

	assert.Equal(t, 2*identityCacheMaxEntries, srv.omitted)
	assert.Equal(t, 3, c.identities.len())
	assert.Same(t, other, c.identities.get(otherKey, time.Now()))
}

func TestRemoteIdentityTokenAliases(t *testing.T) {
	token := newTestToken("clientless")
	data, err := base64.RawURLEncoding.DecodeString(token)
	require.Nil(t, err)

	var aliases []string
	for i := range identityCacheMaxEntries + 1 {
		aliases = append(aliases, newTestTokenAlias(token, i))
	}
	for _, ch := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
		alias := token[:len(token)-1] + string(ch)
		if decoded, err := base64.RawURLEncoding.DecodeString(alias); err == nil && bytes.Equal(data, decoded) && alias != token {
			aliases = append(aliases, alias)
		}
	}
	assert.Len(t, aliases, identityCacheMaxEntries+1+map[int]int{0: 0, 1: 15, 2: 3}[len(data)%3])

	want := newTestIdentity("clientless", 1)
	srv := &tstIdentityServer{identities: map[string]*corev1.RequestContext{"/" + token: want}}
	for _, alias := range aliases {
		srv.identities["/"+alias] = want
	}
	c := newTestIdentityClient(&tstInternalErrC{authenticate: srv.authenticate})

	now := time.Now()
	for key := range uint64(identityCacheMaxEntries - 1) {
		c.identities.set(key, &identity{fingerprint: []byte("other"), expiresAt: now.Add(identityCacheTTL)}, now)
	}

	doAliases := func() {
		t.Helper()
		for _, alias := range aliases {
			omittedBefore := srv.omitted
			resp, err := c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("192.0.2.1", alias))
			require.Nil(t, err)
			sent, full := srv.last()
			assert.Nil(t, sent.IdentityFingerprint)
			assert.Equal(t, omittedBefore, srv.omitted)
			assert.True(t, pbutils.IsEqual(full.RequestContext.Session, resp.RequestContext.Session))
			assert.True(t, pbutils.IsEqual(want.Session, resp.RequestContext.Session))
		}
	}

	doAliases()
	assert.Equal(t, identityCacheMaxEntries-1, c.identities.len())

	_, err = c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("192.0.2.1", token))
	require.Nil(t, err)
	key, accessToken := c.getIdentityCacheKey(newTestIdentityRequest("192.0.2.1", token).Request)
	assert.Equal(t, token, accessToken)
	entry := c.identities.get(key, time.Now())
	require.NotNil(t, entry)
	assert.Equal(t, identityCacheMaxEntries, c.identities.len())

	doAliases()
	assert.Equal(t, identityCacheMaxEntries, c.identities.len())
	assert.Same(t, entry, c.identities.get(key, time.Now()))
	for key := range uint64(identityCacheMaxEntries - 1) {
		assert.NotNil(t, c.identities.get(key, time.Now()))
	}

	omittedBefore := srv.omitted
	resp, err := c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("192.0.2.2", token))
	require.Nil(t, err)
	assert.Equal(t, omittedBefore+1, srv.omitted)
	assert.Same(t, entry.session, resp.RequestContext.Session)
}

type tstRecordingC struct {
	coctovigilv1.InternalServiceClient
	mu      sync.Mutex
	omitted int
	full    int
}

func (c *tstRecordingC) AuthenticateAndAuthorize(ctx context.Context,
	in *coctovigilv1.AuthenticateAndAuthorizeRequest,
	opts ...grpc.CallOption) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
	resp, err := c.InternalServiceClient.AuthenticateAndAuthorize(ctx, in, opts...)
	if err == nil && in.OmitUnchangedIdentity {
		c.mu.Lock()
		if resp.IsIdentityOmitted {
			c.omitted++
		} else if len(resp.IdentityFingerprint) > 0 {
			c.full++
		}
		c.mu.Unlock()
	}
	return resp, err
}

func TestRemoteIdentityOctovigil(t *testing.T) {
	ctx := t.Context()

	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	octeliumC := tst.C.OcteliumC

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  octeliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(octeliumC)

	require.Nil(t, vutils.WaitUntilPortIsAvailable(octovigilc.GetPort()))
	octovigilSrv, err := octovigil.New(ctx, octeliumC)
	require.Nil(t, err)
	require.Nil(t, octovigilSrv.Run(ctx))
	t.Cleanup(func() {
		octovigilSrv.Close()
	})

	var groups []string
	for range 3 {
		grp, err := adminSrv.CreateGroup(ctx, &corev1.Group{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec:     &corev1.Group_Spec{},
		})
		require.Nil(t, err)
		groups = append(groups, grp.Metadata.Name)
	}

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "https://example.com"},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{{
					Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{
						Effect: corev1.Policy_Spec_Rule_ALLOW,
						Condition: &corev1.Condition{Type: &corev1.Condition_Match{
							Match: `!("blocked" in ctx.user.metadata.labels)`,
						}},
					}}},
				}},
			},
		},
	})
	require.Nil(t, err)
	svc, err = octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	require.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	require.Nil(t, err)
	vCache.SetService(svc)

	ns, err := octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Uid: svc.Status.NamespaceRef.Uid})
	require.Nil(t, err)
	require.Nil(t, octovigilSrv.GetCache().SetNamespace(ns))

	remoteC, err := octovigilc.NewClient(ctx)
	require.Nil(t, err)
	recorder := &tstRecordingC{InternalServiceClient: remoteC.InternalC()}
	c := &Client{svcUID: svc.Metadata.Uid, vCache: vCache, remoteC: &tstRemoteC{internalC: recorder}}

	var usrs []*tstuser.User
	for _, typ := range []corev1.User_Spec_Type{corev1.User_Spec_WORKLOAD, corev1.User_Spec_HUMAN} {
		for _, sessType := range []corev1.Session_Status_Type{corev1.Session_Status_CLIENTLESS, corev1.Session_Status_CLIENT} {
			usr, err := tstuser.NewUserWithType(octeliumC, adminSrv, usrSrv, groups[:2], typ, sessType)
			require.Nil(t, err)
			usrs = append(usrs, usr)
		}
	}

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	require.Nil(t, err)
	require.Nil(t, c.setClusterNetwork(cc))
	clientAddr := netip.MustParsePrefix(cc.Status.Network.ClusterNetwork.V4).Addr()
	clientAddrs := make(map[string]string)
	setClientSession := func(sess *corev1.Session) {
		if sess.Status.Type != corev1.Session_Status_CLIENT {
			return
		}
		require.Nil(t, octovigilSrv.GetCache().SetSession(sess))
	}
	for _, usr := range usrs {
		if usr.Session.Status.Type != corev1.Session_Status_CLIENT {
			continue
		}
		clientAddr = clientAddr.Next()
		usr.Session.Status.Connection = &corev1.Session_Status_Connection{
			Addresses: []*metav1.DualStackNetwork{{V4: clientAddr.String() + "/32"}},
		}
		usr.Session, err = octeliumC.CoreC().UpdateSession(ctx, usr.Session)
		require.Nil(t, err)
		setClientSession(usr.Session)
		clientAddrs[usr.Session.Metadata.Uid] = clientAddr.String()
	}

	r := rand.New(rand.NewPCG(5, 6))
	mutations := map[string]int{}
	mutate := func() {
		usr := usrs[r.IntN(len(usrs))]
		label := utilrand.GetRandomStringCanonical(6)
		switch kind := []string{"User", "UserGroups", "Group", "Session", "Device", "Namespace", "Block"}[r.IntN(7)]; kind {
		case "User", "UserGroups", "Block":
			u, err := octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: usr.Usr.Metadata.Uid})
			require.Nil(t, err)
			switch kind {
			case "User":
				u.Metadata.Labels = map[string]string{"label": label}
			case "UserGroups":
				u.Spec.Groups = slices.Clone(groups[:r.IntN(len(groups)+1)])
				r.Shuffle(len(u.Spec.Groups), func(i, j int) { u.Spec.Groups[i], u.Spec.Groups[j] = u.Spec.Groups[j], u.Spec.Groups[i] })
			case "Block":
				if _, ok := u.Metadata.Labels["blocked"]; ok {
					delete(u.Metadata.Labels, "blocked")
				} else {
					u.Metadata.Labels = map[string]string{"blocked": "true"}
				}
			}
			_, err = octeliumC.CoreC().UpdateUser(ctx, u)
			require.Nil(t, err)
			mutations[kind]++
		case "Group":
			grp, err := octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Name: groups[r.IntN(len(groups))]})
			require.Nil(t, err)
			grp.Metadata.Labels = map[string]string{"label": label}
			_, err = octeliumC.CoreC().UpdateGroup(ctx, grp)
			require.Nil(t, err)
			mutations[kind]++
		case "Session":
			sess, err := octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: usr.Session.Metadata.Uid})
			require.Nil(t, err)
			sess.Metadata.Labels = map[string]string{"label": label}
			sess, err = octeliumC.CoreC().UpdateSession(ctx, sess)
			require.Nil(t, err)
			setClientSession(sess)
			mutations[kind]++
		case "Device":
			if usr.Device == nil {
				return
			}
			dev, err := octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{Uid: usr.Device.Metadata.Uid})
			require.Nil(t, err)
			dev.Metadata.Labels = map[string]string{"label": label}
			_, err = octeliumC.CoreC().UpdateDevice(ctx, dev)
			require.Nil(t, err)
			mutations[kind]++
		case "Namespace":
			ns, err := octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Uid: svc.Status.NamespaceRef.Uid})
			require.Nil(t, err)
			ns.Metadata.Labels = map[string]string{"label": label}
			ns, err = octeliumC.CoreC().UpdateNamespace(ctx, ns)
			require.Nil(t, err)
			require.Nil(t, octovigilSrv.GetCache().SetNamespace(ns))
			mutations[kind]++
		}
	}

	var authorized, unauthorized, aliases int
	for range 400 {
		usr := usrs[r.IntN(len(usrs))]
		headers := map[string]string{"x-tenant": utilrand.GetRandomStringCanonical(4)}
		address := []string{"10.200.0.1", "10.200.0.2"}[r.IntN(2)]
		isAlias := false
		if addr, ok := clientAddrs[usr.Session.Metadata.Uid]; ok {
			address = addr
			if r.IntN(2) == 0 {
				headers["authorization"] = "Bearer " + utilrand.GetRandomStringCanonical(32)
			}
		} else {
			token := usr.GetAccessToken().AccessToken
			if r.IntN(8) == 0 {
				token = newTestTokenAlias(token, r.IntN(1<<20))
				isAlias = true
				aliases++
			}
			switch r.IntN(3) {
			case 0:
				headers["x-octelium-auth"] = token
			case 1:
				headers["cookie"] = "other=value; octelium_auth=" + token
			default:
				headers["authorization"] = "Bearer " + token
			}
		}
		req := &AuthenticateAndAuthorizeRequest{
			Request: &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{Address: address, Port: int32(1024 + r.IntN(1024))},
				Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
					Http: &corev1.RequestContext_Request_HTTP{Path: "/" + utilrand.GetRandomStringCanonical(4), Method: "GET", Headers: headers},
				}},
			},
			Service: vCache.GetService(),
		}

		legacy, err := remoteC.InternalC().AuthenticateAndAuthorize(ctx, &coctovigilv1.AuthenticateAndAuthorizeRequest{
			ServiceUID: svc.Metadata.Uid,
			Request:    req.Request,
		})
		require.Nil(t, err)
		omittedBefore, fullBefore := recorder.omitted, recorder.full
		resp, err := c.AuthenticateAndAuthorize(ctx, req)
		require.Nil(t, err)
		if isAlias {
			assert.Equal(t, omittedBefore, recorder.omitted)
			assert.Equal(t, fullBefore+1, recorder.full)
		}

		assert.True(t, legacy.IsAuthenticated)
		assert.Equal(t, usr.Session.Metadata.Uid, legacy.RequestContext.GetSession().GetMetadata().GetUid())
		assert.True(t, pbutils.IsEqual(legacy, resp))
		if resp.IsAuthorized {
			authorized++
		} else {
			unauthorized++
		}

		if r.IntN(4) == 0 {
			mutate()
		}
	}

	t.Logf("mutations: %v, omitted: %d, full: %d, authorized: %d, unauthorized: %d, aliases: %d",
		mutations, recorder.omitted, recorder.full, authorized, unauthorized, aliases)
	assert.Equal(t, 400, recorder.omitted+recorder.full)
	assert.Greater(t, recorder.omitted, 200)
	assert.Greater(t, recorder.full, 50)
	assert.Greater(t, unauthorized, 0)
	assert.Greater(t, aliases, 0)
	assert.Len(t, mutations, 7)
}

func TestRemoteIdentityWithoutSession(t *testing.T) {
	srv := &tstIdentityServer{identities: map[string]*corev1.RequestContext{
		"10.0.0.1/": {Namespace: newTestIdentity("anonymous", 1).Namespace},
	}}
	srv.override = func(resp *coctovigilv1.AuthenticateAndAuthorizeResponse) {
		resp.IdentityFingerprint = []byte("fingerprint")
	}
	c := newTestIdentityClient(&tstInternalErrC{authenticate: srv.authenticate})
	for range 2 {
		resp, err := c.AuthenticateAndAuthorize(t.Context(), newTestIdentityRequest("10.0.0.1", ""))
		require.Nil(t, err)
		assert.Empty(t, resp.IdentityFingerprint)
		assert.NotNil(t, resp.RequestContext.Namespace)
		sent, _ := srv.last()
		assert.Nil(t, sent.IdentityFingerprint)
	}
	assert.Zero(t, c.identities.len())
}
