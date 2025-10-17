// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ucorev1

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

const (
	KindClusterConfig    = "ClusterConfig"
	KindUser             = "User"
	KindGroup            = "Group"
	KindNamespace        = "Namespace"
	KindService          = "Service"
	KindSession          = "Session"
	KindSecret           = "Secret"
	KindCredential       = "Credential"
	KindDevice           = "Device"
	KindConfig           = "Config"
	KindPolicy           = "Policy"
	KindAuthenticator    = "Authenticator"
	KindIdentityProvider = "IdentityProvider"
	KindRegion           = "Region"
	KindGateway          = "Gateway"
	KindAccessLog        = "AccessLog"
	KindComponentLog     = "ComponentLog"
	KindPolicyTrigger    = "PolicyTrigger"
)

func NewObject(kind string) (umetav1.ResourceObjectI, error) {

	switch kind {
	case KindUser:
		return &corev1.User{}, nil
	case KindGroup:
		return &corev1.Group{}, nil
	case KindNamespace:
		return &corev1.Namespace{}, nil
	case KindService:
		return &corev1.Service{}, nil
	case KindCredential:
		return &corev1.Credential{}, nil
	case KindDevice:
		return &corev1.Device{}, nil
	case KindSession:
		return &corev1.Session{}, nil
	case KindSecret:
		return &corev1.Secret{}, nil
	case KindConfig:
		return &corev1.Config{}, nil
	case KindPolicy:
		return &corev1.Policy{}, nil

	case KindIdentityProvider:
		return &corev1.IdentityProvider{}, nil
	case KindRegion:
		return &corev1.Region{}, nil
	case KindGateway:
		return &corev1.Gateway{}, nil
	case KindClusterConfig:
		return &corev1.ClusterConfig{}, nil
	case KindPolicyTrigger:
		return &corev1.PolicyTrigger{}, nil
	case KindAuthenticator:
		return &corev1.Authenticator{}, nil
	default:
		return nil, errors.Errorf("Invalid kind: %s", kind)
	}
}

func NewObjectListOptions(kind string) (proto.Message, error) {

	switch kind {
	case KindUser:
		return &corev1.ListUserOptions{}, nil
	case KindGroup:
		return &corev1.ListGroupOptions{}, nil
	case KindNamespace:
		return &corev1.ListNamespaceOptions{}, nil
	case KindService:
		return &corev1.ListServiceOptions{}, nil
	case KindCredential:
		return &corev1.ListCredentialOptions{}, nil
	case KindDevice:
		return &corev1.ListDeviceOptions{}, nil
	case KindSession:
		return &corev1.ListSessionOptions{}, nil
	case KindSecret:
		return &corev1.ListSecretOptions{}, nil
	case KindPolicy:
		return &corev1.ListPolicyOptions{}, nil

	case KindIdentityProvider:
		return &corev1.ListIdentityProviderOptions{}, nil
	case KindRegion:
		return &corev1.ListRegionOptions{}, nil
	case KindGateway:
		return &corev1.ListGatewayOptions{}, nil
	case KindAuthenticator:
		return &corev1.ListAuthenticatorOptions{}, nil
	default:
		return nil, errors.Errorf("Invalid kind: %s", kind)
	}
}

func NewObjectList(kind string) (umetav1.ObjectI, error) {

	switch kind {
	case KindUser:
		return &corev1.UserList{}, nil
	case KindGroup:
		return &corev1.GroupList{}, nil
	case KindNamespace:
		return &corev1.NamespaceList{}, nil
	case KindService:
		return &corev1.ServiceList{}, nil
	case KindCredential:
		return &corev1.CredentialList{}, nil
	case KindDevice:
		return &corev1.DeviceList{}, nil
	case KindSession:
		return &corev1.SessionList{}, nil
	case KindSecret:
		return &corev1.SecretList{}, nil
	case KindConfig:
		return &corev1.ConfigList{}, nil
	case KindPolicy:
		return &corev1.PolicyList{}, nil

	case KindIdentityProvider:
		return &corev1.IdentityProviderList{}, nil
	case KindRegion:
		return &corev1.RegionList{}, nil
	case KindGateway:
		return &corev1.GatewayList{}, nil
	case KindPolicyTrigger:
		return &corev1.PolicyTriggerList{}, nil

	case KindAuthenticator:
		return &corev1.AuthenticatorList{}, nil
	default:
		return nil, errors.Errorf("Invalid kind: %s", kind)
	}
}

type ResourceObjectRefG interface {
	*corev1.Service | *corev1.Secret | *corev1.Session | *corev1.Device |
		*corev1.User | *corev1.Group | *corev1.Namespace | *corev1.Config | *corev1.Policy |
		*corev1.IdentityProvider |
		*corev1.Region | *corev1.Gateway |
		*corev1.ClusterConfig | *corev1.PolicyTrigger | *corev1.Credential | *corev1.Authenticator
}

type Session struct {
	*corev1.Session
}

type User struct {
	*corev1.User
}

type Service struct {
	*corev1.Service
}

type ServiceConfig struct {
	*corev1.Service_Spec_Config
}

type Credential struct {
	*corev1.Credential
}

type Secret struct {
	*corev1.Secret
}

type Region struct {
	*corev1.Region
}

func ToService(a *corev1.Service) *Service {
	return &Service{
		Service: a,
	}
}

func ToServiceConfig(a *corev1.Service_Spec_Config) *ServiceConfig {
	return &ServiceConfig{
		Service_Spec_Config: a,
	}
}

func ToSession(a *corev1.Session) *Session {
	return &Session{
		Session: a,
	}
}

func ToUser(a *corev1.User) *User {
	return &User{
		User: a,
	}
}

func ToSecret(a *corev1.Secret) *Secret {
	return &Secret{
		Secret: a,
	}
}

func ToCredential(a *corev1.Credential) *Credential {
	return &Credential{
		Credential: a,
	}
}

func (s *Service) Name() string {
	args := strings.Split(s.Metadata.Name, ".")
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func (s *ServiceConfig) GetRealName() string {
	if s == nil {
		return ""
	}
	if s.Name == "" {
		return "default"
	}
	return s.Name
}

func (s *Service) Namespace() string {
	if s.Status.NamespaceRef != nil {
		return s.Status.NamespaceRef.Name
	}
	return ""
}

func (s *Secret) GetSpecValueStr() string {
	if s.Spec.Data == nil {
		return ""
	}
	switch s.Spec.Data.Type.(type) {
	case *corev1.Secret_Spec_Data_Value:
		return s.Spec.Data.GetValue()
	case *corev1.Secret_Spec_Data_ValueBytes:
		return string(s.Spec.Data.GetValueBytes())
	default:
		return ""
	}
}

func (s *Secret) GetValueStr() string {
	if s.Data == nil {
		return ""
	}
	switch s.Data.Type.(type) {
	case *corev1.Secret_Data_Value:
		return s.Data.GetValue()
	case *corev1.Secret_Data_ValueBytes:
		return string(s.Data.GetValueBytes())
	default:
		return ""
	}
}

func (s *Secret) GetSpecValueBytes() []byte {
	return []byte(s.GetSpecValueStr())
}

func (s *Secret) GetValueBytes() []byte {
	return []byte(s.GetValueStr())
}

func (s *Session) IsClient() bool {
	return s.Status.Type == corev1.Session_Status_CLIENT
}

func (s *Session) IsClientConnected() bool {
	return s.Status.Type == corev1.Session_Status_CLIENT && s.Status.Connection != nil
}

func (s *Session) IsClientConnectedESSH() bool {
	if !s.IsClientConnected() {
		return false
	}

	return s.Status.Connection.ESSHEnable
}

func (s *Session) HasV4() bool {
	if s == nil || s.Status.Connection == nil {
		return false
	}

	conn := s.Status.Connection

	return conn.L3Mode == corev1.Session_Status_Connection_BOTH ||
		conn.L3Mode == corev1.Session_Status_Connection_V4
}

func (s *Session) HasV6() bool {
	if s == nil || s.Status.Connection == nil {
		return false
	}

	conn := s.Status.Connection

	return conn.L3Mode == corev1.Session_Status_Connection_BOTH ||
		conn.L3Mode == corev1.Session_Status_Connection_V6
}

func (s *Service) IsServedBySession(sess *Session) bool {

	if sess == nil || !sess.IsClientConnected() {
		return false
	}

	return slices.ContainsFunc(sess.Status.Connection.Upstreams,
		func(u *corev1.Session_Status_Connection_Upstream) bool {
			return u.ServiceRef.Uid == s.Metadata.Uid
		})
}

func (s *Service) GetHostUserRef(userName string) (*metav1.ObjectReference, error) {
	err := errors.Errorf("hostUser not found")
	if s == nil || userName == "" {
		return nil, err
	}
	if s.Metadata.SpecLabels == nil {
		return nil, err
	}

	userUID, ok := s.Metadata.SpecLabels[fmt.Sprintf("host-user-%s", userName)]
	if !ok {
		return nil, err
	}

	return &metav1.ObjectReference{
		ApiVersion: APIVersion,
		Kind:       KindUser,
		Uid:        userUID,
		Name:       userName,
	}, nil
}

func (s *Service) GetSessionUpstream(sess *Session) *corev1.Session_Status_Connection_Upstream {

	if !s.IsServedBySession(sess) {
		return nil
	}

	for _, u := range sess.Status.Connection.Upstreams {
		if u.ServiceRef.Uid == s.Metadata.Uid {
			return u
		}
	}

	return nil
}

func (s *Session) IsExpired() bool {
	if !s.Spec.ExpiresAt.IsValid() {
		return false
	}

	return time.Now().After(s.Spec.ExpiresAt.AsTime())
}

func (s *Session) IsValid() bool {

	if s.Spec.State != corev1.Session_Spec_ACTIVE {
		return false
	}

	if s.IsExpired() {
		return false
	}

	if !s.HasValidAccessToken() {
		return false
	}

	return true
}

func (s *Session) HasValidAccessToken() bool {
	if s.Status.Authentication.AccessTokenDuration == nil {
		return true
	}

	return time.Now().Before(s.Status.Authentication.SetAt.AsTime().
		Add(umetav1.ToDuration(s.Status.Authentication.AccessTokenDuration).ToGo()))
}

func (s *Session) HasValidAccessTokenByTokenID(tid string) bool {
	if s.Status.Authentication.TokenID != tid {
		return false
	}
	if s.Status.Authentication.AccessTokenDuration == nil {
		return true
	}

	return time.Now().Before(s.Status.Authentication.SetAt.AsTime().
		Add(umetav1.ToDuration(s.Status.Authentication.AccessTokenDuration).ToGo()))
}

func (s *Session) ShouldRefresh() bool {

	if s.Status.Authentication.AccessTokenDuration == nil {
		return false
	}

	accessTokenDuration := umetav1.ToDuration(s.Status.Authentication.AccessTokenDuration).ToGo()
	return time.Now().After(s.Status.Authentication.SetAt.AsTime().
		Add(accessTokenDuration).Add(-accessTokenDuration / 4))
}

func (s *Session) HasValidRefreshTokenByTokenID(tid string) bool {
	if s.Status.Authentication.TokenID != tid {
		return false
	}
	if s.Status.Authentication.AccessTokenDuration == nil {
		return true
	}

	return time.Now().Before(s.Status.Authentication.SetAt.AsTime().
		Add(umetav1.ToDuration(s.Status.Authentication.RefreshTokenDuration).ToGo()))
}

func (s *Session) HasValidRefreshToken() bool {

	if s.Status.Authentication.RefreshTokenDuration == nil {
		return true
	}

	return time.Now().Before(s.Status.Authentication.SetAt.AsTime().
		Add(umetav1.ToDuration(s.Status.Authentication.RefreshTokenDuration).ToGo()))
}

func (u *User) HasGroupName(arg string) bool {
	return isInList(u.Spec.Groups, arg)
}

func (u *User) HasGroupNameAny(arg []string) bool {
	for _, itm := range arg {
		if isInList(u.getAllGroups(), itm) {
			return true
		}
	}
	return false
}

func (u *User) getAllGroups() []string {
	return u.Spec.Groups
}

func (u *User) HasGroupNameAll(arg []string) bool {
	for _, itm := range arg {
		if !isInList(u.getAllGroups(), itm) {
			return false
		}
	}
	return true
}

func isInList(lst []string, arg string) bool {
	for _, itm := range lst {
		if itm == arg {
			return true
		}
	}
	return false
}

func (s *Service) IsInMyRegion() bool {
	region := os.Getenv("OCTELIUM_REGION_NAME")
	if s.Spec.Region == "" {
		return region == "default"
	}

	return s.Spec.Region == region
}

func getPortFromScheme(arg string) (int, error) {
	if arg == "" {
		return 0, errors.Errorf("Please provide port in the url")
	}
	switch arg {
	case "http", "ws", "h2c":
		return 80, nil
	case "https", "wss":
		return 443, nil
	case "ssh":
		return 22, nil
	case "dns":
		return 53, nil
	case "postgres", "postgresql":
		return 5432, nil
	case "redis":
		return 6379, nil
	case "mysql":
		return 3306, nil
	case "mongodb":
		return 27017, nil
	case "rdp":
		return 3389, nil
	case "amqp":
		return 5672, nil
	case "ftp":
		return 21, nil
	case "dot":
		return 853, nil
	default:
		return 0, errors.Errorf("Unknown scheme %s. Please provide port number", arg)
	}
}

func (l *Service) GetAllUpstreamEndpointsByConfig(cfg *corev1.Service_Spec_Config) []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint {
	var ret []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint

	scheme := func() string {
		switch l.Spec.Mode {
		case corev1.Service_Spec_HTTP, corev1.Service_Spec_GRPC,
			corev1.Service_Spec_WEB, corev1.Service_Spec_KUBERNETES:
			return "http"
		case corev1.Service_Spec_SSH:
			return "ssh"
		case corev1.Service_Spec_UDP, corev1.Service_Spec_DNS:
			return "udp"
		default:
			return "tcp"
		}
	}()

	if l.IsManagedService() {

		if l.Status.ManagedService != nil && l.Status.ManagedService.Port != 0 {
			ret = append(ret, &corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
				Url: fmt.Sprintf("%s://localhost:%d", scheme, l.Status.ManagedService.Port),
			})
		} else {
			ret = append(ret, &corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
				Url: fmt.Sprintf("%s://localhost:49999", scheme),
			})
		}

		return ret
	}

	if cfg != nil && cfg.GetSsh() != nil && cfg.GetSsh().ESSHMode {
		ret = append(ret, &corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
			Url: "ssh://localhost:22022",
		})
		return ret
	}

	if cfg != nil && l.Metadata != nil && l.Metadata.SpecLabels != nil &&
		l.Metadata.SpecLabels[fmt.Sprintf("k8s-kubeconfig-url-%s", ToServiceConfig(cfg).GetRealName())] != "" {
		ret = append(ret, &corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
			Url: l.Metadata.SpecLabels[fmt.Sprintf("k8s-kubeconfig-url-%s", ToServiceConfig(cfg).GetRealName())],
		})
	}

	if cfg == nil || cfg.GetUpstream() == nil {
		return nil
	}

	upstream := cfg.GetUpstream()

	switch upstream.Type.(type) {
	case *corev1.Service_Spec_Config_Upstream_Url:
		ret = []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
			{
				Url:  upstream.GetUrl(),
				User: upstream.User,
			},
		}
	case *corev1.Service_Spec_Config_Upstream_Loadbalance_:
		ret = upstream.GetLoadbalance().Endpoints
	case *corev1.Service_Spec_Config_Upstream_Container_:

		urlstr := fmt.Sprintf("%s://%s:%d", scheme,
			getSvcK8sUpstreamHostname(l.Service, cfg.Name), cfg.GetUpstream().GetContainer().Port)
		url, _ := url.Parse(urlstr)
		ret = append(ret, &corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
			Url: url.String(),
		})

	}

	return ret
}

func (l *Service) GetAllUpstreamEndpoints() []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint {
	return l.GetAllUpstreamEndpointsByConfig(l.Spec.Config)
}

func getSvcK8sUpstreamHostname(svc *corev1.Service, name string) string {
	if name == "" {
		name = "default"
	}
	return fmt.Sprintf("upstream-svc-%s-%s",
		strings.ReplaceAll(svc.Metadata.Name, ".", "-"), name)
}

func (l *Service) getFirstURL() *url.URL {

	eps := l.GetAllUpstreamEndpoints()
	if len(eps) == 0 {
		return nil
	}
	ret, _ := url.Parse(eps[0].Url)
	return ret
}

func (l *Service) IsManagedContainer() bool {
	return l.Spec.Config != nil && l.Spec.Config.GetUpstream() != nil &&
		l.Spec.Config.GetUpstream().GetContainer() != nil
}

func (l *Service) IsKubernetes() bool {
	return l.Spec.Mode == corev1.Service_Spec_KUBERNETES
}

func (l *Service) IsESSH() bool {
	return l.Spec.Mode == corev1.Service_Spec_SSH &&
		l.Spec.Config != nil && l.Spec.Config.GetSsh() != nil &&
		l.Spec.Config.GetSsh().ESSHMode
}

func (l *Service) L4Type() corev1.Service_Spec_Mode {

	switch l.Spec.Mode {
	case corev1.Service_Spec_UDP, corev1.Service_Spec_DNS:
		return corev1.Service_Spec_UDP
	default:
		return corev1.Service_Spec_TCP
	}
}

func (l *Service) RealPort() int {
	return int(l.Status.Port)
}

func (l *Service) UpstreamRealPort() int {
	eps := l.GetAllUpstreamEndpoints()
	if len(eps) == 0 {
		return 0
	}
	return epRealPort(eps[0])
}

func EndpointRealPort(l *corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint) int {
	return epRealPort(l)
}

func epRealPort(l *corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint) int {
	u, _ := url.Parse(l.Url)
	if u.Port() == "" {
		p, err := getPortFromScheme(u.Scheme)
		if err != nil {
			return 0
		}
		return p

	} else {
		p, err := strconv.Atoi(u.Port())
		if err != nil {
			return 0
		}
		return p
	}
}

func (l *Service) IsHTTP() bool {

	switch l.Spec.Mode {
	case corev1.Service_Spec_HTTP,
		corev1.Service_Spec_KUBERNETES,
		corev1.Service_Spec_GRPC,
		corev1.Service_Spec_WEB:
		return true
	default:
		return false
	}
}

func (l *Service) IsManagedService() bool {
	return l.Status.ManagedService != nil
}

func (s *Service) IsListenerHTTP2() bool {
	if s.IsGRPC() {
		return true
	}

	if !s.IsHTTP() {
		return false
	}

	if s.Spec.Config != nil && s.Spec.Config.GetHttp() != nil && s.Spec.Config.GetHttp().ListenHTTP2 {
		return true
	}

	if s.Spec.IsTLS {
		return true
	}

	switch s.BackendScheme() {
	case "grpc", "h2c":
		return true
	default:
		return false
	}
}

func (s *Service) IsGRPC() bool {
	return s.Spec.Mode == corev1.Service_Spec_GRPC
}

func (s *Service) IsUpstreamHTTP2() bool {
	if s.IsGRPC() {
		return true
	}

	if !s.IsHTTP() {
		return false
	}

	if s.Spec != nil && s.Spec.Config != nil &&
		s.Spec.Config.GetHttp() != nil &&
		s.Spec.Config.GetHttp().IsUpstreamHTTP2 {
		return true
	}

	switch s.BackendScheme() {
	case "grpc", "h2c":
		return true
	default:
		return false
	}
}

func (l *Service) BackendScheme() string {
	u := l.getFirstURL()
	if u == nil {
		return "tcp"
	}

	return u.Scheme
}

func (l *Service) GetMode() corev1.Service_Spec_Mode {
	if l.Spec.Mode != corev1.Service_Spec_MODE_UNSET {
		return l.Spec.Mode
	}
	return corev1.Service_Spec_TCP

}

const API = "core"
const Version = "v1"
const APIVersion = "core/v1"

func (s *IdentityProviderList) GetByName(name string) (*corev1.IdentityProvider, error) {
	for _, idp := range s.Items {
		if idp.Metadata.Name == name {
			return idp, nil
		}
	}
	return nil, errors.Errorf("No identity provider exists with name: %s", name)
}

func (s *IdentityProviderList) FilterByNames(lst []string) []*corev1.IdentityProvider {
	var ret []*corev1.IdentityProvider

	isInList := func(name string) (int, bool) {
		for i, itm := range s.Items {
			if itm.Metadata.Name == name {
				return i, true
			}
		}
		return 0, false
	}
	for _, name := range lst {
		idx, ok := isInList(name)
		if ok {
			ret = append(ret, s.Items[idx])
		}
	}

	return ret
}

type IdentityProviderList struct {
	*corev1.IdentityProviderList
}

func ToIdentityProviderList(a *corev1.IdentityProviderList) *IdentityProviderList {
	return &IdentityProviderList{
		IdentityProviderList: a,
	}
}

func (s *IdentityProviderList) GetByUID(uid string) *corev1.IdentityProvider {
	for _, itm := range s.Items {
		if itm.Metadata.Uid == uid {
			return itm
		}
	}
	return nil
}

type ClusterConfig struct {
	*corev1.ClusterConfig
}

func ToClusterConfig(a *corev1.ClusterConfig) *ClusterConfig {
	return &ClusterConfig{
		ClusterConfig: a,
	}
}

func (c *ClusterConfig) GetNetworkMode() corev1.ClusterConfig_Status_NetworkConfig_Mode {
	if c.Status.NetworkConfig == nil {
		return corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK
	}
	if c.Status.NetworkConfig.Mode == corev1.ClusterConfig_Status_NetworkConfig_MODE_DEFAULT {
		return corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK
	}

	return c.Status.NetworkConfig.Mode
}

func (i *ClusterConfig) HasV4() bool {
	if i == nil || i.Status == nil || i.Status.NetworkConfig == nil {
		return true
	}
	val := i.Status.NetworkConfig.Mode
	switch val {
	case corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY, corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, corev1.ClusterConfig_Status_NetworkConfig_MODE_DEFAULT:
		return true
	default:
		return false
	}
}

func (i *ClusterConfig) HasV6() bool {
	if i == nil || i.Status == nil || i.Status.NetworkConfig == nil {
		return true
	}
	val := i.Status.NetworkConfig.Mode
	switch val {
	case corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY, corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, corev1.ClusterConfig_Status_NetworkConfig_MODE_DEFAULT:
		return true
	default:
		return false
	}
}

func (c *ClusterConfig) GetGatewayPortWireGuard() uint32 {
	if c.Status.NetworkConfig == nil || c.Status.NetworkConfig.Wireguard == nil || c.Status.NetworkConfig.Wireguard.GatewayPort == 0 {
		return 53820
	}

	return c.Status.NetworkConfig.Wireguard.GatewayPort
}

func (c *ClusterConfig) GetGatewayPorQUICv0() uint32 {
	if c.Status.NetworkConfig == nil || c.Status.NetworkConfig.Quicv0 == nil || c.Status.NetworkConfig.Quicv0.GatewayPort == 0 {
		return 8443
	}

	return c.Status.NetworkConfig.Quicv0.GatewayPort
}

func (c *ClusterConfig) GetGatewayPortQUICv0() uint32 {
	if c.Status.NetworkConfig == nil || c.Status.NetworkConfig.Quicv0 == nil || c.Status.NetworkConfig.Quicv0.GatewayPort == 0 {
		return 8443
	}

	return c.Status.NetworkConfig.Quicv0.GatewayPort
}

func (c *ClusterConfig) GetDevMTUWireGuard() int {
	if c.Status.NetworkConfig == nil || c.Status.NetworkConfig.Wireguard == nil || c.Status.NetworkConfig.Wireguard.Mtu == 0 {
		return 1280
	}

	return int(c.Status.NetworkConfig.Wireguard.Mtu)
}

func (c *ClusterConfig) GetDevMTUQUIV0() int {
	const defaultValue = 1280
	if c.Status.NetworkConfig == nil || c.Status.NetworkConfig.Quicv0 == nil || c.Status.NetworkConfig.Quicv0.Mtu == 0 {
		return defaultValue
	}

	if c.Status.NetworkConfig.Quicv0.Mtu > defaultValue {
		return defaultValue
	}

	return int(c.Status.NetworkConfig.Quicv0.Mtu)
}

func (c *Secret) SetCertificate(chainPEM, privateKeyPEM string) {
	if c == nil {
		return
	}
	if c.Spec == nil {
		c.Spec = &corev1.Secret_Spec{}
	}
	c.Spec.Data = &corev1.Secret_Spec_Data{
		Type: &corev1.Secret_Spec_Data_Value{
			Value: chainPEM,
		},
	}
	c.Data = &corev1.Secret_Data{
		Type: &corev1.Secret_Data_Value{
			Value: privateKeyPEM,
		},
	}
}

func (c *Secret) GetCertificateChainAndKey() ([]byte, []byte, error) {
	chain := c.GetSpecValueBytes()
	key := c.GetValueBytes()
	if len(chain) == 0 || len(key) == 0 {
		return nil, nil, errors.Errorf("Could not find certificate chain and key")
	}

	return chain, key, nil
}

func (r *Region) IsDefault() bool {
	return r.Metadata.Name == "default"
}

type Authenticator struct {
	*corev1.Authenticator
}

func ToAuthenticator(a *corev1.Authenticator) *Authenticator {
	return &Authenticator{
		Authenticator: a,
	}
}
