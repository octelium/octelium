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

package vutils

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	k8snet "k8s.io/utils/net"
)

func IsDefaultRegion() bool {
	return GetMyRegionName() == "default"
}

const K8sNS = "octelium"
const ClusterCertSecretName = "crt-ns-default"

func GenerateLog() *corev1.AccessLog {
	return &corev1.AccessLog{
		ApiVersion: ucorev1.APIVersion,
		Kind:       ucorev1.KindAccessLog,
		Metadata: &metav1.LogMetadata{
			Id:        GenerateLogID(),
			CreatedAt: pbutils.Now(),
		},
		Entry: &corev1.AccessLog_Entry{},
	}
}

func GenerateLogID() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		utilrand.GetRandomStringCanonical(4),
		utilrand.GetRandomStringLowercase(4),
		utilrand.GetRandomStringLowercase(24),
		utilrand.GetRandomStringLowercase(4),
		utilrand.GetRandomStringLowercase(4),
	)
}

func GetServicePublicFQDN(svc *corev1.Service, clusterDomain string) string {
	if svc.Status.NamespaceRef.Name == "default" {
		return fmt.Sprintf("%s.%s", ucorev1.ToService(svc).Name(), clusterDomain)
	}
	return fmt.Sprintf("%s.%s", svc.Metadata.Name, clusterDomain)
}

func GetServicePrivateFQDN(svc *corev1.Service, clusterDomain string) string {
	if svc.Status.NamespaceRef.Name == "default" {
		return fmt.Sprintf("%s.local.%s", ucorev1.ToService(svc).Name(), clusterDomain)
	}
	return fmt.Sprintf("%s.local.%s", svc.Metadata.Name, clusterDomain)
}

func UUIDv4() string {
	return uuid.New().String()
}

func UUIDv7() string {
	uid, _ := uuid.NewV7()
	return uid.String()
}

func GetApiVersion(api, version string) string {
	return fmt.Sprintf("%s/%s", api, version)
}

func SplitApiVersion(apiVersion string) (string, string) {
	ret := strings.Split(apiVersion, "/")
	if len(ret) >= 2 {
		return ret[0], ret[1]
	}

	if len(ret) == 1 {
		return ret[0], ""
	}

	return "", ""
}

func NewResourceObject(api, version, kind string) (umetav1.ResourceObjectI, error) {
	switch api {
	case ucorev1.API:
		return ucorev1.NewObject(kind)
	default:
		return nil, errors.Errorf("Invalid API: %s", api)
	}
}

func NewResourceObjectList(api, version, kind string) (proto.Message, error) {
	switch api {
	case ucorev1.API:
		return ucorev1.NewObjectList(kind)
	default:
		return nil, errors.Errorf("Invalid API: %s", api)
	}
}

func GetResourceName(itm umetav1.ResourceObjectI) string {
	if itm == nil || itm.GetMetadata() == nil {
		return ""
	}
	return itm.GetMetadata().Name
}

func GetDualStackIPByIndex(n *metav1.DualStackNetwork, idx int) (*metav1.DualStackIP, error) {

	ret := &metav1.DualStackIP{}

	if n.V4 != "" {
		_, netV4, err := net.ParseCIDR(n.V4)
		if err != nil {
			return nil, err
		}

		ipv4, err := k8snet.GetIndexedIP(netV4, idx)
		if err != nil {
			return nil, err
		}

		ret.Ipv4 = ipv4.String()
	}

	if n.V6 != "" {
		_, netV6, err := net.ParseCIDR(n.V6)
		if err != nil {
			return nil, err
		}
		ipv6, err := k8snet.GetIndexedIP(netV6, idx)
		if err != nil {
			return nil, err
		}

		ret.Ipv6 = ipv6.String()
	}

	return ret, nil
}

func GetMyRegionName() string {
	ret := os.Getenv("OCTELIUM_REGION_NAME")
	if ret != "" {
		return ret
	}

	if ldflags.IsTest() {
		return "default"
	}

	return ret
}

func GetMyRegionUID() string {
	return os.Getenv("OCTELIUM_REGION_UID")
}

func MustParseTime(arg string) time.Time {
	ret, _ := time.Parse(time.RFC3339Nano, arg)
	return ret
}

func FSPathExistent(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func FSPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func DirExists(path string) bool {
	if i, err := os.Stat(path); err == nil && i.Mode().IsDir() {
		return true
	}

	return false
}

func FileExists(path string) bool {
	if i, err := os.Stat(path); err == nil && i.Mode().IsRegular() {
		return true
	}

	return false
}

func GatewayToUser(gw *corev1.Gateway) *userv1.Gateway {

	return &userv1.Gateway{
		Id:        gw.Status.Id,
		Hostname:  gw.Status.Hostname,
		Addresses: gw.Status.PublicIPs,

		Wireguard: &userv1.Gateway_WireGuard{
			Port:      int32(gw.Status.Wireguard.Port),
			PublicKey: gw.Status.Wireguard.PublicKey,
		},
		Quicv0: func() *userv1.Gateway_QUICV0 {
			if gw.Status.Quicv0 == nil {
				return nil
			}
			return &userv1.Gateway_QUICV0{
				Port: int32(gw.Status.Quicv0.Port),
			}
		}(),

		CIDRs: func() []string {
			ret := []string{}

			if gw.Status.Cidr.V4 != "" {
				ret = append(ret, gw.Status.Cidr.V4)
			}
			if gw.Status.Cidr.V6 != "" {
				ret = append(ret, gw.Status.Cidr.V6)
			}

			return ret
		}(),
	}
}

func GetServiceFullNameFromName(arg string) string {
	if arg == "" {
		return ""
	}

	args := strings.Split(arg, ".")
	if len(args) == 1 {
		return fmt.Sprintf("%s.default", arg)
	}
	if len(args) == 2 {
		return arg
	}
	return ""
}

func GetServiceFullName(svc *corev1.Service) string {
	return GetServiceFullNameFromName(svc.Metadata.Name)
}

func IsClusterCertAndReady(sec *corev1.Secret) bool {
	if sec.Metadata.Name != ClusterCertSecretName {
		return false
	}

	return IsCertReady(sec)
}

func IsClusterCertAndReadyWithNamespace(sec *corev1.Secret, ns string) bool {
	if sec.Metadata.Name != fmt.Sprintf("crt-ns-%s", ns) {
		return false
	}

	return IsCertReady(sec)
}

func IsOcteliumCert(sec *corev1.Secret) bool {
	return sec.Metadata.SystemLabels != nil && sec.Metadata.SystemLabels["octelium-cert"] == "true"
}

func IsCertReady(sec *corev1.Secret) bool {

	chain, key, err := ucorev1.ToSecret(sec).GetCertificateChainAndKey()
	if err != nil {
		return false
	}

	if _, err := utils_cert.ParseX509CertificateChainPEM(chain); err != nil {
		return false
	}

	if _, err := utils_cert.ParsePrivateKeyPEM(key); err != nil {
		return false
	}

	return true
}

func SetRegionPublicHostName(r *corev1.Region) {
	r.Status.PublicHostname = fmt.Sprintf("_r-%s", r.Metadata.Name)
}

func NowRFC3339Nano() string {
	return time.Now().Format(time.RFC3339Nano)
}

func isPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}

	ln.Close()
	time.Sleep(100 * time.Millisecond)
	return true
}

func WaitUntilPortIsAvailable(port int) error {
	for i := range 10000 {
		if isPortAvailable(port) {
			return nil
		}
		zap.L().Warn("Port is not available. Trying again...", zap.Int("attempt", i+1))
		time.Sleep(500 * time.Millisecond)
	}
	return errors.Errorf("port %d is not available", port)
}

func Sha256SumHex(arg []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(arg)))
}

func Sha256Sum(arg []byte) []byte {
	ret := sha256.Sum256(arg)
	return ret[:]
}

const UpgradeIDKey = "upgrade-id"
const ManagedServiceAddr = "localhost:49999"
const MaxPolicyParents = 5
const MaxNameSubArgs = 7
const ManagedServicePort = 49999

const HealthCheckPortVigil = 49094
const HealthCheckPortManagedService = 49095
const HealthCheckPortMain = 49090
