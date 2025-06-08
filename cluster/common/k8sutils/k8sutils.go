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

package k8sutils

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	k8scorev1 "k8s.io/api/core/v1"
)

func normalizeSvcName(svc *corev1.Service) string {
	return normalizeSvcNameStr(svc.Metadata.Name)
}

func normalizeSvcNameStr(arg string) string {
	return strings.ReplaceAll(arg, ".", "-")
}

func GetSvcHostname(svc *corev1.Service) string {
	return fmt.Sprintf("svc-%s", normalizeSvcName(svc))
}

func GetSvcFQDN(svc *corev1.Service) string {
	return fmt.Sprintf("%s.octelium.svc", GetSvcHostname(svc))
}

func GetSvcK8sUpstreamHostname(svc *corev1.Service, configName string) string {
	if configName == "" {
		configName = "default"
	}
	return fmt.Sprintf("upstream-svc-%s-%s", normalizeSvcName(svc), configName)
}

func GetSvcK8sUpstreamFQDN(svc *corev1.Service, configName string) string {
	return fmt.Sprintf("%s.octelium.svc", GetSvcK8sUpstreamHostname(svc, configName))
}

func GetGatewayName(node *k8scorev1.Node) string {
	inp := fmt.Sprintf("%s:%s", node.Name, string(node.UID))
	sh := sha256.Sum256([]byte(inp))
	out := strings.ToLower(base32.StdEncoding.EncodeToString(sh[:]))[:8]
	return fmt.Sprintf("%s-%s", vutils.GetMyRegionName(), out)
}

func GetImagePullPolicy() k8scorev1.PullPolicy {
	return k8scorev1.PullIfNotPresent
}
