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

package ocrypto

import (
	"crypto/tls"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

func GetTLSCertificate(sec *corev1.Secret) (*tls.Certificate, error) {

	chain, key, err := ucorev1.ToSecret(sec).GetCertificateChainAndKey()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
