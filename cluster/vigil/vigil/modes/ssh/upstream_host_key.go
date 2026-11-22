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

package ssh

import (
	"slices"

	"golang.org/x/crypto/ssh"
)

func getUpstreamHostKeyAlgorithms(key ssh.PublicKey) []string {
	var ret []string
	for _, algo := range slices.Concat(ssh.SupportedAlgorithms().HostKeys, ssh.InsecureAlgorithms().HostKeys) {
		if getHostKeyAlgorithmFormat(algo) == key.Type() && !slices.Contains(ret, algo) {
			ret = append(ret, algo)
		}
	}

	return ret
}

func getHostKeyAlgorithmFormat(algo string) string {
	switch algo {
	case ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512:
		return ssh.KeyAlgoRSA
	case ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01:
		return ssh.CertAlgoRSAv01
	default:
		return algo
	}
}
