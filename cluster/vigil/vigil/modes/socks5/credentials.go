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

package socks5

import (
	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	"github.com/octelium/octelium/apis/main/corev1"
)

type sessionSelectorCredentialStore struct{}

func (sessionSelectorCredentialStore) Valid(user, password, userAddr string) bool {
	return true
}

func getAuthUsername(req *gosocks5.Request) string {
	if req == nil || req.AuthContext == nil {
		return ""
	}

	if req.AuthContext.Method != statute.MethodUserPassAuth {
		return ""
	}

	return req.AuthContext.Payload["username"]
}

func isEmbeddedMode(cfg *corev1.Service_Spec_Config) bool {
	if cfg == nil || cfg.GetSocks5() == nil {
		return false
	}

	return cfg.GetSocks5().IsEmbeddedMode
}
