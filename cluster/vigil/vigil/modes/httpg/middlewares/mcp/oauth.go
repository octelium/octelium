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

package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
)

const PathProtectedResourceMetadata = "/.well-known/oauth-protected-resource"

type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

func (m *guard) serveWellKnown(w http.ResponseWriter, req *http.Request,
	reqCtx *middlewares.RequestContext) bool {

	if req.URL.Path != PathProtectedResourceMetadata {
		return false
	}

	svc := reqCtx.Service
	if svc == nil || !svc.Spec.IsPublic {
		return false
	}

	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}

	body, err := json.Marshal(&protectedResourceMetadata{
		Resource: fmt.Sprintf("https://%s/",
			vutils.GetServicePublicFQDN(svc, m.domain)),
		AuthorizationServers:   []string{fmt.Sprintf("https://%s", m.domain)},
		BearerMethodsSupported: []string{"header"},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}

	hdr := w.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Server", "octelium")
	hdr.Set("Cache-Control", "public, max-age=3600")

	w.WriteHeader(http.StatusOK)
	if req.Method == http.MethodGet {
		w.Write(body)
	}

	return true
}

func GetWWWAuthenticate(fqdn string) string {
	return fmt.Sprintf(`Bearer resource_metadata="https://%s%s"`,
		fqdn, PathProtectedResourceMetadata)
}
