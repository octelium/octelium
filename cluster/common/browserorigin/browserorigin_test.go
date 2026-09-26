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

package browserorigin

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
)

func TestSystemServiceHosts(t *testing.T) {
	newService := func(name, namespace string, isSystem, isPublic, isManaged, hasSubdomain bool) *corev1.Service {
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{Name: name, IsSystem: isSystem},
			Spec:     &corev1.Service_Spec{IsPublic: isPublic},
			Status: &corev1.Service_Status{
				NamespaceRef: &metav1.ObjectReference{Name: namespace},
			},
		}
		if isManaged {
			svc.Status.ManagedService = &corev1.Service_Status_ManagedService{
				HasSubdomain: hasSubdomain,
			}
		}
		return svc
	}

	hosts := SystemServiceHosts("EXAMPLE.COM.", []*corev1.Service{
		newService("default.default", "default", true, true, true, false),
		newService("portal.default", "default", true, true, true, false),
		newService("default.cordium", "cordium", true, true, true, true),
		newService("console.octelium", "octelium", true, true, true, false),
		newService("app.default", "default", false, true, true, true),
		newService("private.octelium", "octelium", true, false, true, false),
		newService("external.octelium", "octelium", true, true, false, false),
		newService("portal.default", "default", true, true, true, true),
		nil,
	})

	assert.Equal(t, []Host{
		{Name: "console.octelium.example.com"},
		{Name: "cordium.example.com", AllowSubdomains: true},
		{Name: "default.cordium.example.com", AllowSubdomains: true},
		{Name: "default.default.example.com"},
		{Name: "default.example.com"},
		{Name: "example.com"},
		{Name: "portal.default.example.com", AllowSubdomains: true},
		{Name: "portal.example.com", AllowSubdomains: true},
	}, hosts)
}

func TestIsAllowed(t *testing.T) {
	hosts := []Host{
		{Name: "example.com"},
		{Name: "portal.example.com"},
		{Name: "cordium.example.com", AllowSubdomains: true},
	}

	for _, origin := range []string{
		"https://example.com",
		"https://PORTAL.EXAMPLE.COM",
		"https://cordium.example.com",
		"https://workspace.cordium.example.com",
		"https://nested.workspace.cordium.example.com",
	} {
		assert.True(t, IsAllowed(origin, hosts), origin)
	}

	for _, origin := range []string{
		"",
		"http://example.com",
		"https://example.com:443",
		"https://evil.example.com",
		"https://cordium.example.com.evil.com",
		"https://evilcordium.example.com",
		"https://workspace.cordium.example.com/path",
		"https://workspace.cordium.example.com?query=true",
		"https://user@workspace.cordium.example.com",
	} {
		assert.False(t, IsAllowed(origin, hosts), origin)
	}
}
