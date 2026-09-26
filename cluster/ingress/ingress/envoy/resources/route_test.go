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

package resources

import (
	"regexp"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
)

func TestGetAPIAllowedOriginMatchers(t *testing.T) {
	newService := func(name, namespace string, isSystem, hasSubdomain bool) *corev1.Service {
		return &corev1.Service{
			Metadata: &metav1.Metadata{Name: name, IsSystem: isSystem},
			Spec:     &corev1.Service_Spec{IsPublic: true},
			Status: &corev1.Service_Status{
				NamespaceRef: &metav1.ObjectReference{Name: namespace},
				ManagedService: &corev1.Service_Status_ManagedService{
					HasSubdomain: hasSubdomain,
				},
			},
		}
	}

	matchers := getAPIAllowedOriginMatchers("example.com", []*corev1.Service{
		newService("default.default", "default", true, false),
		newService("portal.default", "default", true, false),
		newService("default.cordium", "cordium", true, true),
		newService("untrusted.default", "default", false, true),
	})

	var got []string
	for _, matcher := range matchers {
		if exact := matcher.GetExact(); exact != "" {
			got = append(got, "exact:"+exact)
		} else if regex := matcher.GetSafeRegex(); regex != nil {
			got = append(got, "regex:"+regex.Regex)
			_, err := regexp.Compile(regex.Regex)
			assert.NoError(t, err)
		}
	}

	assert.Equal(t, []string{
		"exact:https://cordium.example.com",
		`regex:^https://([a-zA-Z0-9-]+\.)+cordium\.example\.com$`,
		"exact:https://default.cordium.example.com",
		`regex:^https://([a-zA-Z0-9-]+\.)+default\.cordium\.example\.com$`,
		"exact:https://default.default.example.com",
		"exact:https://default.example.com",
		"exact:https://example.com",
		"exact:https://portal.default.example.com",
		"exact:https://portal.example.com",
	}, got)
}
