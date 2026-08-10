//go:build e2e

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

package tests

import (
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func testOcteliumctlCommands(t *testing.T, h *harness.H) {
	t.Run("Get", func(t *testing.T) {
		aliases := []string{
			"cc", "clusterconfig",
			"service", "svc",
			"policy", "pol",
			"user", "usr",
			"session", "sess",
			"gateway", "gw",
			"secret", "sec",
			"credential", "cred",
			"group", "grp",
			"namespace", "ns",
			"device", "dev",
			"identityprovider", "idp",
			"region", "rgn",
			"config", "cfg", "conf",
		}

		for _, alias := range aliases {
			h.MustRun(t, fmt.Sprintf("octeliumctl get %s", alias))
		}
	})

	t.Run("ConfigFromFile", func(t *testing.T) {
		h.MustRun(t, fmt.Sprintf("octeliumctl create config %s --file %s",
			utilrand.GetRandomStringCanonical(8), h.State.KubeconfigPath))
	})

	t.Run("ConfigLifecycle", func(t *testing.T) {
		name := utilrand.GetRandomStringCanonical(8)

		h.MustRun(t, fmt.Sprintf("octeliumctl create cfg %s --value %s",
			name, utilrand.GetRandomStringCanonical(32)))
		h.MustRun(t, fmt.Sprintf("octeliumctl get cfg %s", name))
		h.MustRun(t, fmt.Sprintf("octeliumctl del cfg %s", name))
	})

	t.Run("JSONOutput", func(t *testing.T) {
		res := &corev1.ServiceList{}
		h.MustOutputProto(t, "octeliumctl get svc -o json", res)
		assert.True(t, len(res.Items) > 0)
	})
}

func testOcteliumCommands(t *testing.T, h *harness.H) {
	t.Run("Get", func(t *testing.T) {
		for _, alias := range []string{"service", "svc", "namespace", "ns"} {
			h.MustRun(t, fmt.Sprintf("octelium get %s", alias))
		}

		h.MustRun(t, "octelium status")
	})

	t.Run("JSONOutput", func(t *testing.T) {
		res := &userv1.ServiceList{}
		h.MustOutputProto(t, "octelium get svc -o json", res)
		assert.True(t, len(res.Items) > 0)
	})
}
