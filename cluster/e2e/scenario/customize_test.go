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

package scenario

import (
	"context"
	"slices"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withCustomizers(t *testing.T, fns ...Customizer) {
	t.Helper()

	prev := customizers
	t.Cleanup(func() { customizers = prev })

	customizers = nil
	Customize(fns...)
}

func TestCustomizersApplyOncePerScenario(t *testing.T) {
	var calls int
	withCustomizers(t, func(s *Scenario) error {
		calls++
		s.AddComponents("octeliumee-billing")
		s.AddWaitDeployments("svc-billing-octelium-ee")
		s.SetEnv("OCTELIUM_EE", "true")
		s.AddPostInstall(Step{Name: "ee/package", Run: func(context.Context, *Runner) error {
			return nil
		}})
		return nil
	})

	t.Run("a Scenario built from a Spec", func(t *testing.T) {
		calls = 0

		s, err := Get("k3s-flannel")
		require.NoError(t, err)

		assert.Equal(t, 1, calls, "the Customizer must run exactly once")
		assert.Contains(t, s.ComponentList(), "octeliumee-billing")
		assert.Contains(t, s.ComponentList(), "rscserver",
			"the Scenario's own components are kept")
		assert.Contains(t, s.Install.WaitDeployments, "svc-billing-octelium-ee")
		assert.Contains(t, s.Install.WaitDeployments, "svc-default-octelium-api")
		assert.Equal(t, "true", s.Install.Env["OCTELIUM_EE"])
		assert.Len(t, s.Hooks.PostInstall, 1)
	})

	t.Run("a Scenario that also carries SPIFFE", func(t *testing.T) {
		calls = 0

		s, err := Get("k3s-flannel-spiffe")
		require.NoError(t, err)

		assert.Equal(t, 1, calls)
		assert.Contains(t, s.ComponentList(), "octeliumee-billing")
		assert.True(t, s.Caps.Has(CapSPIFFE))

		var names []string
		for _, step := range s.Hooks.PostPrepare {
			names = append(names, step.Name)
		}
		assert.Contains(t, names, "spiffe/spire",
			"the module's own hooks survive customization")
	})

	t.Run("a Scenario from the registry", func(t *testing.T) {
		calls = 0

		Register("customize-test", func() *Scenario {
			ret := baseScenario()
			ret.Provisioner = k3sProvisioner(CNIFlannel)
			return ret
		})
		t.Cleanup(func() { delete(registry, "customize-test") })

		s, err := Get("customize-test")
		require.NoError(t, err)

		assert.Equal(t, 1, calls)
		assert.Equal(t, "customize-test", s.ID)
		assert.Contains(t, s.ComponentList(), "octeliumee-billing")
	})
}

func TestCustomizersRunInOrderAndReportErrors(t *testing.T) {
	t.Run("in registration order", func(t *testing.T) {
		var order []string
		withCustomizers(t,
			func(s *Scenario) error { order = append(order, "first"); return nil },
			func(s *Scenario) error { order = append(order, "second"); return nil },
		)

		_, err := Get("k3s-flannel")
		require.NoError(t, err)
		assert.Equal(t, []string{"first", "second"}, order)
	})

	t.Run("a failing Customizer fails the Scenario", func(t *testing.T) {
		withCustomizers(t, func(s *Scenario) error {
			return errors.Errorf("the enterprise package is not published for %s", s.ID)
		})

		_, err := Get("k3s-flannel")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "k3s-flannel")
	})
}

func TestScenarioHelpersDoNotMutateTheDefaults(t *testing.T) {
	withCustomizers(t)

	before := slices.Clone(DefaultComponents)

	s, err := Get("k3s-flannel")
	require.NoError(t, err)

	s.AddComponents("octeliumee-billing")

	assert.Equal(t, before, DefaultComponents,
		"a Scenario that had no components of its own must copy the defaults, not append to them")

	other, err := Get("k3s-flannel")
	require.NoError(t, err)
	assert.NotContains(t, other.ComponentList(), "octeliumee-billing")
}
