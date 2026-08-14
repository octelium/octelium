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

import "slices"

type Customizer func(*Scenario) error

var customizers []Customizer

func Customize(fns ...Customizer) {
	customizers = append(customizers, fns...)
}

func applyCustomizers(s *Scenario) error {
	for _, fn := range customizers {
		if fn == nil {
			continue
		}
		if err := fn(s); err != nil {
			return err
		}
	}

	return nil
}

func (s *Scenario) AddComponents(names ...string) {
	if len(s.Components) == 0 {
		s.Components = slices.Clone(DefaultComponents)
	}

	for _, name := range names {
		if !slices.Contains(s.Components, name) {
			s.Components = append(s.Components, name)
		}
	}
}

func (s *Scenario) AddWaitDeployments(names ...string) {
	for _, name := range names {
		if !slices.Contains(s.Install.WaitDeployments, name) {
			s.Install.WaitDeployments = append(s.Install.WaitDeployments, name)
		}
	}
}

func (s *Scenario) SetEnv(k, v string) {
	if s.Install.Env == nil {
		s.Install.Env = map[string]string{}
	}
	s.Install.Env[k] = v
}

func (s *Scenario) AddPostProvision(steps ...Step) {
	s.Hooks.PostProvision = append(s.Hooks.PostProvision, steps...)
}

func (s *Scenario) AddPostPrepare(steps ...Step) {
	s.Hooks.PostPrepare = append(s.Hooks.PostPrepare, steps...)
}

func (s *Scenario) AddPostInstall(steps ...Step) {
	s.Hooks.PostInstall = append(s.Hooks.PostInstall, steps...)
}

func (s *Scenario) AddCaps(caps ...Capability) {
	for _, c := range caps {
		if !s.Caps.Has(c) {
			s.Caps = append(s.Caps, c)
		}
	}
}
