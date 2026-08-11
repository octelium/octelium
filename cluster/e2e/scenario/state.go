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
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
)

const StatePathEnv = "OCTELIUM_E2E_STATE"

type State struct {
	ScenarioID string       `json:"scenarioID"`
	Caps       Capabilities `json:"caps"`

	Domain         string `json:"domain"`
	KubeconfigPath string `json:"kubeconfigPath"`
	HomeDir        string `json:"homeDir"`
	ExternalIP     string `json:"externalIP"`

	PostgresPassword string `json:"postgresPassword,omitempty"`
	RedisPassword    string `json:"redisPassword,omitempty"`

	AuthTokenPath string `json:"authTokenPath,omitempty"`
	CertPath      string `json:"certPath,omitempty"`
	KeyPath       string `json:"keyPath,omitempty"`

	ProvisionedAt time.Time `json:"provisionedAt,omitempty"`
	InstalledAt   time.Time `json:"installedAt,omitempty"`

	Extra map[string]string `json:"extra,omitempty"`
}

func (s *State) Set(k, v string) {
	if s.Extra == nil {
		s.Extra = map[string]string{}
	}
	s.Extra[k] = v
}

func (s *State) Get(k string) string {
	return s.Extra[k]
}

func DefaultStatePath() string {
	if val := os.Getenv(StatePathEnv); val != "" {
		return val
	}
	return filepath.Join(os.TempDir(), "octelium-e2e", "state.json")
}

func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf(
				"No e2e state at %s. Run the provision/prepare/install stages first", path)
		}
		return nil, err
	}

	ret := &State{}
	if err := json.Unmarshal(b, ret); err != nil {
		return nil, errors.Errorf("Could not parse the e2e state at %s: %+v", path, err)
	}

	return ret, nil
}

func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
