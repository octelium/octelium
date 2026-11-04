// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package initcmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/require"
)

func TestBootstrapPasswordReferences(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, tc := range []struct {
			name, namespace, key string
			valid                bool
		}{
			{name: "credentials", valid: true},
			{name: "credentials.v2", namespace: "storage", key: "KEY-name.value_1", valid: true},
			{name: strings.Repeat("a", 253), namespace: strings.Repeat("a", 63), key: strings.Repeat("a", 253), valid: true},
			{}, {name: "Credentials"}, {name: "a/b"}, {name: " credentials"}, {name: strings.Repeat("a", 254)},
			{name: "credentials", namespace: "a.b"}, {name: "credentials", namespace: "Storage"}, {name: "credentials", namespace: "a/b"}, {name: "credentials", namespace: strings.Repeat("a", 64)},
			{name: "credentials", key: "a/b"}, {name: "credentials", key: "bad key"}, {name: "credentials", key: ".."}, {name: "credentials", key: strings.Repeat("a", 254)},
		} {
			t.Run(fmt.Sprintf("%s/%s/%s/%s", storage, tc.name, tc.namespace, tc.key), func(t *testing.T) {
				bs := &cbootstrapv1.Config{}
				require.NoError(t, pbutils.UnmarshalYAML([]byte("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, password: postgres-secret}\n  secondaryStorage:\n    redis: {host: redis, password: redis-secret}\n"), bs))
				if storage == "postgres" {
					bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_{PasswordFromSecret: &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret{Name: tc.name, Namespace: tc.namespace, Key: tc.key}}
				} else {
					bs.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret_{PasswordFromSecret: &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret{Name: tc.name, Namespace: tc.namespace, Key: tc.key}}
				}
				err := validateBootstrap(bs)
				if tc.valid {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, "passwordFromSecret")
				}
			})
		}
	}
}

func TestBootstrapNilPasswordReferences(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, wrapper := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapper=%t", storage, wrapper), func(t *testing.T) {
				bs := &cbootstrapv1.Config{}
				require.NoError(t, pbutils.UnmarshalYAML([]byte("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, password: postgres-secret}\n  secondaryStorage:\n    redis: {host: redis, password: redis-secret}\n"), bs))
				if storage == "postgres" {
					if wrapper {
						bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = (*cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_)(nil)
					} else {
						bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_{}
					}
				} else {
					if wrapper {
						bs.Spec.SecondaryStorage.GetRedis().PasswordType = (*cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret_)(nil)
					} else {
						bs.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret_{}
					}
				}
				require.ErrorContains(t, validateBootstrap(bs), "passwordFromSecret")
			})
		}
	}
}
