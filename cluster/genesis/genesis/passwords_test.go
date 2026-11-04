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

package genesis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func newPasswordBootstrap(t *testing.T) *cbootstrapv1.Config {
	t.Helper()
	bs := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, password: inline-postgres}\n  secondaryStorage:\n    redis: {host: redis, password: inline-redis}\n"), bs))
	return bs
}

func setPasswordReference(bs *cbootstrapv1.Config, storage, name, namespace, key string) {
	if storage == "postgres" {
		bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_{PasswordFromSecret: &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret{Name: name, Namespace: namespace, Key: key}}
	} else {
		bs.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret_{PasswordFromSecret: &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret{Name: name, Namespace: namespace, Key: key}}
	}
}

func initializePasswordStorage(ctx context.Context, g *Genesis, bs *cbootstrapv1.Config) error {
	return g.initStorage(ctx, &genesisutils.InstallCtx{Bootstrap: bs})
}

func resetPasswordEnvironment(t *testing.T) {
	t.Helper()
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, prefix := range []string{"OCTELIUM_POSTGRES_", "OCTELIUM_REDIS_"} {
		for _, suffix := range []string{"PASSWORD", "USERNAME", "HOST", "PORT", "DATABASE", "NOSSL", "USE_TLS"} {
			t.Setenv(prefix+suffix, "unchanged")
		}
	}
}

func assertPasswordResolutionReadOnly(t *testing.T, c *fake.Clientset) {
	t.Helper()
	for _, action := range c.Actions() {
		assert.Contains(t, []string{"get", "list"}, action.GetVerb())
	}
	assert.Equal(t, "unchanged", os.Getenv("OCTELIUM_POSTGRES_PASSWORD"))
	assert.Equal(t, "unchanged", os.Getenv("OCTELIUM_REDIS_PASSWORD"))
}

func TestStoragePasswordSelection(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, tc := range []struct {
			name, key string
			data      map[string][]byte
			want      string
		}{
			{name: "password-default", data: map[string][]byte{"password": []byte("password-value")}, want: "password-value"},
			{name: "data-default", data: map[string][]byte{"data": []byte("data-value")}, want: "data-value"},
			{name: "legacy-default-order", data: map[string][]byte{"password": []byte("password-value"), "data": []byte("data-value")}, want: "password-value"},
			{name: "legacy-empty-password-fallback", data: map[string][]byte{"password": {}, "data": []byte("data-value")}, want: "data-value"},
			{name: "explicit-custom", key: "custom", data: map[string][]byte{"custom": []byte("custom-value"), "password": []byte("fallback-value"), "data": []byte("other-value")}, want: "custom-value"},
			{name: "explicit-data", key: "data", data: map[string][]byte{"password": []byte("password-value"), "data": []byte("data-value")}, want: "data-value"},
			{name: "explicit-missing", key: "custom", data: map[string][]byte{"password": []byte("fallback-value"), "data": []byte("other-value")}},
			{name: "explicit-empty", key: "custom", data: map[string][]byte{"custom": {}, "password": []byte("fallback-value"), "data": []byte("other-value")}},
			{name: "explicit-nil", key: "custom", data: map[string][]byte{"custom": nil, "password": []byte("fallback-value")}},
			{name: "explicit-password-empty", key: "password", data: map[string][]byte{"password": {}, "data": []byte("fallback-value")}},
			{name: "missing-defaults", data: map[string][]byte{"custom": []byte("custom-value")}},
			{name: "empty-defaults", data: map[string][]byte{"password": {}, "data": nil}},
			{name: "no-data"},
			{name: "exact-whitespace", key: "custom", data: map[string][]byte{"custom": []byte(" \n\t")}, want: " \n\t"},
			{name: "case-sensitive-key", key: "PASSWORD", data: map[string][]byte{"PASSWORD": []byte("upper-value"), "password": []byte("lower-value")}, want: "upper-value"},
		} {
			t.Run(storage+"/"+tc.name, func(t *testing.T) {
				resetPasswordEnvironment(t)
				bs := newPasswordBootstrap(t)
				setPasswordReference(bs, storage, "credentials", "", tc.key)
				c := fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: tc.data})
				g := &Genesis{k8sC: c}
				err := initializePasswordStorage(t.Context(), g, bs)
				if tc.want == "" {
					require.Error(t, err)
					for _, value := range tc.data {
						if len(value) > 0 {
							assert.NotContains(t, err.Error(), string(value))
						}
					}
					assertPasswordResolutionReadOnly(t, c)
					return
				}
				require.NoError(t, err)
				name, key := "octelium-redis", "password"
				if storage == "postgres" {
					name, key = "octelium-postgres", "postgres-password"
				}
				secret, err := c.CoreV1().Secrets("octelium").Get(t.Context(), name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, tc.want, string(secret.Data[key]))
				source, err := c.CoreV1().Secrets("default").Get(t.Context(), "credentials", metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, tc.data, source.Data)
			})
		}
	}
}

func TestStoragePasswordReferenceValidation(t *testing.T) {
	for _, tc := range []struct {
		name, namespace, key string
		valid                bool
	}{
		{name: "credentials", valid: true},
		{name: "credentials.v2", namespace: "storage", key: "KEY-name.value_1", valid: true},
		{name: strings.Repeat("a", 253), namespace: strings.Repeat("a", 63), key: strings.Repeat("a", 253), valid: true},
		{name: ""}, {name: "Credentials"}, {name: "a/b"}, {name: " credentials"}, {name: strings.Repeat("a", 254)},
		{name: "credentials", namespace: "a.b"}, {name: "credentials", namespace: "Storage"}, {name: "credentials", namespace: "a/b"}, {name: "credentials", namespace: strings.Repeat("a", 64)},
		{name: "credentials", key: "a/b"}, {name: "credentials", key: "bad key"}, {name: "credentials", key: ".."}, {name: "credentials", key: strings.Repeat("a", 254)},
	} {
		t.Run(fmt.Sprintf("%s/%s/%s", tc.name, tc.namespace, tc.key), func(t *testing.T) {
			err := validatePasswordSecretReference(tc.name, tc.namespace, tc.key)
			if tc.valid {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, storage := range []string{"postgres", "redis"} {
				resetPasswordEnvironment(t)
				bs := newPasswordBootstrap(t)
				setPasswordReference(bs, storage, tc.name, tc.namespace, tc.key)
				c := fake.NewSimpleClientset()
				require.Error(t, initializePasswordStorage(t.Context(), &Genesis{k8sC: c}, bs))
				assert.Empty(t, c.Actions())
				assertPasswordResolutionReadOnly(t, c)
			}
		})
	}
}

func TestStoragePasswordsUseOneSnapshotPerSecret(t *testing.T) {
	resetPasswordEnvironment(t)
	bs := newPasswordBootstrap(t)
	setPasswordReference(bs, "postgres", "credentials", "", "pg")
	setPasswordReference(bs, "redis", "credentials", "default", "redis")
	c := fake.NewSimpleClientset()
	calls := 0
	c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		assert.Equal(t, "default", action.GetNamespace())
		return true, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"pg": []byte(fmt.Sprintf("pg-%d", calls)), "redis": []byte(fmt.Sprintf("redis-%d", calls))}}, nil
	})
	g := &Genesis{k8sC: c}
	for i := 1; i <= 2; i++ {
		passwords, err := g.resolveStoragePasswords(t.Context(), bs)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("pg-%d", i), passwords.postgres)
		assert.Equal(t, fmt.Sprintf("redis-%d", i), passwords.redis)
		assert.Equal(t, i, calls)
	}
	assertPasswordResolutionReadOnly(t, c)
}

func TestStoragePasswordReferenceNamespaces(t *testing.T) {
	resetPasswordEnvironment(t)
	bs := newPasswordBootstrap(t)
	setPasswordReference(bs, "postgres", "credentials", "", "password")
	setPasswordReference(bs, "redis", "credentials", "storage", "password")
	c := fake.NewSimpleClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("pg-value")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "storage"}, Data: map[string][]byte{"password": []byte("redis-value")}},
	)
	passwords, err := (&Genesis{k8sC: c}).resolveStoragePasswords(t.Context(), bs)
	require.NoError(t, err)
	assert.Equal(t, "pg-value", passwords.postgres)
	assert.Equal(t, "redis-value", passwords.redis)
	assert.Len(t, c.Actions(), 2)
	assertPasswordResolutionReadOnly(t, c)
}

func TestStoragePasswordReadFailures(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, failure := range []string{"transient", "forbidden", "not-found", "canceled", "deadline"} {
			t.Run(storage+"/"+failure, func(t *testing.T) {
				resetPasswordEnvironment(t)
				bs := newPasswordBootstrap(t)
				setPasswordReference(bs, storage, "credentials", "default", "password")
				c := fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("secret-value")}})
				calls := 0
				c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					calls++
					switch failure {
					case "transient":
						if calls == 1 {
							return true, nil, io.ErrUnexpectedEOF
						}
					case "forbidden":
						return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "credentials", io.EOF)
					case "not-found":
						return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), "credentials")
					case "deadline":
						return true, nil, k8serr.NewServiceUnavailable("temporary outage")
					}
					return false, nil, nil
				})
				g := &Genesis{k8sC: c}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if failure == "canceled" {
					cancel()
				}
				if failure == "deadline" {
					ctx, cancel = context.WithTimeout(t.Context(), 30*time.Millisecond)
					defer cancel()
				}
				err := initializePasswordStorage(ctx, g, bs)
				switch failure {
				case "transient":
					require.NoError(t, err)
					assert.Equal(t, 2, calls)
					return
				case "forbidden":
					require.True(t, k8serr.IsForbidden(err))
					assert.Equal(t, 1, calls)
				case "not-found":
					require.True(t, k8serr.IsNotFound(err))
					assert.Equal(t, 1, calls)
				case "canceled":
					require.ErrorIs(t, err, context.Canceled)
					assert.Zero(t, calls)
				case "deadline":
					require.ErrorIs(t, err, context.DeadlineExceeded)
					assert.Equal(t, 1, calls)
				}
				assertPasswordResolutionReadOnly(t, c)
			})
		}
	}
}

func TestStoragePasswordsPreserveLegacyInlineInputs(t *testing.T) {
	for _, omitted := range []bool{false, true} {
		t.Run(fmt.Sprint(omitted), func(t *testing.T) {
			resetPasswordEnvironment(t)
			bs := newPasswordBootstrap(t)
			bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password{}
			bs.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{}
			if omitted {
				bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = nil
				bs.Spec.SecondaryStorage.GetRedis().PasswordType = nil
			}
			c := fake.NewSimpleClientset()
			passwords, err := (&Genesis{k8sC: c}).resolveStoragePasswords(t.Context(), bs)
			require.NoError(t, err)
			assert.Equal(t, &storagePasswords{}, passwords)
			assert.Empty(t, c.Actions())
			assertPasswordResolutionReadOnly(t, c)
		})
	}
}

func TestStoragePasswordNilReferences(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, wrapper := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapper=%t", storage, wrapper), func(t *testing.T) {
				resetPasswordEnvironment(t)
				bs := newPasswordBootstrap(t)
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
				c := fake.NewSimpleClientset()
				require.Error(t, initializePasswordStorage(t.Context(), &Genesis{k8sC: c}, bs))
				assert.Empty(t, c.Actions())
				assertPasswordResolutionReadOnly(t, c)
			})
		}
	}
}

func TestStoragePasswordHTTPRecovery(t *testing.T) {
	for _, failure := range []string{"disconnect", "unavailable", "missing-key", "forbidden"} {
		t.Run(failure, func(t *testing.T) {
			var reads, unexpected atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/default/secrets/credentials" {
					unexpected.Add(1)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				n := reads.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if n == 1 && failure == "disconnect" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				if (n == 1 && failure == "unavailable") || failure == "forbidden" {
					code, reason := http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable
					if failure == "forbidden" {
						code, reason = http.StatusForbidden, metav1.StatusReasonForbidden
					}
					w.WriteHeader(code)
					assert.NoError(t, json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: int32(code), Reason: reason}))
					return
				}
				data := map[string][]byte{"password": []byte("fallback-value"), "pg": []byte("pg-value"), "redis": []byte("redis-value")}
				if failure == "missing-key" {
					delete(data, "redis")
				}
				assert.NoError(t, json.NewEncoder(w).Encode(&corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: data}))
			}))
			defer server.Close()
			c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: -1})
			require.NoError(t, err)
			bs := newPasswordBootstrap(t)
			setPasswordReference(bs, "postgres", "credentials", "default", "pg")
			setPasswordReference(bs, "redis", "credentials", "", "redis")
			passwords, err := (&Genesis{k8sC: c}).resolveStoragePasswords(t.Context(), bs)
			if failure == "forbidden" {
				require.True(t, k8serr.IsForbidden(err))
				assert.Equal(t, int32(1), reads.Load())
			} else if failure == "missing-key" {
				require.ErrorContains(t, err, "missing or empty")
				assert.Equal(t, int32(1), reads.Load())
			} else {
				require.NoError(t, err)
				assert.Equal(t, &storagePasswords{postgres: "pg-value", redis: "redis-value"}, passwords)
				assert.Equal(t, int32(2), reads.Load())
			}
			assert.Zero(t, unexpected.Load())
		})
	}
}

func TestStoragePasswordHTTPStallCancellation(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(canceled) }))
	defer server.Close()
	c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: -1})
	require.NoError(t, err)
	bs := newPasswordBootstrap(t)
	setPasswordReference(bs, "redis", "credentials", "default", "password")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := (&Genesis{k8sC: c}).resolveStoragePasswords(ctx, bs); result <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("Secret read did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("Secret read did not stop")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP request was not canceled")
	}
}

func TestPasswordResolutionFailurePreservesExistingStorageSecrets(t *testing.T) {
	resetPasswordEnvironment(t)
	bs := newPasswordBootstrap(t)
	setPasswordReference(bs, "redis", "credentials", "default", "missing")
	pg := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-postgres", Namespace: "octelium", UID: "preserved-postgres", Annotations: map[string]string{"custom": "preserved"}}, Data: map[string][]byte{"postgres-password": []byte("stored-postgres"), "custom": []byte("preserved")}}
	redis := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-redis", Namespace: "octelium", UID: "preserved-redis"}, Data: map[string][]byte{"password": []byte("stored-redis")}}
	c := fake.NewSimpleClientset(pg, redis, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("fallback-value")}})
	require.Error(t, initializePasswordStorage(t.Context(), &Genesis{k8sC: c}, bs))
	assertPasswordResolutionReadOnly(t, c)
	for _, before := range []*corev1.Secret{pg, redis} {
		stored, err := c.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), "octelium", before.Name)
		require.NoError(t, err)
		assert.Equal(t, before, stored)
	}
}
