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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nadclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"

	fakenad "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"

	k8scorev1 "k8s.io/api/core/v1"

	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	fakek8s "k8s.io/client-go/kubernetes/fake"

	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8stesting "k8s.io/client-go/testing"
)

type FakeClient struct {
	K8sC kubernetes.Interface
	NadC nadclientset.Interface
}

func resetOctopsStorageEnv(t *testing.T) {
	t.Helper()
	for _, prefix := range []string{"OCTELIUM_POSTGRES_", "OCTELIUM_REDIS_"} {
		for _, suffix := range []string{"DATABASE", "USERNAME", "PASSWORD", "HOST", "PORT", "NOSSL", "USE_TLS"} {
			t.Setenv(prefix+suffix, "")
		}
	}
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
}

func TestOctopsStorageBootstrap(t *testing.T) {
	for _, tc := range []struct {
		name, namespace, key string
		data                 map[string][]byte
		password             string
	}{
		{"inline", "", "", nil, "inline-secret"},
		{"default namespace password", "", "", map[string][]byte{"password": []byte("password-secret"), "data": []byte("other-secret")}, "password-secret"},
		{"default namespace data", "", "", map[string][]byte{"data": []byte("data-secret")}, "data-secret"},
		{"custom key", "storage", "custom", map[string][]byte{"custom": []byte("custom-secret"), "password": []byte("other-secret")}, "custom-secret"},
	} {
		for _, tls := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tls=%t", tc.name, tls), func(t *testing.T) {
				resetOctopsStorageEnv(t)
				bs := &cbootstrapv1.Config{}
				passwordSpec := "password: inline-secret"
				if tc.data != nil {
					passwordSpec = fmt.Sprintf("passwordFromSecret: {name: storage-auth, namespace: '%s', key: '%s'}", tc.namespace, tc.key)
				}
				require.NoError(t, pbutils.UnmarshalYAML([]byte(fmt.Sprintf("spec:\n  primaryStorage:\n    postgresql: {host: postgres.storage.svc, username: installer, database: octelium, port: 6432, isTLS: %t, %s}\n  secondaryStorage:\n    redis: {host: redis.storage.svc, username: redis-user, database: 7, port: 6380, isTLS: %t, %s}\n", tls, passwordSpec, tls, passwordSpec)), bs))
				c := fakek8s.NewSimpleClientset()
				if tc.data != nil {
					namespace := tc.namespace
					if namespace == "" {
						namespace = "default"
					}
					require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "storage-auth", Namespace: namespace}, Data: tc.data}))
				}
				g := &Genesis{k8sC: c}
				require.NoError(t, g.initStorage(context.Background(), &genesisutils.InstallCtx{Bootstrap: bs}))
				pg, err := c.CoreV1().Secrets("octelium").Get(context.Background(), "octelium-postgres", k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, map[string][]byte{"postgres-password": []byte(tc.password), "username": []byte("installer"), "database": []byte("octelium"), "host": []byte("postgres.storage.svc"), "port": []byte("6432"), "no_ssl": []byte(fmt.Sprint(!tls))}, pg.Data)
				redis, err := c.CoreV1().Secrets("octelium").Get(context.Background(), "octelium-redis", k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, map[string][]byte{"password": []byte(tc.password), "username": []byte("redis-user"), "database": []byte("7"), "host": []byte("redis.storage.svc"), "port": []byte("6380"), "use_tls": []byte(fmt.Sprint(tls))}, redis.Data)
				for key, want := range map[string]string{"OCTELIUM_POSTGRES_PASSWORD": tc.password, "OCTELIUM_POSTGRES_USERNAME": "installer", "OCTELIUM_POSTGRES_DATABASE": "octelium", "OCTELIUM_POSTGRES_HOST": "postgres.storage.svc", "OCTELIUM_POSTGRES_PORT": "6432", "OCTELIUM_REDIS_PASSWORD": tc.password, "OCTELIUM_REDIS_USERNAME": "redis-user", "OCTELIUM_REDIS_DATABASE": "7", "OCTELIUM_REDIS_HOST": "redis.storage.svc", "OCTELIUM_REDIS_PORT": "6380"} {
					assert.Equal(t, want, os.Getenv(key), key)
				}
				if tls {
					assert.Empty(t, os.Getenv("OCTELIUM_POSTGRES_NOSSL"))
					assert.Equal(t, "true", os.Getenv("OCTELIUM_REDIS_USE_TLS"))
				} else {
					assert.Equal(t, "true", os.Getenv("OCTELIUM_POSTGRES_NOSSL"))
					assert.Empty(t, os.Getenv("OCTELIUM_REDIS_USE_TLS"))
				}
			})
		}
	}
}

func TestOctopsStorageBootstrapErrors(t *testing.T) {
	for _, data := range []string{"{}", "spec: {}", "spec: {primaryStorage: {postgresql: {}}}"} {
		bs := &cbootstrapv1.Config{}
		require.NoError(t, pbutils.UnmarshalYAML([]byte(data), bs))
		g := &Genesis{k8sC: fakek8s.NewSimpleClientset()}
		assert.Error(t, g.initStorage(context.Background(), &genesisutils.InstallCtx{Bootstrap: bs}))
	}
	for _, storage := range []string{"postgresql", "redis"} {
		for _, failure := range []string{"missing reference", "missing secret", "forbidden", "create"} {
			t.Run(storage+"/"+failure, func(t *testing.T) {
				resetOctopsStorageEnv(t)
				bs := &cbootstrapv1.Config{}
				require.NoError(t, pbutils.UnmarshalYAML([]byte("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, password: secret}\n  secondaryStorage:\n    redis: {host: redis, password: secret}"), bs))
				c := fakek8s.NewSimpleClientset()
				if failure != "create" {
					name := "credentials"
					if failure == "missing reference" {
						name = ""
					}
					if storage == "postgresql" {
						bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_{PasswordFromSecret: &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret{Name: name}}
					} else {
						bs.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret_{PasswordFromSecret: &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_PasswordFromSecret{Name: name}}
					}
					if failure == "forbidden" {
						c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
							return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "credentials", fmt.Errorf("not permitted"))
						})
					}
				} else {
					c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
						secret := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret)
						if (storage == "postgresql" && secret.Name == "octelium-postgres") || (storage == "redis" && secret.Name == "octelium-redis") {
							return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), secret.Name, fmt.Errorf("not permitted"))
						}
						return false, nil, nil
					})
				}
				g := &Genesis{k8sC: c}
				err := g.initStorage(context.Background(), &genesisutils.InstallCtx{Bootstrap: bs})
				require.Error(t, err)
				switch failure {
				case "missing reference":
					assert.ErrorContains(t, err, "name of passwordFromSecret is empty")
				case "missing secret":
					assert.True(t, k8serr.IsNotFound(err))
				default:
					assert.True(t, k8serr.IsForbidden(err))
				}
			})
		}
	}
}

func TestOctopsNamespaceErrors(t *testing.T) {
	for _, verb := range []string{"get", "delete", "create"} {
		t.Run(verb, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			if verb == "delete" {
				require.NoError(t, c.Tracker().Add(&k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium"}}))
			}
			c.PrependReactor(verb, "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "octelium", fmt.Errorf("not permitted"))
			})
			g := &Genesis{k8sC: c}
			assert.True(t, k8serr.IsForbidden(g.setNamespace(context.Background())))
			actions := c.Actions()
			assert.Equal(t, verb, actions[len(actions)-1].GetVerb())
		})
	}
}

func now() k8smetav1.Time {
	return k8smetav1.Time{
		time.Now(),
	}
}

func newFakeClient() *FakeClient {
	k8sC := fakek8s.NewSimpleClientset()

	k8sC.PrependReactor("*", "*", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		switch {
		case action.Matches("create", "secrets"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Secret)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(vutils.UUIDv4())
		case action.Matches("create", "pods"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Pod)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(vutils.UUIDv4())
		case action.Matches("create", "nodes"):
			obj := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Node)
			obj.CreationTimestamp = now()
			obj.UID = types.UID(vutils.UUIDv4())
		}
		return
	})

	return &FakeClient{
		K8sC: k8sC,
		NadC: fakenad.NewSimpleClientset(),
	}
}

func setClusterConfigRegion(ctx context.Context, k8sC kubernetes.Interface, region *corev1.Region, db string) error {

	dataMap := map[string][]byte{
		"region": pbutils.MarshalMust(region),
		"bootstrap": pbutils.MarshalMust(&cbootstrapv1.Config{
			Spec: &cbootstrapv1.Config_Spec{
				PrimaryStorage: &cbootstrapv1.Config_Spec_PrimaryStorage{
					Type: &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_{
						Postgresql: &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql{
							Database: db,
						},
					},
				},
				SecondaryStorage: &cbootstrapv1.Config_Spec_SecondaryStorage{
					Type: &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_{
						Redis: &cbootstrapv1.Config_Spec_SecondaryStorage_Redis{},
					},
				},
			},
		}),
	}

	{

		if secret, err := k8sC.CoreV1().Secrets("default").Get(ctx, "octelium-init", k8smetav1.GetOptions{}); err == nil {
			secret.Data = dataMap
			_, err := k8sC.CoreV1().Secrets("default").Update(ctx, secret, k8smetav1.UpdateOptions{})
			if err != nil {
				return err
			}
		} else if k8serr.IsNotFound(err) {
			_, err := k8sC.CoreV1().Secrets("default").Create(ctx, &k8scorev1.Secret{
				ObjectMeta: k8smetav1.ObjectMeta{
					Name: "octelium-init",
				},
				Data: dataMap,
			}, k8smetav1.CreateOptions{})
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func TestRunInitNodesReadiness(t *testing.T) {
	previous := ldflags.TestMode
	t.Cleanup(func() { ldflags.TestMode = previous })
	ldflags.TestMode = "false"

	ready := k8scorev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "ready"},
		Status: k8scorev1.NodeStatus{
			Conditions: []k8scorev1.NodeCondition{{Type: k8scorev1.NodeReady, Status: k8scorev1.ConditionTrue}},
		},
	}
	missing := k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "missing"}}
	notReady := *ready.DeepCopy()
	notReady.Status.Conditions[0].Status = k8scorev1.ConditionFalse
	unknown := *ready.DeepCopy()
	unknown.Status.Conditions[0].Status = k8scorev1.ConditionUnknown

	for _, tc := range []struct {
		name  string
		nodes []k8scorev1.Node
		ready bool
	}{
		{"Ready", []k8scorev1.Node{ready}, true},
		{"NoNodes", nil, false},
		{"MissingReady", []k8scorev1.Node{missing}, false},
		{"NotReady", []k8scorev1.Node{notReady}, false},
		{"Unknown", []k8scorev1.Node{unknown}, false},
		{"MixedMissingReady", []k8scorev1.Node{ready, missing}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			timeout := 100 * time.Millisecond
			if tc.ready {
				timeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			client := fakek8s.NewClientset()
			wantErr := fmt.Errorf("Stopped after the readiness check")
			progressed := false
			client.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.Matches("list", "nodes") && action.(k8stesting.ListAction).GetListRestrictions().Labels.Empty() {
					if err := ctx.Err(); err != nil {
						return true, nil, err
					}
					return true, &k8scorev1.NodeList{Items: tc.nodes}, nil
				}
				progressed = true
				return true, nil, wantErr
			})
			g := &Genesis{k8sC: client}
			err := g.RunInit(ctx, nil)
			if tc.ready {
				assert.ErrorIs(t, err, wantErr)
				assert.True(t, progressed)
			} else {
				assert.ErrorIs(t, err, context.DeadlineExceeded)
				assert.False(t, progressed)
			}
		})
	}
}

func TestRunInit(t *testing.T) {

	ldflags.TestMode = "true"
	ldflags.PrivateRegistry = "false"

	os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")

	os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
	os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
	os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")

	ctx := context.Background()
	dbName := fmt.Sprintf("octelium%s", utilrand.GetRandomStringLowercase(6))

	os.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")

	os.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
	os.Setenv("OCTELIUM_POSTGRES_USERNAME", "postgres")
	os.Setenv("OCTELIUM_POSTGRES_PASSWORD", "postgres")

	db, err := postgresutils.NewDBWithNODB()
	assert.Nil(t, err)

	defer db.Close()

	// ctx := context.Background()
	// c := newFakeClient()

	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s;", dbName))
	assert.Nil(t, err)

	os.Setenv("OCTELIUM_POSTGRES_DATABASE", dbName)

	region := &corev1.Region{
		Kind: "Region",
		Metadata: &metav1.Metadata{
			Name: "default",
		},
		Spec:   &corev1.Region_Spec{},
		Status: &corev1.Region_Status{},
	}

	{
		c := newFakeClient()
		g := &Genesis{
			k8sC: c.K8sC,
			nadC: c.NadC,
		}

		err := setClusterConfigRegion(ctx, g.k8sC, region, dbName)
		assert.Nil(t, err)

		err = g.RunInit(ctx, nil)
		assert.Nil(t, err, "%+v", err)

		{
			sec, err := g.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: vutils.ClusterCertSecretName,
			})
			assert.Nil(t, err)

			assert.True(t, vutils.IsCertReady(sec))
		}

		region, err = g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Name: region.Metadata.Name,
		})
		assert.Nil(t, err)

		regionHostname := fmt.Sprintf("octelium-region-%s", strings.Split(region.Metadata.Uid, "-")[4])
		assert.Equal(t, regionHostname, region.Status.PublicHostname)

		{
			svcList, err := g.getAllServices(ctx, region)
			assert.Nil(t, err)
			assert.True(t, len(svcList) > 0)
		}

		{
			region.Status.PublicHostname = "_r-default"
			region, err = g.octeliumC.CoreC().UpdateRegion(ctx, region)
			assert.Nil(t, err)
			assert.Equal(t, "_r-default", region.Status.PublicHostname)
		}

		{
			err = g.RunUpgrade(ctx, nil)
			assert.Nil(t, err, "%+v", err)

			region, err = g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
				Name: region.Metadata.Name,
			})
			assert.Nil(t, err)
			assert.Equal(t, regionHostname, region.Status.PublicHostname)
		}

		{
			err = g.RunUpgrade(ctx, nil)
			assert.Nil(t, err, "%+v", err)

			region, err = g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
				Name: region.Metadata.Name,
			})
			assert.Nil(t, err)
			assert.Equal(t, regionHostname, region.Status.PublicHostname)
		}
	}
}
