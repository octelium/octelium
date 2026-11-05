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

	nadclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	fakenad "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
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
	for _, verb := range []string{"get", "create"} {
		t.Run(verb, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
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
		case action.Matches("create", "namespaces"):
			obj := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Namespace)
			obj.UID = types.UID(vutils.UUIDv4())
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
		"domain": []byte(os.Getenv("OCTELIUM_DOMAIN")),
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
	reserveInitializationRedis(t)
	t.Setenv("OCTELIUM_DOMAIN", "example.com")
	t.Setenv("OCTELIUM_REGION_NAME", "default")

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
		require.Nil(t, err, "%+v", err)
		t.Cleanup(func() {
			if g.rscServer != nil {
				g.rscServer.Stop()
			}
		})

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

		{
			t.Setenv("OCTELIUM_REGION_NAME", "default")

			joinedRegion, err := g.octeliumC.CoreC().CreateRegion(ctx, &corev1.Region{
				Metadata: &metav1.Metadata{
					Name:     "region-1",
					IsSystem: true,
				},
				Spec: &corev1.Region_Spec{},
				Status: &corev1.Region_Status{
					Index: 1,
				},
			})
			assert.Nil(t, err)

			err = genesisutils.CreateOrUpdateService(ctx, g.octeliumC, &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: "svc1.default",
				},
				Spec: &corev1.Service_Spec{
					Port:   8080,
					Mode:   corev1.Service_Spec_HTTP,
					Region: joinedRegion.Metadata.Name,
					Config: &corev1.Service_Spec_Config{
						Upstream: &corev1.Service_Spec_Config_Upstream{
							Type: &corev1.Service_Spec_Config_Upstream_Url{
								Url: "https://example.com",
							},
						},
					},
				},
			})
			assert.Nil(t, err, "%+v", err)

			portal, err := g.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
				Name: "portal.default",
			})
			assert.Nil(t, err)
			portalUpgradeID := portal.Metadata.SystemLabels[vutils.UpgradeIDKey]
			assert.NotEmpty(t, portalUpgradeID)

			portal.Metadata.DisplayName = "Modified Portal"
			_, err = g.octeliumC.CoreC().UpdateService(ctx, portal)
			assert.Nil(t, err)

			pol, err := g.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
				Name: "allow-all",
			})
			assert.Nil(t, err)
			_, err = g.octeliumC.CoreC().DeletePolicy(ctx, &rmetav1.DeleteOptions{
				Uid: pol.Metadata.Uid,
			})
			assert.Nil(t, err)

			seed, err := g.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: "sys:ssh-svc-seed",
			})
			assert.Nil(t, err)
			_, err = g.octeliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{
				Uid: seed.Metadata.Uid,
			})
			assert.Nil(t, err)

			defaultRegion, err := g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
				Name: "default",
			})
			assert.Nil(t, err)

			initSecret, err := g.k8sC.CoreV1().Secrets(vutils.K8sNS).Get(ctx, "octelium-init", k8smetav1.GetOptions{})
			assert.Nil(t, err)

			cJoin := newFakeClient()
			gJoin := &Genesis{
				k8sC: cJoin.K8sC,
				nadC: cJoin.NadC,
			}
			_, err = cJoin.K8sC.CoreV1().Namespaces().Create(ctx, &k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS}}, k8smetav1.CreateOptions{})
			assert.NoError(t, err)

			_, err = cJoin.K8sC.CoreV1().Secrets(vutils.K8sNS).Create(ctx, &k8scorev1.Secret{
				ObjectMeta: k8smetav1.ObjectMeta{
					Name:      "octelium-init",
					Namespace: vutils.K8sNS,
				},
				Data: map[string][]byte{
					"bootstrap": initSecret.Data["bootstrap"],
					"region":    pbutils.MarshalMust(joinedRegion),
				},
			}, k8smetav1.CreateOptions{})
			assert.Nil(t, err)

			err = gJoin.RunUpgrade(ctx, nil)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, joinedRegion.Metadata.Name, os.Getenv("OCTELIUM_REGION_NAME"))

			for _, name := range []string{"octelium-ingress", "octelium-ingress-dataplane"} {
				_, err = g.k8sC.AppsV1().Deployments(vutils.K8sNS).Get(ctx, name, k8smetav1.GetOptions{})
				assert.Nil(t, err)
				_, err = g.k8sC.CoreV1().Services(vutils.K8sNS).Get(ctx, name, k8smetav1.GetOptions{})
				assert.Nil(t, err)

				_, err = cJoin.K8sC.AppsV1().Deployments(vutils.K8sNS).Get(ctx, name, k8smetav1.GetOptions{})
				assert.True(t, k8serr.IsNotFound(err), "%s: %+v", name, err)
				_, err = cJoin.K8sC.CoreV1().Services(vutils.K8sNS).Get(ctx, name, k8smetav1.GetOptions{})
				assert.True(t, k8serr.IsNotFound(err), "%s: %+v", name, err)
			}

			_, err = cJoin.K8sC.CoreV1().ConfigMaps(vutils.K8sNS).Get(ctx,
				"ingress-dataplane-envoy-config", k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err), "%+v", err)
			_, err = cJoin.K8sC.NetworkingV1().NetworkPolicies(vutils.K8sNS).Get(ctx,
				"octelium-ingress", k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err), "%+v", err)

			for _, name := range []string{"octelium-rscserver", "octelium-nocturne", "octelium-octovigil"} {
				_, err = cJoin.K8sC.AppsV1().Deployments(vutils.K8sNS).Get(ctx, name, k8smetav1.GetOptions{})
				assert.Nil(t, err, "%s: %+v", name, err)
			}

			_, err = cJoin.K8sC.AppsV1().DaemonSets(vutils.K8sNS).Get(ctx, "octelium-gwagent", k8smetav1.GetOptions{})
			assert.Nil(t, err)
			_, err = cJoin.K8sC.NetworkingV1().NetworkPolicies(vutils.K8sNS).Get(ctx, "svc-upstream", k8smetav1.GetOptions{})
			assert.Nil(t, err)

			portal, err = g.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
				Name: "portal.default",
			})
			assert.Nil(t, err)
			assert.Equal(t, "Modified Portal", portal.Metadata.DisplayName)
			assert.Equal(t, portalUpgradeID, portal.Metadata.SystemLabels[vutils.UpgradeIDKey])

			_, err = g.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
				Name: "allow-all",
			})
			assert.True(t, grpcerr.IsNotFound(err), "%+v", err)

			_, err = g.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: "sys:ssh-svc-seed",
			})
			assert.True(t, grpcerr.IsNotFound(err), "%+v", err)

			svc1, err := g.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
				Name: "svc1.default",
			})
			assert.Nil(t, err)
			svc1UpgradeID := svc1.Metadata.SystemLabels[vutils.UpgradeIDKey]
			assert.NotEmpty(t, svc1UpgradeID)

			joinedRegion, err = g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
				Uid: joinedRegion.Metadata.Uid,
			})
			assert.Nil(t, err)
			assert.Equal(t, ldflags.GetVersion(), joinedRegion.Status.VersionInfoMap["octelium"].Version)
			assert.Equal(t, fmt.Sprintf("octelium-region-%s", strings.Split(joinedRegion.Metadata.Uid, "-")[4]),
				joinedRegion.Status.PublicHostname)

			rgn, err := g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
				Name: "default",
			})
			assert.Nil(t, err)
			assert.True(t, pbutils.IsEqual(defaultRegion, rgn))

			os.Setenv("OCTELIUM_REGION_NAME", "default")
			err = g.RunUpgrade(ctx, nil)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, "default", os.Getenv("OCTELIUM_REGION_NAME"))

			portal, err = g.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
				Name: "portal.default",
			})
			assert.Nil(t, err)
			assert.Equal(t, "Modified Portal", portal.Metadata.DisplayName)
			assert.NotEmpty(t, portal.Metadata.SystemLabels[vutils.UpgradeIDKey])
			assert.NotEqual(t, portalUpgradeID, portal.Metadata.SystemLabels[vutils.UpgradeIDKey])

			_, err = g.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
				Name: "allow-all",
			})
			assert.True(t, grpcerr.IsNotFound(err))

			_, err = g.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
				Name: "sys:ssh-svc-seed",
			})
			assert.Nil(t, err)

			svc1, err = g.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
				Name: "svc1.default",
			})
			assert.Nil(t, err)
			assert.Equal(t, svc1UpgradeID, svc1.Metadata.SystemLabels[vutils.UpgradeIDKey])
		}
	}
}

func readyGatewayDaemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-gwagent", Namespace: vutils.K8sNS, UID: "gateway-daemonset", Generation: 2},
		Spec: appsv1.DaemonSetSpec{
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType},
			Template:       k8scorev1.PodTemplateSpec{Spec: k8scorev1.PodSpec{NodeSelector: map[string]string{vutils.NodeLabelDataPlane: ""}}},
		},
		Status: appsv1.DaemonSetStatus{ObservedGeneration: 2, CurrentNumberScheduled: 2, DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberReady: 2, NumberAvailable: 2},
	}
}

func registeredGatewayNode(name string) *k8scorev1.Node {
	return &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Labels: map[string]string{vutils.NodeLabelDataPlane: "", vutils.NodeLabelGatewayRegistered: "true"}}}
}

func TestGatewayReadinessDoesNotTrustOldRegistration(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, state := range []string{"complete", "empty", "unobserved", "stale", "old-pods", "unavailable", "unregistered", "missing-label", "wrong-label-value"} {
		t.Run(state, func(t *testing.T) {
			ds := readyGatewayDaemonSet()
			node := registeredGatewayNode("node")
			switch state {
			case "empty":
				ds.Status = appsv1.DaemonSetStatus{ObservedGeneration: 2}
			case "unobserved":
				ds.Status = appsv1.DaemonSetStatus{}
			case "stale":
				ds.Status.ObservedGeneration--
			case "old-pods":
				ds.Status.UpdatedNumberScheduled = 1
			case "unavailable":
				ds.Status.NumberAvailable = 1
			case "unregistered":
				node.Labels[vutils.NodeLabelGatewayRegistered] = "false"
			case "missing-label":
				delete(node.Labels, vutils.NodeLabelGatewayRegistered)
			case "wrong-label-value":
				node.Labels[vutils.NodeLabelDataPlane] = "true"
			}
			c := fakek8s.NewSimpleClientset(ds, node)
			ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
			defer cancel()
			err := waitGatewayAgentsRegistered(ctx, c)
			if state == "complete" {
				require.NoError(t, err)
			} else if state == "wrong-label-value" {
				require.ErrorContains(t, err, "No Kubernetes node is labeled")
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			for _, action := range c.Actions() {
				assert.Contains(t, []string{"get", "list"}, action.GetVerb())
				if action.GetResource().Resource == "nodes" {
					assert.Contains(t, []string{"complete", "unregistered", "missing-label", "wrong-label-value"}, state)
					assert.Equal(t, vutils.NodeLabelDataPlane+"=", action.(k8stesting.ListAction).GetListRestrictions().Labels.String())
				}
			}
		})
	}
}

func TestGatewayReadinessErrorsAndCancellation(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, check := range []func(context.Context, kubernetes.Interface) error{waitGatewayAgentReady, waitGatewayAgentsRegistered} {
		c := fakek8s.NewSimpleClientset()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.ErrorIs(t, check(ctx, c), context.Canceled)
		assert.Empty(t, c.Actions())
		want := k8serr.NewForbidden(appsv1.Resource("daemonsets"), "octelium-gwagent", fmt.Errorf("denied"))
		c.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
		require.ErrorIs(t, check(t.Context(), c), want)
		assert.Len(t, c.Actions(), 1)
	}
	c := fakek8s.NewSimpleClientset(readyGatewayDaemonSet(), registeredGatewayNode("node"))
	want := k8serr.NewForbidden(k8scorev1.Resource("nodes"), "", fmt.Errorf("denied"))
	c.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	require.ErrorIs(t, waitGatewayAgentsRegistered(t.Context(), c), want)
	ldflags.TestMode = "true"
	c.ClearActions()
	require.NoError(t, waitGatewayAgentReady(t.Context(), c))
	require.NoError(t, waitGatewayAgentsRegistered(t.Context(), c))
	assert.Empty(t, c.Actions())
}

func TestGatewayReadinessHTTP(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, state := range []string{"empty", "stale", "old-pods", "unavailable", "missing", "daemonset-outage", "node-outage", "registration", "stalled"} {
		t.Run(state, func(t *testing.T) {
			var reads, nodeReads atomic.Int32
			finished := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/apis/apps/v1/namespaces/octelium/daemonsets/octelium-gwagent":
					n := reads.Add(1)
					if state == "stalled" {
						<-r.Context().Done()
						close(finished)
						return
					}
					if n == 1 && (state == "daemonset-outage" || state == "missing") {
						code, reason := http.StatusServiceUnavailable, k8smetav1.StatusReasonServiceUnavailable
						if state == "missing" {
							code, reason = http.StatusNotFound, k8smetav1.StatusReasonNotFound
						}
						w.WriteHeader(code)
						assert.NoError(t, json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: k8smetav1.StatusFailure, Reason: reason, Code: int32(code)}))
						return
					}
					ds := readyGatewayDaemonSet()
					if n == 1 {
						switch state {
						case "empty":
							ds.Status = appsv1.DaemonSetStatus{ObservedGeneration: 2}
						case "stale":
							ds.Status.ObservedGeneration--
						case "old-pods":
							ds.Status.UpdatedNumberScheduled = 1
						case "unavailable":
							ds.Status.NumberAvailable = 1
						}
					}
					assert.NoError(t, json.NewEncoder(w).Encode(ds))
				case "/api/v1/nodes":
					n := nodeReads.Add(1)
					assert.Equal(t, vutils.NodeLabelDataPlane+"=", r.URL.Query().Get("labelSelector"))
					if state == "node-outage" && n == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						assert.NoError(t, json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: k8smetav1.StatusFailure, Reason: k8smetav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable}))
						return
					}
					node := registeredGatewayNode("node")
					if state == "registration" && n == 1 {
						node.Labels[vutils.NodeLabelGatewayRegistered] = "false"
					}
					assert.NoError(t, json.NewEncoder(w).Encode(&k8scorev1.NodeList{Items: []k8scorev1.Node{*node, *registeredGatewayNode("second-node")}}))
				default:
					t.Errorf("Unexpected Kubernetes request: %s", r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			defer server.Close()
			c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			require.NoError(t, err)
			timeout := 7 * time.Second
			if state == "stalled" {
				timeout = 80 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			if state == "empty" {
				err = waitGatewayAgentReady(ctx, c)
			} else {
				err = waitGatewayAgentsRegistered(ctx, c)
			}
			if state == "stalled" {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Fatal("The gateway readiness request did not observe cancellation")
				}
			} else {
				require.NoError(t, err)
				assert.GreaterOrEqual(t, reads.Load(), int32(2))
				if state != "empty" {
					assert.GreaterOrEqual(t, nodeReads.Load(), int32(1))
				}
			}
		})
	}
}

func savePasswordBootstrap(t *testing.T, f *initializationFixture) {
	t.Helper()
	input, err := f.client.K8sC.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	input.Data["bootstrap"] = pbutils.MarshalMust(f.input.Bootstrap)
	_, err = f.client.K8sC.CoreV1().Secrets("default").Update(t.Context(), input, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
}

func TestPasswordReferenceFailureBeforeStorageE2E(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, failure := range []string{"missing-key", "empty-key"} {
			t.Run(storage+"/"+failure, func(t *testing.T) {
				f := newInitializationFixture(t)
				setPasswordReference(f.input.Bootstrap, storage, "credentials", "default", "custom")
				savePasswordBootstrap(t, f)
				source := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("private-wrong-fallback")}}
				if failure == "empty-key" {
					source.Data["custom"] = nil
				}
				c := f.client.K8sC.(*fakek8s.Clientset)
				require.NoError(t, c.Tracker().Add(source))
				require.NoError(t, f.redis.Set(t.Context(), "unrelated-sentinel", "preserved", 0).Err())
				c.ClearActions()
				err := f.genesis.RunInit(t.Context(), nil)
				require.ErrorContains(t, err, "missing or empty")
				assert.NotContains(t, err.Error(), "private-wrong-fallback")
				for _, action := range c.Actions() {
					assert.Contains(t, []string{"get", "list"}, action.GetVerb())
				}
				var exists bool
				require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT to_regclass('octelium_resources') IS NOT NULL`).Scan(&exists))
				assert.False(t, exists)
				marker, err := f.redis.Exists(t.Context(), initializationRedisKey).Result()
				require.NoError(t, err)
				assert.Zero(t, marker)
				for _, name := range []string{initializationSecretName, "octelium-postgres", "octelium-redis", "init-token"} {
					_, err := c.Tracker().Get(k8scorev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, name)
					assert.True(t, k8serr.IsNotFound(err))
				}
				f.checkPreserved(t)
				value, err := f.redis.Get(t.Context(), "unrelated-sentinel").Result()
				require.NoError(t, err)
				assert.Equal(t, "preserved", value)
				password := "postgres"
				if storage == "redis" {
					password = "secret"
				}
				source.Data["custom"] = []byte(password)
				require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), source, "default"))
				require.NoError(t, f.genesis.RunInit(t.Context(), nil))
				name, key := "octelium-postgres", "postgres-password"
				if storage == "redis" {
					name, key = "octelium-redis", "password"
				}
				derived, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, password, string(derived.Data[key]))
			})
		}
	}
}

func TestCompletedPasswordReferencesAreNotRequiredForReplayOrUpgradeE2E(t *testing.T) {
	f := newInitializationFixture(t)
	setPasswordReference(f.input.Bootstrap, "postgres", "credentials", "default", "pg")
	setPasswordReference(f.input.Bootstrap, "redis", "credentials", "default", "redis")
	savePasswordBootstrap(t, f)
	c := f.client.K8sC.(*fakek8s.Clientset)
	require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"pg": []byte("postgres"), "redis": []byte("secret")}}))
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	keys := initializationSecrets(t, f.db)
	rows := initializationRows(t, f.db)
	storage := make(map[string]*k8scorev1.Secret)
	for _, name := range []string{"octelium-postgres", "octelium-redis"} {
		secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		storage[name] = secret
	}
	require.NoError(t, c.Tracker().Delete(k8scorev1.SchemeGroupVersion.WithResource("secrets"), "default", "credentials"))
	c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.GetAction).GetName() == "credentials" {
			t.Error("An existing Cluster tried to resolve the original password reference")
			return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), "credentials")
		}
		return false, nil, nil
	})
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	assert.Equal(t, rows, initializationRows(t, f.db))
	require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	require.NoError(t, c.Tracker().Delete(k8scorev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, initializationSecretName))
	require.NoError(t, f.redis.Del(t.Context(), initializationRedisKey).Err())
	require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	for name, before := range storage {
		after, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, before.UID, after.UID)
		assert.Equal(t, before.Data, after.Data)
	}
	f.checkPreserved(t)
}

func TestInitializationPasswordErrorsBeforeMutation(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, failure := range []string{"name", "namespace", "key", "missing-key", "empty-key", "missing-defaults", "missing-secret"} {
			t.Run(storage+"/"+failure, func(t *testing.T) {
				resetPasswordEnvironment(t)
				ldflags.TestMode = "true"
				input := newInitializationInput(t)
				name, namespace, key := "credentials", "default", "custom"
				data := map[string][]byte{"custom": []byte("source-password"), "password": []byte("fallback-password")}
				switch failure {
				case "name":
					name = ""
				case "namespace":
					namespace = "bad/namespace"
				case "key":
					key = "bad/key"
				case "missing-key":
					delete(data, "custom")
				case "empty-key":
					data["custom"] = nil
				case "missing-defaults":
					key = ""
					delete(data, "password")
				}
				setPasswordReference(input.Bootstrap, storage, name, namespace, key)
				bootstrap := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: map[string][]byte{"bootstrap": pbutils.MarshalMust(input.Bootstrap), "region": pbutils.MarshalMust(input.Region), "domain": []byte(input.Domain)}}
				c := fakek8s.NewSimpleClientset(bootstrap)
				if failure != "missing-secret" {
					require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: data}))
				}
				g := &Genesis{k8sC: c}
				require.Error(t, g.RunInit(t.Context(), nil))
				assertPasswordResolutionReadOnly(t, c)
				_, err := c.Tracker().Get(k8scorev1.SchemeGroupVersion.WithResource("namespaces"), "", vutils.K8sNS)
				assert.True(t, k8serr.IsNotFound(err))
				for _, name := range []string{initializationSecretName, "octelium-postgres", "octelium-redis"} {
					_, err := c.Tracker().Get(k8scorev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, name)
					assert.True(t, k8serr.IsNotFound(err))
				}
			})
		}
	}
}

func TestInitializationCarriesResolvedPasswordSnapshot(t *testing.T) {
	resetPasswordEnvironment(t)
	input := newInitializationInput(t)
	setPasswordReference(input.Bootstrap, "postgres", "credentials", "default", "pg")
	setPasswordReference(input.Bootstrap, "redis", "credentials", "", "redis")
	source := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"pg": []byte("snapshot-postgres-password"), "redis": []byte("snapshot-redis-password")}}
	c := fakek8s.NewSimpleClientset(source)
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret).Name == initializationSecretName {
			rotated := source.DeepCopy()
			rotated.Data["pg"], rotated.Data["redis"] = []byte("rotated-pg"), []byte("rotated-redis")
			require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), rotated, "default"))
		}
		return false, nil, nil
	})
	g := &Genesis{k8sC: c}
	init, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	require.NotNil(t, init.passwords)
	require.NoError(t, g.initStorageWithPasswords(t.Context(), &genesisutils.InstallCtx{Bootstrap: input.Bootstrap}, init.passwords))
	for name, key := range map[string]string{"octelium-postgres": "postgres-password", "octelium-redis": "password"} {
		secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		want := "snapshot-postgres-password"
		if name == "octelium-redis" {
			want = "snapshot-redis-password"
		}
		assert.Equal(t, want, string(secret.Data[key]))
	}
	reads := 0
	for _, action := range c.Actions() {
		if action.GetVerb() == "get" && action.GetResource().Resource == "secrets" && action.(k8stesting.GetAction).GetName() == "credentials" {
			reads++
		}
	}
	assert.Equal(t, 1, reads)
	checkpoint, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	for _, value := range checkpoint.Data {
		assert.NotContains(t, string(value), "snapshot-postgres-password")
		assert.NotContains(t, string(value), "snapshot-redis-password")
	}
}

func TestInitializationPasswordReferenceReplay(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(fmt.Sprint(complete), func(t *testing.T) {
			resetPasswordEnvironment(t)
			input := newInitializationInput(t)
			setPasswordReference(input.Bootstrap, "redis", "credentials", "default", "custom")
			source := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"custom": []byte("redis-secret"), "password": []byte("wrong-fallback")}}
			c := fakek8s.NewSimpleClientset(source)
			g := &Genesis{k8sC: c}
			first, err := g.prepareInitialization(t.Context(), input)
			require.NoError(t, err)
			if complete {
				require.NoError(t, g.completeInitialization(t.Context(), first))
			}
			require.NoError(t, c.Tracker().Delete(k8scorev1.SchemeGroupVersion.WithResource("secrets"), "default", source.Name))
			c.ClearActions()
			replayed, err := g.prepareInitialization(t.Context(), input)
			if complete {
				require.NoError(t, err)
				assert.Equal(t, first.id, replayed.id)
				assert.Nil(t, replayed.passwords)
				for _, action := range c.Actions() {
					if action.GetResource().Resource == "secrets" && action.GetVerb() == "get" {
						assert.NotEqual(t, source.Name, action.(k8stesting.GetAction).GetName())
					}
				}
			} else {
				require.True(t, k8serr.IsNotFound(err))
			}
			assertPasswordResolutionReadOnly(t, c)
			if !complete {
				require.NoError(t, c.Tracker().Add(source))
				recovered, err := g.prepareInitialization(t.Context(), input)
				require.NoError(t, err)
				assert.Equal(t, first.id, recovered.id)
				assert.Equal(t, first.aesKeyName, recovered.aesKeyName)
				assert.Equal(t, first.passwords, recovered.passwords)
			}
		})
	}
}

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

func assertPasswordResolutionReadOnly(t *testing.T, c *fakek8s.Clientset) {
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
				c := fakek8s.NewSimpleClientset(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: tc.data})
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
				secret, err := c.CoreV1().Secrets("octelium").Get(t.Context(), name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, tc.want, string(secret.Data[key]))
				source, err := c.CoreV1().Secrets("default").Get(t.Context(), "credentials", k8smetav1.GetOptions{})
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
				c := fakek8s.NewSimpleClientset()
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
	c := fakek8s.NewSimpleClientset()
	calls := 0
	c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		assert.Equal(t, "default", action.GetNamespace())
		return true, &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"pg": []byte(fmt.Sprintf("pg-%d", calls)), "redis": []byte(fmt.Sprintf("redis-%d", calls))}}, nil
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
	c := fakek8s.NewSimpleClientset(
		&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("pg-value")}},
		&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "storage"}, Data: map[string][]byte{"password": []byte("redis-value")}},
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
				c := fakek8s.NewSimpleClientset(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("secret-value")}})
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
			c := fakek8s.NewSimpleClientset()
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
				c := fakek8s.NewSimpleClientset()
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
					code, reason := http.StatusServiceUnavailable, k8smetav1.StatusReasonServiceUnavailable
					if failure == "forbidden" {
						code, reason = http.StatusForbidden, k8smetav1.StatusReasonForbidden
					}
					w.WriteHeader(code)
					assert.NoError(t, json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: int32(code), Reason: reason}))
					return
				}
				data := map[string][]byte{"password": []byte("fallback-value"), "pg": []byte("pg-value"), "redis": []byte("redis-value")}
				if failure == "missing-key" {
					delete(data, "redis")
				}
				assert.NoError(t, json.NewEncoder(w).Encode(&k8scorev1.Secret{TypeMeta: k8smetav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: data}))
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
	pg := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-postgres", Namespace: "octelium", UID: "preserved-postgres", Annotations: map[string]string{"custom": "preserved"}}, Data: map[string][]byte{"postgres-password": []byte("stored-postgres"), "custom": []byte("preserved")}}
	redis := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-redis", Namespace: "octelium", UID: "preserved-redis"}, Data: map[string][]byte{"password": []byte("stored-redis")}}
	c := fakek8s.NewSimpleClientset(pg, redis, &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("fallback-value")}})
	require.Error(t, initializePasswordStorage(t.Context(), &Genesis{k8sC: c}, bs))
	assertPasswordResolutionReadOnly(t, c)
	for _, before := range []*k8scorev1.Secret{pg, redis} {
		stored, err := c.Tracker().Get(k8scorev1.SchemeGroupVersion.WithResource("secrets"), "octelium", before.Name)
		require.NoError(t, err)
		assert.Equal(t, before, stored)
	}
}

func TestScaledClusterUpgradesPreserveReplicasE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	region, err := f.genesis.octeliumC.CoreC().GetRegion(t.Context(), &rmetav1.GetOptions{Name: "default"})
	require.NoError(t, err)
	require.NoError(t, components.CreateRscServer(t.Context(), &components.CommonOpts{K8sC: f.client.K8sC, ClusterConfig: cc, Region: region}))
	counts := map[string]int32{"octelium-rscserver": 3, "octelium-nocturne": 0, "octelium-octovigil": 4, "octelium-ingress": 2, "octelium-ingress-dataplane": 5}
	identities := make(map[string]types.UID)
	for name, count := range counts {
		deployment, err := f.client.K8sC.AppsV1().Deployments(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		deployment.UID = types.UID("existing-" + name)
		deployment.Spec.Replicas = new(count)
		deployment.Spec.Template.Spec.Containers[0].Image = "previous-release"
		deployment, err = f.client.K8sC.AppsV1().Deployments(vutils.K8sNS).Update(t.Context(), deployment, k8smetav1.UpdateOptions{})
		require.NoError(t, err)
		identities[name] = deployment.UID
	}
	keys := initializationSecrets(t, f.db)
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		for name, count := range counts {
			deployment, err := f.client.K8sC.AppsV1().Deployments(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, new(count), deployment.Spec.Replicas, name)
			assert.Equal(t, identities[name], deployment.UID, name)
			assert.NotEqual(t, "previous-release", deployment.Spec.Template.Spec.Containers[0].Image, name)
		}
		assert.Equal(t, keys, initializationSecrets(t, f.db))
	}
	f.checkPreserved(t)
}

func assertResourceMetadataPreserved(t *testing.T, before, after *metav1.Metadata) {
	t.Helper()
	assert.Equal(t, before.Name, after.Name)
	assert.Equal(t, before.Uid, after.Uid)
	assert.Equal(t, before.CreatedAt, after.CreatedAt)
	assert.Equal(t, before.DisplayName, after.DisplayName)
	assert.Equal(t, before.Description, after.Description)
	assert.Equal(t, before.Labels, after.Labels)
	assert.Equal(t, before.Annotations, after.Annotations)
	assert.Equal(t, before.Tags, after.Tags)
	assert.Equal(t, before.PicURL, after.PicURL)
	assert.Equal(t, before.IsSystem, after.IsSystem)
}

func TestUpgradePreservesMutableResourcesE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := f.genesis.octeliumC.CoreC()
	var services []*corev1.Service
	for _, name := range []string{"demo-nginx.default", "essh.octelium", "socks5.octelium"} {
		svc, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: name})
		require.NoError(t, err)
		svc.Metadata.DisplayName = "Customer service"
		svc.Metadata.Description = "Customer description"
		svc.Metadata.Labels = map[string]string{"owner": "customer"}
		svc.Metadata.Annotations = map[string]string{"note": "preserve"}
		svc.Metadata.Tags = []string{"custom"}
		svc.Metadata.PicURL = "customer-picture"
		svc.Spec.IsPublic = false
		svc.Spec.Port = 9099
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{InlinePolicies: []*corev1.InlinePolicy{{
			Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Effect: corev1.Policy_Spec_Rule_DENY, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}}}},
		}}}
		if container := svc.Spec.GetConfig().GetUpstream().GetContainer(); container != nil {
			container.Image = "customer.example/nginx:pinned"
		}
		svc, err = c.UpdateService(t.Context(), svc)
		require.NoError(t, err)
		services = append(services, svc)
	}
	policies, err := f.genesis.getBuiltinPolicies(t.Context())
	require.NoError(t, err)
	var savedPolicies []*corev1.Policy
	for _, desired := range policies.Items {
		pol, err := c.GetPolicy(t.Context(), &rmetav1.GetOptions{Name: desired.Metadata.Name})
		require.NoError(t, err)
		pol.Metadata.Description = "Customer policy"
		pol.Metadata.Annotations = map[string]string{"owner": "customer"}
		pol.Spec = &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Effect: corev1.Policy_Spec_Rule_DENY, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}}}}
		pol, err = c.UpdatePolicy(t.Context(), pol)
		require.NoError(t, err)
		savedPolicies = append(savedPolicies, pol)
	}
	ns, err := c.GetNamespace(t.Context(), &rmetav1.GetOptions{Name: "default"})
	require.NoError(t, err)
	ns.Metadata.IsSystem = false
	ns.Metadata.Description = "Legacy namespace description"
	ns.Metadata.Labels = map[string]string{"owner": "customer"}
	ns.Spec.Attrs, err = structpb.NewStruct(map[string]any{"custom": "preserved"})
	require.NoError(t, err)
	ns.Spec.Authorization = &corev1.Namespace_Spec_Authorization{Policies: []string{"deny-all"}}
	ns, err = c.UpdateNamespace(t.Context(), ns)
	require.NoError(t, err)
	cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	region, err := c.GetRegion(t.Context(), &rmetav1.GetOptions{Name: "default"})
	require.NoError(t, err)
	require.NoError(t, f.genesis.installOcteliumResources(t.Context(), cc, region, true))
	require.NoError(t, f.genesis.installBuiltinPolicies(t.Context()))
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		for _, before := range services {
			after, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: before.Metadata.Name})
			require.NoError(t, err)
			assertResourceMetadataPreserved(t, before.Metadata, after.Metadata)
			assert.True(t, proto.Equal(before.Spec, after.Spec), before.Metadata.Name)
			assert.True(t, proto.Equal(before.Status, after.Status), before.Metadata.Name)
		}
		for _, before := range savedPolicies {
			after, err := c.GetPolicy(t.Context(), &rmetav1.GetOptions{Name: before.Metadata.Name})
			require.NoError(t, err)
			assert.True(t, proto.Equal(before, after), before.Metadata.Name)
		}
		after, err := c.GetNamespace(t.Context(), &rmetav1.GetOptions{Name: ns.Metadata.Name})
		require.NoError(t, err)
		assert.True(t, proto.Equal(ns, after))
	}
	f.checkPreserved(t)
}

func TestUpgradeDoesNotReinstallDefaultsE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := f.genesis.octeliumC.CoreC()
	names := []string{"demo-nginx.default", "essh.octelium", "socks5.octelium"}
	for _, name := range names {
		svc, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: name})
		require.NoError(t, err)
		_, err = c.DeleteService(t.Context(), &rmetav1.DeleteOptions{Uid: svc.Metadata.Uid})
		require.NoError(t, err)
	}
	policies, err := f.genesis.getBuiltinPolicies(t.Context())
	require.NoError(t, err)
	for _, desired := range policies.Items {
		pol, err := c.GetPolicy(t.Context(), &rmetav1.GetOptions{Name: desired.Metadata.Name})
		require.NoError(t, err)
		_, err = c.DeletePolicy(t.Context(), &rmetav1.DeleteOptions{Uid: pol.Metadata.Uid})
		require.NoError(t, err)
	}
	portal, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: "portal.default"})
	require.NoError(t, err)
	portal.Metadata.Description = "Customer portal"
	portal.Metadata.Labels = map[string]string{"owner": "customer"}
	portal.Metadata.Annotations = map[string]string{"custom": "kept"}
	portal.Status.ManagedService.Image = "legacy-image"
	portal, err = c.UpdateService(t.Context(), portal)
	require.NoError(t, err)
	dns, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: "dns.octelium"})
	require.NoError(t, err)
	dns.Status.ManagedService = nil
	_, err = c.UpdateService(t.Context(), dns)
	require.NoError(t, err)
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		for _, name := range names {
			_, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: name})
			assert.True(t, grpcerr.IsNotFound(err), name)
		}
		for _, pol := range policies.Items {
			_, err := c.GetPolicy(t.Context(), &rmetav1.GetOptions{Name: pol.Metadata.Name})
			assert.True(t, grpcerr.IsNotFound(err), pol.Metadata.Name)
		}
		current, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: portal.Metadata.Name})
		require.NoError(t, err)
		assertResourceMetadataPreserved(t, portal.Metadata, current.Metadata)
		assert.NotEqual(t, "legacy-image", current.Status.ManagedService.Image)
		assert.NotEmpty(t, current.Status.ManagedService.Image)
		for _, name := range []string{"dns.octelium", "default.octelium-api", "auth.octelium-api", "default.default"} {
			svc, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: name})
			require.NoError(t, err)
			assert.True(t, svc.Metadata.IsSystem)
			require.NotNil(t, svc.Status.ManagedService)
			assert.NotEmpty(t, svc.Status.ManagedService.Image)
		}
	}
	f.checkPreserved(t)
}

func TestUpgradeRefusesUnownedSystemServiceE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := f.genesis.octeliumC.CoreC()
	portal, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: "portal.default"})
	require.NoError(t, err)
	_, err = c.DeleteService(t.Context(), &rmetav1.DeleteOptions{Uid: portal.Metadata.Uid})
	require.NoError(t, err)
	require.NoError(t, genesisutils.CreateOrUpdateService(t.Context(), f.genesis.octeliumC, &corev1.Service{
		Metadata: &metav1.Metadata{Name: portal.Metadata.Name, Description: "User-owned collision"},
		Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Port: 9000, Config: &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "https://customer.example"}},
		}},
	}))
	before, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: portal.Metadata.Name})
	require.NoError(t, err)
	assert.False(t, before.Metadata.IsSystem)
	require.ErrorContains(t, f.genesis.RunUpgrade(t.Context(), nil), "Refusing to replace")
	after, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: portal.Metadata.Name})
	require.NoError(t, err)
	assert.True(t, proto.Equal(before, after))
	f.checkPreserved(t)
}

func TestInitialResourceSeedRecoveryE2E(t *testing.T) {
	for _, point := range []struct{ kind, name string }{{"Service", "demo-nginx.default"}, {"Policy", "allow-all"}} {
		for _, committed := range []bool{false, true} {
			t.Run(point.kind+"/"+map[bool]string{false: "before-commit", true: "after-commit"}[committed], func(t *testing.T) {
				f := newInitializationFixture(t)
				failed := false
				hook := func(_ context.Context, object umetav1.ResourceObjectI, _, _, kind string) error {
					if !failed && kind == point.kind && object.GetMetadata().Name == point.name {
						failed = true
						return status.Error(codes.Unavailable, "injected initial resource failure")
					}
					return nil
				}
				opts := &rscserver.Opts{PreCreate: hook}
				if committed {
					opts = &rscserver.Opts{PostCreate: hook}
				}
				server, err := rscserver.NewServer(t.Context(), opts)
				require.NoError(t, err)
				f.genesis.rscServer = server
				require.NoError(t, server.Run(t.Context()))
				require.Error(t, f.genesis.RunInit(t.Context(), nil))
				require.True(t, failed)
				_, err = f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "init-token", k8smetav1.GetOptions{})
				assert.True(t, k8serr.IsNotFound(err))
				var modified *corev1.Service
				if committed || point.kind == "Policy" {
					modified, err = f.genesis.octeliumC.CoreC().GetService(t.Context(), &rmetav1.GetOptions{Name: "demo-nginx.default"})
					require.NoError(t, err)
					modified.Metadata.Description = "Preserve edits during resume"
					modified.Spec.Config.Upstream.GetContainer().Image = "customer.example/nginx:pinned"
					modified, err = f.genesis.octeliumC.CoreC().UpdateService(t.Context(), modified)
					require.NoError(t, err)
				}
				keys := initializationSecrets(t, f.db)
				require.NoError(t, f.genesis.RunInit(t.Context(), nil))
				for name, key := range keys {
					assert.Equal(t, key, initializationSecrets(t, f.db)[name], name)
				}
				if modified != nil {
					current, err := f.genesis.octeliumC.CoreC().GetService(t.Context(), &rmetav1.GetOptions{Name: modified.Metadata.Name})
					require.NoError(t, err)
					assert.True(t, proto.Equal(modified, current))
				}
				policies, err := f.genesis.getBuiltinPolicies(t.Context())
				require.NoError(t, err)
				for _, desired := range policies.Items {
					_, err := f.genesis.octeliumC.CoreC().GetPolicy(t.Context(), &rmetav1.GetOptions{Name: desired.Metadata.Name})
					require.NoError(t, err)
				}
				_, err = f.genesis.getInitAuthenticationToken(t.Context())
				require.NoError(t, err)
				f.checkPreserved(t)
			})
		}
	}
}

type resourceTestClient struct {
	octeliumc.ClientInterface
	core *resourceTestCore
}

func (c *resourceTestClient) CoreC() rcorev1.ResourceServiceClient { return c.core }

type resourceTestCore struct {
	rcorev1.ResourceServiceClient
	getService      func(*rmetav1.GetOptions) (*corev1.Service, error)
	updateService   func(*corev1.Service) (*corev1.Service, error)
	getNamespace    func(*rmetav1.GetOptions) (*corev1.Namespace, error)
	createNamespace func(*corev1.Namespace) (*corev1.Namespace, error)
	getPolicy       func(*rmetav1.GetOptions) (*corev1.Policy, error)
	createPolicy    func(*corev1.Policy) (*corev1.Policy, error)
}

func (c *resourceTestCore) GetService(_ context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Service, error) {
	return c.getService(o)
}

func (c *resourceTestCore) UpdateService(_ context.Context, o *corev1.Service, _ ...grpc.CallOption) (*corev1.Service, error) {
	return c.updateService(o)
}

func (c *resourceTestCore) GetNamespace(_ context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Namespace, error) {
	return c.getNamespace(o)
}

func (c *resourceTestCore) CreateNamespace(_ context.Context, o *corev1.Namespace, _ ...grpc.CallOption) (*corev1.Namespace, error) {
	return c.createNamespace(o)
}

func (c *resourceTestCore) GetPolicy(_ context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Policy, error) {
	return c.getPolicy(o)
}

func (c *resourceTestCore) CreatePolicy(_ context.Context, o *corev1.Policy, _ ...grpc.CallOption) (*corev1.Policy, error) {
	return c.createPolicy(o)
}

func resourceTestGenesis(c *resourceTestCore) *Genesis {
	return &Genesis{octeliumC: &resourceTestClient{core: c}}
}

func TestEnsureServicePreservesMutableResources(t *testing.T) {
	for _, system := range []bool{false, true} {
		existing := &corev1.Service{
			Metadata: &metav1.Metadata{Name: "demo-nginx.default", Uid: "user-service", IsSystem: system, Description: "custom", Labels: map[string]string{"user": "kept"}},
			Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP, Port: 9000},
			Status:   &corev1.Service_Status{NamespaceRef: &metav1.ObjectReference{Uid: "namespace"}},
		}
		desired := &corev1.Service{Metadata: &metav1.Metadata{Name: existing.Metadata.Name}, Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_WEB}}
		before, input := proto.Clone(existing), proto.Clone(desired)
		c := &resourceTestCore{getService: func(*rmetav1.GetOptions) (*corev1.Service, error) { return existing, nil }}
		require.NoError(t, resourceTestGenesis(c).ensureService(t.Context(), desired))
		assert.True(t, proto.Equal(before, existing))
		assert.True(t, proto.Equal(input, desired))
	}
}

func TestEnsureSystemServicePreservesMetadataAndStatus(t *testing.T) {
	existing := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "dns.octelium", Uid: "legacy-service", ResourceVersion: "version-1", IsSystem: true,
			DisplayName: "Custom DNS", Description: "Custom description", Tags: []string{"custom"}, PicURL: "custom-picture",
			Labels: map[string]string{"owner": "user"}, Annotations: map[string]string{"note": "kept"},
			SpecLabels: map[string]string{"controller": "kept"}, SystemLabels: map[string]string{"runtime": "kept", "owned": "old"},
		},
		Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Port: 8080},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Uid: "namespace"}, RegionRef: &metav1.ObjectReference{Uid: "region"},
			PrimaryHostname: "existing-host", Port: 1234, ManagedService: &corev1.Service_Status_ManagedService{Image: "old-image"},
		},
	}
	desired := &corev1.Service{
		Metadata: &metav1.Metadata{Name: existing.Metadata.Name, IsSystem: true, IsUserHidden: true, DisplayName: "DNS", Description: "Default description", SystemLabels: map[string]string{"owned": "new"}},
		Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_DNS, Port: 53},
		Status:   &corev1.Service_Status{ManagedService: &corev1.Service_Status_ManagedService{Image: "new-image", Type: "dnsserver"}},
	}
	before, input := proto.Clone(existing), proto.Clone(desired)
	var updated *corev1.Service
	c := &resourceTestCore{
		getService: func(*rmetav1.GetOptions) (*corev1.Service, error) { return existing, nil },
		updateService: func(svc *corev1.Service) (*corev1.Service, error) {
			updated = svc
			return svc, nil
		},
	}
	require.NoError(t, resourceTestGenesis(c).ensureService(t.Context(), desired))
	require.NotNil(t, updated)
	assert.Equal(t, existing.Metadata.Uid, updated.Metadata.Uid)
	assert.Equal(t, existing.Metadata.ResourceVersion, updated.Metadata.ResourceVersion)
	assert.Equal(t, existing.Metadata.DisplayName, updated.Metadata.DisplayName)
	assert.Equal(t, existing.Metadata.Description, updated.Metadata.Description)
	assert.Equal(t, existing.Metadata.Labels, updated.Metadata.Labels)
	assert.Equal(t, existing.Metadata.Annotations, updated.Metadata.Annotations)
	assert.Equal(t, existing.Metadata.SpecLabels, updated.Metadata.SpecLabels)
	assert.Equal(t, existing.Metadata.Tags, updated.Metadata.Tags)
	assert.Equal(t, existing.Metadata.PicURL, updated.Metadata.PicURL)
	assert.Equal(t, map[string]string{"runtime": "kept", "owned": "new"}, updated.Metadata.SystemLabels)
	assert.True(t, updated.Metadata.IsUserHidden)
	assert.True(t, proto.Equal(desired.Spec, updated.Spec))
	assert.True(t, proto.Equal(desired.Status.ManagedService, updated.Status.ManagedService))
	assert.True(t, proto.Equal(existing.Status.NamespaceRef, updated.Status.NamespaceRef))
	assert.True(t, proto.Equal(existing.Status.RegionRef, updated.Status.RegionRef))
	assert.Equal(t, existing.Status.PrimaryHostname, updated.Status.PrimaryHostname)
	assert.Equal(t, existing.Status.Port, updated.Status.Port)
	assert.True(t, proto.Equal(before, existing))
	assert.True(t, proto.Equal(input, desired))
}

func TestEnsureSystemServiceOwnership(t *testing.T) {
	for _, system := range []bool{false, true} {
		existing := &corev1.Service{Metadata: &metav1.Metadata{Name: "portal.default", IsSystem: system}}
		desired := &corev1.Service{Metadata: &metav1.Metadata{Name: existing.Metadata.Name, IsSystem: true, Description: "Portal"}, Status: &corev1.Service_Status{ManagedService: &corev1.Service_Status_ManagedService{Image: "new-image"}}}
		updates := 0
		c := &resourceTestCore{
			getService: func(*rmetav1.GetOptions) (*corev1.Service, error) { return existing, nil },
			updateService: func(svc *corev1.Service) (*corev1.Service, error) {
				updates++
				assert.Equal(t, "Portal", svc.Metadata.Description)
				assert.Equal(t, "new-image", svc.Status.ManagedService.Image)
				return svc, nil
			},
		}
		err := resourceTestGenesis(c).ensureService(t.Context(), desired)
		if system {
			require.NoError(t, err)
			assert.Equal(t, 1, updates)
		} else {
			require.ErrorContains(t, err, "Refusing to replace")
			assert.Zero(t, updates)
		}
	}
}

func TestEnsureSystemServiceConflict(t *testing.T) {
	for _, state := range []string{"concurrent-edit", "ownership-changed", "cancelled", "continuous-conflict"} {
		t.Run(state, func(t *testing.T) {
			existing := &corev1.Service{Metadata: &metav1.Metadata{Name: "portal.default", ResourceVersion: "1", IsSystem: true}, Spec: &corev1.Service_Spec{}, Status: &corev1.Service_Status{}}
			desired := proto.Clone(existing).(*corev1.Service)
			desired.Status.ManagedService = &corev1.Service_Status_ManagedService{Image: "new-image"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			updates := 0
			c := &resourceTestCore{
				getService: func(*rmetav1.GetOptions) (*corev1.Service, error) { return existing, nil },
				updateService: func(svc *corev1.Service) (*corev1.Service, error) {
					updates++
					if updates == 1 || state == "continuous-conflict" {
						existing = proto.Clone(existing).(*corev1.Service)
						existing.Metadata.ResourceVersion = "2"
						existing.Metadata.Labels = map[string]string{"concurrent": "preserved"}
						if state == "ownership-changed" {
							existing.Metadata.IsSystem = false
						}
						if state == "cancelled" {
							cancel()
						}
						return nil, status.Error(codes.OutOfRange, "resource changed")
					}
					assert.Equal(t, "2", svc.Metadata.ResourceVersion)
					assert.Equal(t, "preserved", svc.Metadata.Labels["concurrent"])
					return svc, nil
				},
			}
			err := resourceTestGenesis(c).ensureService(ctx, desired)
			switch state {
			case "concurrent-edit":
				require.NoError(t, err)
				assert.Equal(t, 2, updates)
			case "ownership-changed":
				require.ErrorContains(t, err, "Refusing to replace")
				assert.Equal(t, 1, updates)
			case "cancelled":
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, 1, updates)
			case "continuous-conflict":
				assert.Equal(t, codes.OutOfRange, status.Code(err))
				assert.LessOrEqual(t, updates, 6)
			}
		})
	}
}

func TestEnsureServiceReadAndWriteFailures(t *testing.T) {
	for _, state := range []string{"read-failed", "response-lost"} {
		t.Run(state, func(t *testing.T) {
			existing := &corev1.Service{Metadata: &metav1.Metadata{Name: "portal.default", IsSystem: true}, Spec: &corev1.Service_Spec{}, Status: &corev1.Service_Status{}}
			desired := proto.Clone(existing).(*corev1.Service)
			desired.Status.ManagedService = &corev1.Service_Status_ManagedService{Image: "new-image"}
			want := status.Error(codes.Unavailable, state)
			updates := 0
			c := &resourceTestCore{
				getService: func(*rmetav1.GetOptions) (*corev1.Service, error) {
					if state == "read-failed" {
						return nil, want
					}
					return existing, nil
				},
				updateService: func(svc *corev1.Service) (*corev1.Service, error) {
					updates++
					existing = proto.Clone(svc).(*corev1.Service)
					return nil, want
				},
			}
			g := resourceTestGenesis(c)
			require.ErrorIs(t, g.ensureService(t.Context(), desired), want)
			if state == "response-lost" {
				require.NoError(t, g.ensureService(t.Context(), desired))
				assert.Equal(t, 1, updates)
			} else {
				assert.Zero(t, updates)
			}
		})
	}
}

func TestEnsureNamespacePreservesExistingResources(t *testing.T) {
	for _, system := range []bool{false, true} {
		existing := &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", Uid: "original", IsSystem: system, Description: "Custom", Labels: map[string]string{"user": "kept"}}, Spec: &corev1.Namespace_Spec{}, Status: &corev1.Namespace_Status{}}
		before := proto.Clone(existing)
		c := &resourceTestCore{getNamespace: func(*rmetav1.GetOptions) (*corev1.Namespace, error) { return existing, nil }}
		require.NoError(t, resourceTestGenesis(c).ensureNamespace(t.Context(), &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", IsSystem: true}}))
		assert.True(t, proto.Equal(before, existing))
	}
}

func TestBuiltinPolicyDefaultsAreCreateOnly(t *testing.T) {
	existing := &corev1.Policy{Metadata: &metav1.Metadata{Name: "allow-all", Description: "Custom restrictive policy"}, Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Effect: corev1.Policy_Spec_Rule_DENY}}}}
	before := proto.Clone(existing)
	created := 0
	c := &resourceTestCore{
		getPolicy: func(o *rmetav1.GetOptions) (*corev1.Policy, error) {
			if o.Name == existing.Metadata.Name {
				return existing, nil
			}
			return nil, status.Error(codes.NotFound, "missing")
		},
		createPolicy: func(pol *corev1.Policy) (*corev1.Policy, error) {
			created++
			return pol, nil
		},
	}
	require.NoError(t, resourceTestGenesis(c).installBuiltinPolicies(t.Context()))
	assert.Equal(t, 4, created)
	assert.True(t, proto.Equal(before, existing))
	want := status.Error(codes.Unavailable, "temporary policy read failure")
	c.getPolicy = func(*rmetav1.GetOptions) (*corev1.Policy, error) { return nil, want }
	require.ErrorIs(t, resourceTestGenesis(c).installBuiltinPolicies(t.Context()), want)
	assert.Equal(t, 4, created)
}

func TestEnsureNamespaceCreationRace(t *testing.T) {
	for _, raced := range []bool{false, true} {
		desired := &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", IsSystem: true}}
		before := proto.Clone(desired)
		gets, creates := 0, 0
		c := &resourceTestCore{
			getNamespace: func(*rmetav1.GetOptions) (*corev1.Namespace, error) {
				gets++
				if gets == 1 {
					return nil, status.Error(codes.NotFound, "missing")
				}
				return &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", Description: "Concurrent user namespace"}}, nil
			},
			createNamespace: func(ns *corev1.Namespace) (*corev1.Namespace, error) {
				creates++
				require.NotNil(t, ns.Spec)
				require.NotNil(t, ns.Status)
				if raced {
					return nil, status.Error(codes.AlreadyExists, "created concurrently")
				}
				ns.Metadata.Uid = "assigned-by-server"
				return ns, nil
			},
		}
		require.NoError(t, resourceTestGenesis(c).ensureNamespace(t.Context(), desired))
		assert.Equal(t, 1, creates)
		assert.True(t, proto.Equal(before, desired))
		if raced {
			assert.Equal(t, 2, gets)
		}
	}
}

func TestEnsureServiceCreationRace(t *testing.T) {
	for _, system := range []bool{false, true} {
		existing := &corev1.Service{Metadata: &metav1.Metadata{Name: "portal.default", Description: "Concurrent user service"}, Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP}}
		before := proto.Clone(existing)
		gets := 0
		c := &resourceTestCore{
			getNamespace: func(*rmetav1.GetOptions) (*corev1.Namespace, error) {
				return &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", Uid: "namespace"}}, nil
			},
			getService: func(*rmetav1.GetOptions) (*corev1.Service, error) {
				gets++
				if gets == 1 {
					return nil, status.Error(codes.NotFound, "missing")
				}
				return existing, nil
			},
		}
		err := resourceTestGenesis(c).ensureService(t.Context(), &corev1.Service{Metadata: &metav1.Metadata{Name: existing.Metadata.Name, IsSystem: system}})
		if system {
			require.ErrorContains(t, err, "Refusing to replace")
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, 3, gets)
		assert.True(t, proto.Equal(before, existing))
	}
}

func TestBuiltinPolicyCreationRace(t *testing.T) {
	gets := 0
	created := 0
	c := &resourceTestCore{
		getPolicy: func(o *rmetav1.GetOptions) (*corev1.Policy, error) {
			gets++
			if gets == 1 {
				return nil, status.Error(codes.NotFound, "missing")
			}
			return &corev1.Policy{Metadata: &metav1.Metadata{Name: o.Name, Description: "Concurrent policy"}}, nil
		},
		createPolicy: func(*corev1.Policy) (*corev1.Policy, error) {
			created++
			return nil, status.Error(codes.AlreadyExists, "created concurrently")
		},
	}
	require.NoError(t, resourceTestGenesis(c).installBuiltinPolicies(t.Context()))
	assert.Equal(t, 1, created)
	assert.Equal(t, 6, gets)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, resourceTestGenesis(c).installBuiltinPolicies(ctx), context.Canceled)
	assert.Equal(t, 6, gets)
}
