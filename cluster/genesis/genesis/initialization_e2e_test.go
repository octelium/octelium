package genesis

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	fakenad "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func reserveInitializationRedis(t *testing.T) *redis.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reservation := utilrand.GetRandomStringCanonical(32)
	for database := 1; database < 16; database++ {
		c := redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: database})
		size, err := c.DBSize(ctx).Result()
		if err != nil {
			c.Close()
			require.NoError(t, err)
		}
		if size != 0 {
			c.Close()
			continue
		}
		claimed, err := c.SetNX(ctx, "genesis-test-reservation", reservation, 0).Result()
		require.NoError(t, err)
		if !claimed {
			c.Close()
			continue
		}
		t.Setenv("OCTELIUM_REDIS_DATABASE", strconv.Itoa(database))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if owner, err := c.Get(ctx, "genesis-test-reservation").Result(); err == nil && owner == reservation {
				assert.NoError(t, c.FlushDB(ctx).Err())
			}
			assert.NoError(t, c.Close())
		})
		return c
	}
	t.Fatal("No empty Redis database is available for the initialization test")
	return nil
}

type initializationFixture struct {
	genesis *Genesis
	client  *FakeClient
	db      *sql.DB
	redis   *redis.Client
	input   *LoadedClusterResource
}

func newInitializationFixture(t *testing.T) *initializationFixture {
	t.Helper()
	previous := ldflags.TestMode
	ldflags.TestMode = "true"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for name, value := range map[string]string{
		"OCTELIUM_POSTGRES_NOSSL": "true", "OCTELIUM_POSTGRES_HOST": "localhost",
		"OCTELIUM_POSTGRES_USERNAME": "postgres", "OCTELIUM_POSTGRES_PASSWORD": "postgres",
		"OCTELIUM_REGION_NAME": "default",
	} {
		t.Setenv(name, value)
	}
	redisC := reserveInitializationRedis(t)
	database := "genesis" + utilrand.GetRandomStringLowercase(12)
	adminDB, err := postgresutils.NewDBWithNODB()
	require.NoError(t, err)
	_, err = adminDB.ExecContext(t.Context(), "CREATE DATABASE "+database)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := adminDB.ExecContext(context.Background(), "DROP DATABASE "+database+" WITH (FORCE)")
		assert.NoError(t, err)
		assert.NoError(t, adminDB.Close())
	})
	t.Setenv("OCTELIUM_POSTGRES_DATABASE", database)
	db, err := postgresutils.NewDB()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Setenv("OCTELIUM_TEST_RSCSERVER_PORT", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	require.NoError(t, listener.Close())
	input := newInitializationInput(t)
	input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Database = database
	c := newFakeClient()
	require.NoError(t, c.K8sC.(*k8sfake.Clientset).Tracker().Add(&k8scorev1.Namespace{
		ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS, UID: "preserved-namespace", Labels: map[string]string{"custom": "preserved"}},
	}))
	require.NoError(t, c.K8sC.(*k8sfake.Clientset).Tracker().Add(&k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "storage-auth", Namespace: vutils.K8sNS}, Data: map[string][]byte{"password": []byte("preserved")},
	}))
	_, err = c.K8sC.CoreV1().Secrets("default").Create(t.Context(), &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"},
		Data:       map[string][]byte{"domain": []byte(input.Domain), "bootstrap": pbutils.MarshalMust(input.Bootstrap), "region": pbutils.MarshalMust(input.Region)},
	}, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	g := &Genesis{k8sC: c.K8sC, nadC: c.NadC}
	t.Cleanup(func() {
		if g.rscServer != nil {
			g.rscServer.Stop()
		}
	})
	return &initializationFixture{genesis: g, client: c, db: db, redis: redisC, input: input}
}

func initializationRows(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT resource::text FROM octelium_resources ORDER BY uid`)
	require.NoError(t, err)
	defer rows.Close()
	var ret []string
	for rows.Next() {
		var resource string
		require.NoError(t, rows.Scan(&resource))
		ret = append(ret, resource)
	}
	require.NoError(t, rows.Err())
	return ret
}

func initializationSecrets(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT resource->'metadata'->>'name', resource::text FROM octelium_resources WHERE kind = 'Secret'`)
	require.NoError(t, err)
	defer rows.Close()
	ret := make(map[string]string)
	for rows.Next() {
		var name, resource string
		require.NoError(t, rows.Scan(&name, &resource))
		ret[name] = resource
	}
	require.NoError(t, rows.Err())
	return ret
}

func (f *initializationFixture) checkPreserved(t *testing.T) {
	t.Helper()
	namespace, err := f.client.K8sC.CoreV1().Namespaces().Get(t.Context(), vutils.K8sNS, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "preserved-namespace", string(namespace.UID))
	assert.Equal(t, "preserved", namespace.Labels["custom"])
	secret, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "storage-auth", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "preserved", string(secret.Data["password"]))
	for _, action := range f.client.K8sC.(*k8sfake.Clientset).Actions() {
		if action.GetResource().Resource == "namespaces" {
			assert.NotEqual(t, "delete", action.GetVerb())
		}
	}
}

func TestInitializationReplayE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.redis.Set(t.Context(), "unrelated-sentinel", "preserved", 0).Err())
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	rows := initializationRows(t, f.db)
	cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	token, err := f.genesis.getInitAuthenticationToken(t.Context())
	require.NoError(t, err)
	credential, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
	require.NoError(t, err)
	keys := initializationSecrets(t, f.db)
	for range 3 {
		restarted := &Genesis{k8sC: f.client.K8sC, nadC: f.client.NadC}
		require.NoError(t, restarted.RunInit(t.Context(), nil))
		assert.Equal(t, f.genesis.initializationID, restarted.initializationID)
		assert.Equal(t, rows, initializationRows(t, f.db))
	}
	current, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	assert.True(t, proto.Equal(cc, current))
	stored, err := f.genesis.getInitAuthenticationToken(t.Context())
	require.NoError(t, err)
	assert.Equal(t, token.Data, stored.Data)
	currentCredential, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
	require.NoError(t, err)
	assert.True(t, proto.Equal(credential, currentCredential))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	signer, err := jwkctl.NewJWKController(t.Context(), f.genesis.octeliumC, nil)
	require.NoError(t, err)
	_, err = signer.VerifyCredential(string(stored.Data["data"]))
	require.NoError(t, err)
	assert.Equal(t, "preserved", f.redis.Get(t.Context(), "unrelated-sentinel").Val())
	f.checkPreserved(t)
}

func TestInitializationFailureRecoveryE2E(t *testing.T) {
	for _, point := range []struct {
		verb, resource, namespace, name string
		nad                             bool
	}{
		{"create", "secrets", vutils.K8sNS, initializationSecretName, false},
		{"create", "secrets", vutils.K8sNS, "octelium-postgres", false},
		{"create", "secrets", vutils.K8sNS, "octelium-redis", false},
		{"create", "configmaps", vutils.K8sNS, installationConfigMapName, false},
		{"create", "serviceaccounts", vutils.K8sNS, "octelium-gwagent", false},
		{"create", "daemonsets", vutils.K8sNS, "octelium-gwagent", false},
		{"create", "deployments", vutils.K8sNS, "octelium-nocturne", false},
		{"create", "deployments", vutils.K8sNS, "octelium-octovigil", false},
		{"create", "deployments", vutils.K8sNS, "octelium-ingress-dataplane", false},
		{"create", "network-attachment-definitions", vutils.K8sNS, "octelium", true},
		{"create", "secrets", vutils.K8sNS, "octelium-init", false},
		{"delete", "secrets", "default", "octelium-init", false},
		{"create", "secrets", vutils.K8sNS, "init-token", false},
		{"update", "secrets", vutils.K8sNS, initializationSecretName, false},
	} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/%s/committed=%t", point.verb, point.resource, point.name, committed), func(t *testing.T) {
				f := newInitializationFixture(t)
				failed := false
				tracker := f.client.K8sC.(*k8sfake.Clientset).Tracker()
				reactor := func(action k8stesting.Action) (bool, runtime.Object, error) {
					if failed || action.GetNamespace() != point.namespace {
						return false, nil, nil
					}
					var object runtime.Object
					name := ""
					switch a := action.(type) {
					case k8stesting.CreateAction:
						object = a.GetObject()
						name = object.(k8smetav1.Object).GetName()
					case k8stesting.UpdateAction:
						object = a.GetObject()
						name = object.(k8smetav1.Object).GetName()
					case k8stesting.DeleteAction:
						name = a.GetName()
					}
					if name != point.name {
						return false, nil, nil
					}
					failed = true
					if committed {
						switch point.verb {
						case "create":
							require.NoError(t, tracker.Create(action.GetResource(), object, action.GetNamespace()))
						case "update":
							require.NoError(t, tracker.Update(action.GetResource(), object, action.GetNamespace()))
						case "delete":
							require.NoError(t, tracker.Delete(action.GetResource(), action.GetNamespace(), name))
						}
					}
					return true, nil, io.ErrUnexpectedEOF
				}
				if point.nad {
					c := f.client.NadC.(*fakenad.Clientset)
					tracker = c.Tracker()
					c.PrependReactor(point.verb, point.resource, reactor)
				} else {
					f.client.K8sC.(*k8sfake.Clientset).PrependReactor(point.verb, point.resource, reactor)
				}
				require.Error(t, f.genesis.RunInit(t.Context(), nil))
				require.True(t, failed)
				secrets := make(map[string]string)
				var cc *corev1.ClusterConfig
				var tableExists bool
				require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT to_regclass('octelium_resources') IS NOT NULL`).Scan(&tableExists))
				if tableExists {
					secrets = initializationSecrets(t, f.db)
					loaded := &corev1.ClusterConfig{}
					if getInitializationResource(t.Context(), f.db, ucorev1.KindClusterConfig, "default", loaded) == nil {
						cc = loaded
					}
				}
				restarted := &Genesis{k8sC: f.client.K8sC, nadC: f.client.NadC, rscServer: f.genesis.rscServer}
				require.NoError(t, restarted.RunInit(t.Context(), nil))
				if f.genesis.rscServer == nil {
					f.genesis.rscServer = restarted.rscServer
				}
				currentSecrets := initializationSecrets(t, f.db)
				for name, secret := range secrets {
					assert.Equal(t, secret, currentSecrets[name], name)
				}
				if cc != nil {
					client := restarted.octeliumC
					if client == nil {
						client = f.genesis.octeliumC
					}
					current, err := client.CoreV1Utils().GetClusterConfig(t.Context())
					require.NoError(t, err)
					assert.True(t, proto.Equal(cc, current))
				}
				state, err := restarted.loadInitializationInput(t.Context())
				require.NoError(t, err)
				init, err := restarted.prepareInitialization(t.Context(), state)
				require.NoError(t, err)
				assert.True(t, init.complete)
				_, err = restarted.getInitAuthenticationToken(t.Context())
				require.NoError(t, err)
				f.checkPreserved(t)
			})
		}
	}
}

func TestInitializationRejectsExistingPrimaryStorageE2E(t *testing.T) {
	for _, clusterConfig := range []bool{false, true} {
		t.Run(fmt.Sprint(clusterConfig), func(t *testing.T) {
			f := newInitializationFixture(t)
			require.NoError(t, postgresutils.Migrate(t.Context(), f.db))
			resource := &corev1.User{Metadata: &metav1.Metadata{Name: "existing", Uid: vutils.UUIDv4()}, Spec: &corev1.User_Spec{}}
			kind := ucorev1.KindUser
			var object proto.Message = resource
			if clusterConfig {
				object = &corev1.ClusterConfig{Metadata: &metav1.Metadata{Name: "default", Uid: resource.Metadata.Uid}, Spec: &corev1.ClusterConfig_Spec{}, Status: &corev1.ClusterConfig_Status{Domain: "existing.example"}}
				kind = ucorev1.KindClusterConfig
			}
			data, err := pbutils.MarshalJSON(object, false)
			require.NoError(t, err)
			_, err = f.db.ExecContext(t.Context(), `INSERT INTO octelium_resources(uid, created_at, api, version, kind, resource) VALUES ($1, NOW(), $2, $3, $4, $5)`, resource.Metadata.Uid, ucorev1.API, ucorev1.Version, kind, string(data))
			require.NoError(t, err)
			before := initializationRows(t, f.db)
			require.NoError(t, f.redis.Set(t.Context(), "existing-data", "preserved", 0).Err())
			require.ErrorContains(t, f.genesis.RunInit(t.Context(), nil), "primary storage")
			assert.Equal(t, before, initializationRows(t, f.db))
			assert.Equal(t, "preserved", f.redis.Get(t.Context(), "existing-data").Val())
			assert.Equal(t, int64(0), f.redis.Exists(t.Context(), initializationRedisKey).Val())
			f.checkPreserved(t)
		})
	}
}

func TestInitializationRejectsExistingRedisE2E(t *testing.T) {
	for _, key := range []string{"octelium:rsc:cache:existing", "rsc:core:v1:ClusterConfig:default", initializationRedisKey} {
		t.Run(key, func(t *testing.T) {
			f := newInitializationFixture(t)
			require.NoError(t, f.redis.Set(t.Context(), key, "existing", 0).Err())
			require.ErrorContains(t, f.genesis.RunInit(t.Context(), nil), "Redis database")
			assert.Empty(t, initializationRows(t, f.db))
			assert.Equal(t, "existing", f.redis.Get(t.Context(), key).Val())
			f.checkPreserved(t)
		})
	}
}

func TestInitializationLockE2E(t *testing.T) {
	f := newInitializationFixture(t)
	unlock, err := lockInitialization(t.Context(), f.db)
	require.NoError(t, err)
	_, err = lockInitialization(t.Context(), f.db)
	require.ErrorContains(t, err, "Another genesis initialization")
	unlock()
	unlock, err = lockInitialization(t.Context(), f.db)
	require.NoError(t, err)
	unlock()
}

func TestInitializationLegacyUpgradeE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	_, err := f.db.ExecContext(t.Context(), `UPDATE octelium_resources SET resource = resource #- '{metadata,annotations,octelium.com/genesis-init-id}' WHERE kind IN ('ClusterConfig', 'Region')`)
	require.NoError(t, err)
	require.NoError(t, f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Delete(t.Context(), initializationSecretName, k8smetav1.DeleteOptions{}))
	require.NoError(t, f.redis.Del(t.Context(), initializationRedisKey).Err())
	_, err = f.db.ExecContext(t.Context(), `UPDATE octelium_resources SET resource = jsonb_set(resource, '{metadata,name}', '"sys:aes256-key-legacyab"') WHERE kind = 'Secret' AND resource->'metadata'->>'name' = 'sys:aes256-key-genesis'`)
	require.NoError(t, err)
	legacyToken, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "init-token", k8smetav1.GetOptions{})
	require.NoError(t, err)
	legacyToken.Annotations = nil
	_, err = f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Update(t.Context(), legacyToken, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
	before := initializationRows(t, f.db)
	keys := initializationSecrets(t, f.db)
	cc := &corev1.ClusterConfig{}
	require.NoError(t, getInitializationResource(t.Context(), f.db, ucorev1.KindClusterConfig, "default", cc))
	require.ErrorContains(t, f.genesis.RunInit(t.Context(), nil), "octops upgrade")
	assert.Equal(t, before, initializationRows(t, f.db))
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		current, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
		require.NoError(t, err)
		assert.True(t, proto.Equal(cc, current))
		assert.Equal(t, keys, initializationSecrets(t, f.db))
		_, err = f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
		assert.Error(t, err)
	}
	f.checkPreserved(t)
}

func TestInitializationResourceWriteRecoveryE2E(t *testing.T) {
	for _, point := range []struct{ kind, name string }{
		{ucorev1.KindUser, "root"},
		{ucorev1.KindUser, "octelium"},
		{ucorev1.KindSecret, "sys:ssh-ca"},
		{ucorev1.KindSecret, "sys:ssh-svc-seed"},
		{ucorev1.KindSecret, "sys:aes256-key-genesis"},
		{ucorev1.KindSecret, vutils.ClusterCertSecretName},
		{ucorev1.KindSecret, "sys:bootstrap-config"},
		{ucorev1.KindConfig, "sys:conn-info"},
		{ucorev1.KindCredential, "root-init"},
	} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/committed=%t", point.kind, point.name, committed), func(t *testing.T) {
				f := newInitializationFixture(t)
				failed := false
				hook := func(_ context.Context, object umetav1.ResourceObjectI, _, _, kind string) error {
					if !failed && kind == point.kind && object.GetMetadata().Name == point.name {
						failed = true
						return status.Error(codes.Unavailable, "injected resource failure")
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
				keys := initializationSecrets(t, f.db)
				cc := &corev1.ClusterConfig{}
				require.NoError(t, getInitializationResource(t.Context(), f.db, ucorev1.KindClusterConfig, "default", cc))
				restarted := &Genesis{k8sC: f.client.K8sC, nadC: f.client.NadC, rscServer: server}
				require.NoError(t, restarted.RunInit(t.Context(), nil))
				currentKeys := initializationSecrets(t, f.db)
				for name, key := range keys {
					assert.Equal(t, key, currentKeys[name], name)
				}
				current, err := restarted.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
				require.NoError(t, err)
				assert.True(t, proto.Equal(cc, current))
				f.checkPreserved(t)
			})
		}
	}
}

func TestInitializationSeedWriteRecoveryE2E(t *testing.T) {
	for _, kind := range []string{ucorev1.KindClusterConfig, ucorev1.KindRegion} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%t", kind, committed), func(t *testing.T) {
				f := newInitializationFixture(t)
				state, err := f.genesis.prepareInitialization(t.Context(), f.input)
				require.NoError(t, err)
				failed := false
				hook := func(_ context.Context, _ umetav1.ResourceObjectI, _, _, resourceKind string) error {
					if !failed && kind == resourceKind {
						failed = true
						return status.Error(codes.Unavailable, "injected seed failure")
					}
					return nil
				}
				opts := &rscserver.Opts{PreCreate: hook}
				if committed {
					opts = &rscserver.Opts{PostCreate: hook}
				}
				server, err := rscserver.NewServer(t.Context(), opts)
				require.NoError(t, err)
				t.Cleanup(server.Stop)
				_, err = initializeClusterResources(t.Context(), server, state)
				require.Error(t, err)
				require.True(t, failed)
				seeded, err := initializeClusterResources(t.Context(), server, state)
				require.NoError(t, err)
				assert.Equal(t, state.id, seeded.ClusterConfig.Metadata.Annotations[initializationIDKey])
				assert.Equal(t, state.id, seeded.Region.Metadata.Annotations[initializationIDKey])
				assert.True(t, proto.Equal(state.clusterConfig.Status.Network, seeded.ClusterConfig.Status.Network))
				before := initializationRows(t, f.db)
				_, err = initializeClusterResources(t.Context(), server, state)
				require.NoError(t, err)
				assert.Equal(t, before, initializationRows(t, f.db))
			})
		}
	}
}

func TestInitializationCredentialUpdateRecoveryE2E(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			f := newInitializationFixture(t)
			failed := false
			hook := func(_ context.Context, object, _ umetav1.ResourceObjectI, _, _, kind string) error {
				if !failed && kind == ucorev1.KindCredential && object.GetMetadata().Name == "root-init" {
					failed = true
					return status.Error(codes.Unavailable, "injected token rotation failure")
				}
				return nil
			}
			opts := &rscserver.Opts{PreUpdate: hook}
			if committed {
				opts = &rscserver.Opts{PostUpdate: hook}
			}
			server, err := rscserver.NewServer(t.Context(), opts)
			require.NoError(t, err)
			f.genesis.rscServer = server
			require.NoError(t, server.Run(t.Context()))
			require.Error(t, f.genesis.RunInit(t.Context(), nil))
			require.True(t, failed)
			credential, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
			require.NoError(t, err)
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			current, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
			require.NoError(t, err)
			assert.Equal(t, credential.Metadata.Uid, current.Metadata.Uid)
			if committed {
				assert.Equal(t, credential.Status.TokenID, current.Status.TokenID)
			}
			assert.Equal(t, uint32(1), current.Status.TotalRotations)
			stored, err := f.genesis.getInitAuthenticationToken(t.Context())
			require.NoError(t, err)
			controller, err := jwkctl.NewJWKController(t.Context(), f.genesis.octeliumC, nil)
			require.NoError(t, err)
			claims, err := controller.VerifyCredential(string(stored.Data["data"]))
			require.NoError(t, err)
			assert.Equal(t, current.Status.TokenID, claims.TokenID)
		})
	}
}

func TestInitializationPasswordReferenceNamespaceE2E(t *testing.T) {
	f := newInitializationFixture(t)
	storage, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "storage-auth", k8smetav1.GetOptions{})
	require.NoError(t, err)
	storage.Data["password"] = []byte("postgres")
	_, err = f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Update(t.Context(), storage, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
	f.input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret_{
		PasswordFromSecret: &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_PasswordFromSecret{
			Name: "storage-auth", Namespace: vutils.K8sNS, Key: "password",
		},
	}
	input, err := f.client.K8sC.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	input.Data["bootstrap"] = pbutils.MarshalMust(f.input.Bootstrap)
	_, err = f.client.K8sC.CoreV1().Secrets("default").Update(t.Context(), input, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	stored, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "storage-auth", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, storage.Data, stored.Data)
	derived, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "octelium-postgres", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, storage.Data["password"], derived.Data["postgres-password"])
	namespace, err := f.client.K8sC.CoreV1().Namespaces().Get(t.Context(), vutils.K8sNS, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "preserved-namespace", string(namespace.UID))
}

func TestInitializationCompletedReplayPreservesRevocationE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	credential, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
	require.NoError(t, err)
	_, err = f.genesis.octeliumC.CoreC().DeleteCredential(t.Context(), &rmetav1.DeleteOptions{Uid: credential.Metadata.Uid})
	require.NoError(t, err)
	require.NoError(t, f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Delete(t.Context(), "init-token", k8smetav1.DeleteOptions{}))
	rows := initializationRows(t, f.db)
	require.Error(t, f.genesis.RunInit(t.Context(), nil))
	assert.Equal(t, rows, initializationRows(t, f.db))
	f.checkPreserved(t)
}

func TestInitializationRejectsInvalidCredentialE2E(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *initializationFixture, *corev1.Credential)
	}{
		{"disabled", func(_ *testing.T, _ *initializationFixture, c *corev1.Credential) { c.Spec.IsDisabled = true }},
		{"locked", func(_ *testing.T, _ *initializationFixture, c *corev1.Credential) { c.Status.IsLocked = true }},
		{"expired", func(_ *testing.T, _ *initializationFixture, c *corev1.Credential) {
			c.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(-time.Hour))
		}},
		{"wrong-type", func(_ *testing.T, _ *initializationFixture, c *corev1.Credential) {
			c.Spec.Type = corev1.Credential_Spec_OAUTH2
		}},
		{"wrong-user", func(_ *testing.T, _ *initializationFixture, c *corev1.Credential) { c.Spec.User = "octelium" }},
		{"missing-user-reference", func(_ *testing.T, _ *initializationFixture, c *corev1.Credential) { c.Status.UserRef = nil }},
		{"missing-user", func(_ *testing.T, _ *initializationFixture, c *corev1.Credential) {
			c.Status.UserRef = &metav1.ObjectReference{Uid: vutils.UUIDv4()}
		}},
		{"wrong-user-reference", func(t *testing.T, f *initializationFixture, c *corev1.Credential) {
			user, err := f.genesis.octeliumC.CoreC().GetUser(t.Context(), &rmetav1.GetOptions{Name: "octelium"})
			require.NoError(t, err)
			c.Status.UserRef = umetav1.GetObjectReference(user)
		}},
		{"system-user", func(t *testing.T, f *initializationFixture, _ *corev1.Credential) {
			user, err := f.genesis.octeliumC.CoreC().GetUser(t.Context(), &rmetav1.GetOptions{Name: "root"})
			require.NoError(t, err)
			user.Metadata.IsSystem = true
			_, err = f.genesis.octeliumC.CoreC().UpdateUser(t.Context(), user)
			require.NoError(t, err)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newInitializationFixture(t)
			failed := false
			f.client.K8sC.(*k8sfake.Clientset).PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.GetNamespace() != vutils.K8sNS || action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret).Name != "init-token" {
					return false, nil, nil
				}
				failed = true
				return true, nil, io.ErrUnexpectedEOF
			})
			require.Error(t, f.genesis.RunInit(t.Context(), nil))
			require.True(t, failed)
			credential, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
			require.NoError(t, err)
			test.change(t, f, credential)
			credential, err = f.genesis.octeliumC.CoreC().UpdateCredential(t.Context(), credential)
			require.NoError(t, err)
			failed = false
			require.Error(t, f.genesis.createInitAuthenticationToken(t.Context()))
			assert.False(t, failed)
			current, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
			require.NoError(t, err)
			assert.True(t, proto.Equal(credential, current))
		})
	}
}
