package genesis

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func preserveRepairStorageEnvironment(t *testing.T) func() {
	t.Helper()
	values := map[string]string{}
	for _, prefix := range []string{"OCTELIUM_POSTGRES_", "OCTELIUM_REDIS_"} {
		for _, suffix := range []string{"HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD", "NOSSL", "USE_TLS"} {
			key := prefix + suffix
			values[key] = os.Getenv(key)
			t.Setenv(key, values[key])
		}
	}
	return func() {
		for key, value := range values {
			os.Setenv(key, value)
		}
	}
}

func assertRepairBeforeStorage(t *testing.T, f *initializationFixture) {
	t.Helper()
	var exists bool
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT to_regclass('octelium_resources') IS NOT NULL`).Scan(&exists))
	assert.False(t, exists)
	marker, err := f.redis.Exists(t.Context(), initializationRedisKey).Result()
	require.NoError(t, err)
	assert.Zero(t, marker)
	for _, name := range []string{initializationSecretName, "octelium-postgres", "octelium-redis", "init-token"} {
		_, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, metav1.GetOptions{})
		assert.True(t, k8serr.IsNotFound(err), name)
	}
	f.checkPreserved(t)
}

func TestRepairConnectionFailureBeforeBindingE2E(t *testing.T) {
	for _, point := range []string{"postgres-host", "postgres-auth", "redis-host", "redis-auth"} {
		t.Run(point, func(t *testing.T) {
			f := newInitializationFixture(t)
			restore := preserveRepairStorageEnvironment(t)
			good := proto.Clone(f.input.Bootstrap).(*cbootstrapv1.Config)
			good.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{Password: ""}
			f.input.Bootstrap = proto.Clone(good).(*cbootstrapv1.Config)
			pg, redis := f.input.Bootstrap.Spec.PrimaryStorage.GetPostgresql(), f.input.Bootstrap.Spec.SecondaryStorage.GetRedis()
			if point == "postgres-host" {
				pg.Host = "gen037-does-not-exist.invalid"
			}
			if point == "redis-host" {
				redis.Host = "gen037-does-not-exist.invalid"
			}
			if point == "redis-auth" {
				redis.PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{Password: "private-invalid-redis-password"}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { listener.Close() })
				redis.Host, redis.Port = "127.0.0.1", int32(listener.Addr().(*net.TCPAddr).Port)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					reader := bufio.NewReader(conn)
					for {
						line, err := reader.ReadString('\n')
						if err != nil || !strings.HasPrefix(line, "*") {
							return
						}
						count, err := strconv.Atoi(strings.TrimSpace(line[1:]))
						if err != nil || count < 1 || count > 100 {
							return
						}
						for range count {
							line, err := reader.ReadString('\n')
							if err != nil || !strings.HasPrefix(line, "$") {
								return
							}
							length, err := strconv.Atoi(strings.TrimSpace(line[1:]))
							if err != nil || length < 0 || length > 100000 {
								return
							}
							if _, err := io.CopyN(io.Discard, reader, int64(length+2)); err != nil {
								return
							}
						}
						if _, err := io.WriteString(conn, "-WRONGPASS invalid username-password pair\r\n"); err != nil {
							return
						}
					}
				}()
			}
			if point == "postgres-auth" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { listener.Close() })
				pg.Host, pg.Port = "127.0.0.1", int32(listener.Addr().(*net.TCPAddr).Port)
				pg.PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password{Password: "private-invalid-postgres-password"}
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					var length uint32
					if err := binary.Read(conn, binary.BigEndian, &length); err != nil || length < 4 || length > 100000 {
						return
					}
					if _, err := io.CopyN(io.Discard, conn, int64(length-4)); err != nil {
						return
					}
					body := []byte("SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")
					conn.Write([]byte{'E'})
					binary.Write(conn, binary.BigEndian, uint32(len(body)+4))
					conn.Write(body)
				}()
			}
			savePasswordBootstrap(t, f)
			_, err := f.client.K8sC.CoreV1().Nodes().Create(t.Context(), &k8scorev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "ready-node"},
				Status:     k8scorev1.NodeStatus{Conditions: []k8scorev1.NodeCondition{{Type: k8scorev1.NodeReady, Status: k8scorev1.ConditionTrue}}},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
			ldflags.TestMode = "false"
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			err = f.genesis.RunInit(ctx, nil)
			cancel()
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "private-invalid-")
			assertRepairBeforeStorage(t, f)
			restore()
			ldflags.TestMode = "true"
			f.input.Bootstrap = good
			savePasswordBootstrap(t, f)
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			keys := initializationSecrets(t, f.db)
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
			assert.Equal(t, keys, initializationSecrets(t, f.db))
			f.checkPreserved(t)
		})
	}
}

func TestRepairStalledStoragePreflight(t *testing.T) {
	for _, storage := range []string{"postgres", "redis", "redis-tls"} {
		t.Run(storage, func(t *testing.T) {
			f := newInitializationFixture(t)
			preserveRepairStorageEnvironment(t)
			ldflags.TestMode = "false"
			bootstrap := proto.Clone(f.input.Bootstrap).(*cbootstrapv1.Config)
			bootstrap.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{Password: ""}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			port := int32(listener.Addr().(*net.TCPAddr).Port)
			if storage == "postgres" {
				bootstrap.Spec.PrimaryStorage.GetPostgresql().Host, bootstrap.Spec.PrimaryStorage.GetPostgresql().Port = "127.0.0.1", port
			} else {
				bootstrap.Spec.SecondaryStorage.GetRedis().Host, bootstrap.Spec.SecondaryStorage.GetRedis().Port = "127.0.0.1", port
				bootstrap.Spec.SecondaryStorage.GetRedis().IsTLS = storage == "redis-tls"
			}
			closed := make(chan struct{})
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				io.Copy(io.Discard, conn)
				close(closed)
			}()
			passwords, err := f.genesis.resolveStoragePasswords(t.Context(), bootstrap)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			err = preflightInitializationStorage(ctx, bootstrap, passwords)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Less(t, time.Since(start), 2*time.Second)
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("Storage connection was not closed on cancellation")
			}
			assertRepairBeforeStorage(t, f)
		})
	}
}

func TestRepairStoragePreflightAcceptsSpecialCredentials(t *testing.T) {
	f := newInitializationFixture(t)
	preserveRepairStorageEnvironment(t)
	ldflags.TestMode = "false"
	name := "gen037 user /?@" + strconv.FormatInt(time.Now().UnixNano(), 36)
	password := " pa:ss/@?#&% ' \\ π "
	_, err := f.db.ExecContext(t.Context(), "CREATE ROLE "+pq.QuoteIdentifier(name)+" LOGIN PASSWORD "+pq.QuoteLiteral(password))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := f.db.ExecContext(context.Background(), "DROP ROLE "+pq.QuoteIdentifier(name))
		assert.NoError(t, err)
	})
	bootstrap := proto.Clone(f.input.Bootstrap).(*cbootstrapv1.Config)
	bootstrap.Spec.PrimaryStorage.GetPostgresql().Username = name
	bootstrap.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password{Password: password}
	redisUser := "gen037:user@" + strconv.FormatInt(time.Now().UnixNano(), 36)
	require.NoError(t, f.redis.Do(t.Context(), "ACL", "SETUSER", redisUser, "on", ">"+password, "+@all", "~*").Err())
	t.Cleanup(func() { assert.NoError(t, f.redis.Do(context.Background(), "ACL", "DELUSER", redisUser).Err()) })
	bootstrap.Spec.SecondaryStorage.GetRedis().Username = redisUser
	bootstrap.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{Password: password}
	passwords, err := f.genesis.resolveStoragePasswords(t.Context(), bootstrap)
	require.NoError(t, err)
	require.NoError(t, preflightInitializationStorage(t.Context(), bootstrap, passwords))
	assertRepairBeforeStorage(t, f)
}

func TestRepairCheckpointOnlyInitializationE2E(t *testing.T) {
	f := newInitializationFixture(t)
	state, err := f.genesis.prepareInitialization(t.Context(), f.input)
	require.NoError(t, err)
	c := f.client.K8sC.(*fake.Clientset)
	checkpoint, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	checkpoint.ResourceVersion = "1"
	require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, vutils.K8sNS))
	f.input.Bootstrap.Spec.Cni = &cbootstrapv1.Config_Spec_CNI{ConfDirType: &cbootstrapv1.Config_Spec_CNI_MultusConfDir{MultusConfDir: "/custom/multus"}}
	savePasswordBootstrap(t, f)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	current, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, state.id, string(current.Data["id"]))
	assert.Equal(t, "true", current.Annotations[initializationCompleteKey])
	keys := initializationSecrets(t, f.db)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	assert.NotEmpty(t, current.Data["aes-key-name"])
}

func attachRepairJob(t *testing.T, f *initializationFixture, binding string) *k8scorev1.Pod {
	t.Helper()
	pod := upgradeTestPod("init-job-uid")
	pod.Namespace, pod.Name = "default", "genesis-attempt"
	pod.Annotations = map[string]string{initializationInputHashKey: binding}
	pod.Labels = map[string]string{"octelium.com/component": "genesis"}
	pod.Status.Phase = k8scorev1.PodRunning
	pod.OwnerReferences[0].Name = "octelium-genesis"
	owner := metav1.GetControllerOf(pod)
	_, err := f.client.K8sC.BatchV1().Jobs(pod.Namespace).Create(t.Context(), &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: owner.Name, Namespace: pod.Namespace, UID: owner.UID, Labels: pod.Labels},
		Status:     batchv1.JobStatus{Active: 1},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	pod, err = f.client.K8sC.CoreV1().Pods(pod.Namespace).Create(t.Context(), pod, metav1.CreateOptions{})
	require.NoError(t, err)
	f.genesis.pod = pod
	return pod
}

func TestRepairInputBindingFailureIsReadOnlyE2E(t *testing.T) {
	f := newInitializationFixture(t)
	attachRepairJob(t, f, "different-input-binding")
	require.ErrorContains(t, f.genesis.RunInit(t.Context(), nil), "no longer matches")
	assertRepairBeforeStorage(t, f)
}

func TestRepairBoundInitializationResumesAfterHandoffE2E(t *testing.T) {
	f := newInitializationFixture(t)
	source, err := f.client.K8sC.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	source.Data[initializationInputKey] = []byte("01234567890123456789012345678901")
	_, err = f.client.K8sC.CoreV1().Secrets("default").Update(t.Context(), source, metav1.UpdateOptions{})
	require.NoError(t, err)
	input, err := f.genesis.loadInitializationInput(t.Context())
	require.NoError(t, err)
	hash, err := initializationInputHash(input)
	require.NoError(t, err)
	sourceUID := string(source.UID)
	pod := attachRepairJob(t, f, initializationInputBinding(hash, f.genesis.inputBindingKey))
	c := f.client.K8sC.(*fake.Clientset)
	failed := false
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		secret := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret)
		if secret.Name == "init-token" && !failed {
			failed = true
			return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), secret.Name, io.EOF)
		}
		return false, nil, nil
	})
	require.Error(t, f.genesis.RunInit(t.Context(), nil))
	assert.True(t, failed)
	_, err = c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.True(t, k8serr.IsNotFound(err))
	installed, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, sourceUID, string(installed.UID))
	keys := initializationSecrets(t, f.db)
	restarted := &Genesis{k8sC: c, nadC: f.client.NadC, pod: pod, rscServer: f.genesis.rscServer}
	require.NoError(t, restarted.RunInit(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	require.NoError(t, restarted.RunInit(t.Context(), nil))
	require.NoError(t, restarted.RunUpgrade(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	f.checkPreserved(t)
}

func TestRepairTLSConnection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	dialer := &initializationDialer{ctx: ctx, tlsConfig: config}
	conn, err := dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestRepairStorageEnvironmentKeepsLegacyFallbacks(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	values := map[string]string{
		"OCTELIUM_POSTGRES_HOST": "::1", "OCTELIUM_POSTGRES_PORT": "6432", "OCTELIUM_POSTGRES_DATABASE": "tenant/db?@",
		"OCTELIUM_POSTGRES_USERNAME": "custom user", "OCTELIUM_POSTGRES_PASSWORD": " p@ss:/?& ", "OCTELIUM_POSTGRES_NOSSL": "true",
		"OCTELIUM_REDIS_HOST": "cache.example", "OCTELIUM_REDIS_PORT": "6380", "OCTELIUM_REDIS_DATABASE": "7",
		"OCTELIUM_REDIS_USERNAME": "custom:user", "OCTELIUM_REDIS_PASSWORD": "p@ss:/?&", "OCTELIUM_REDIS_USE_TLS": "true",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
	bootstrap := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {isTLS: true}}, secondaryStorage: {redis: {}}}"), bootstrap))
	setStorageEnvironment(bootstrap, &storagePasswords{})
	for key, value := range values {
		assert.Equal(t, value, os.Getenv(key), key)
	}
}
