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

package e2e

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v9"
	"github.com/go-redis/redis/v8"
	"github.com/go-resty/resty/v2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nats-io/nats.go"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/net/html"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type server struct {
	domain  string
	homedir string
	t       *CustomT
	k8sC    kubernetes.Interface
}

func initServer(ctx context.Context) (*server, error) {

	ret := &server{
		domain: "localhost",
		t:      &CustomT{},
	}

	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	zap.L().Info("Current user", zap.Any("info", u))

	ret.homedir = fmt.Sprintf("/home/%s", u.Username)

	return ret, nil
}

func (s *server) run(ctx context.Context) error {
	t := s.t
	if err := s.installCluster(ctx); err != nil {
		return err
	}
	{
		os.Setenv("OCTELIUM_DOMAIN", s.domain)
		os.Setenv("OCTELIUM_INSECURE_TLS", "true")
		// os.Setenv("OCTELIUM_QUIC", "true")
		os.Setenv("OCTELIUM_PRODUCTION", "true")
		os.Setenv("HOME", s.homedir)
		os.Setenv("KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")
	}

	{
		s.runCmd(ctx, "id")
		s.runCmd(ctx, "mkdir -p ~/.ssh")
		s.runCmd(ctx, "chmod 700 ~/.ssh")
		s.runCmd(ctx, "cat /etc/rancher/k3s/k3s.yaml")
	}
	{
		zap.L().Info("Env vars", zap.Strings("env", os.Environ()))
	}

	{
		k8sC, err := getK8sC()
		if err != nil {
			return err
		}
		s.k8sC = k8sC

		assert.Nil(t, s.runK8sInitChecks(ctx))
	}

	{
		s.startKubectlLog(ctx, "-l octelium.com/svc=dns.octelium -c managed")
		s.startKubectlLog(ctx, "-l octelium.com/component=nocturne")
		s.startKubectlLog(ctx, "-l octelium.com/component=gwagent")
		s.startKubectlLog(ctx, "-l octelium.com/component=rscserver")

		assert.Nil(t, s.runCmd(ctx, "kubectl get pods -A"))
		assert.Nil(t, s.runCmd(ctx, "kubectl get deployment -A"))
		assert.Nil(t, s.runCmd(ctx, "kubectl get svc -A"))
		assert.Nil(t, s.runCmd(ctx, "kubectl get daemonset -A"))
	}

	{
		assert.Nil(t, s.runCmd(ctx, "octelium version"))
		assert.Nil(t, s.runCmd(ctx, "octelium version -o json"))
		assert.Nil(t, s.runCmd(ctx, "octeliumctl version"))
		assert.Nil(t, s.runCmd(ctx, "octelium status"))

		assert.Nil(t, s.runCmd(ctx, "octeliumctl get rgn default"))
	}
	{
		res, err := s.httpC().R().Get("https://localhost")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode())
	}
	{

		res, err := s.httpCPublic("demo-nginx").R().Get("/")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode())
	}
	{

		res, err := s.httpCPublic("portal").R().Get("/")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode())
	}

	if err := s.runOcteliumctlEmbedded(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlCommands(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumCommands(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumConnectCommands(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlApplyCommands(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlAccessToken(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlAuthToken(ctx); err != nil {
		return err
	}

	return nil
}

func (s *server) runOcteliumctlEmbedded(ctx context.Context) error {
	if err := cliutils.OpenDB(""); err != nil {
		return err
	}
	defer cliutils.CloseDB()

	t := s.t
	conn, err := client.GetGRPCClientConn(ctx, s.domain)
	assert.Nil(t, err)
	defer conn.Close()

	c := corev1.NewMainServiceClient(conn)

	{
		_, err = c.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		assert.Nil(t, err)

		_, err = c.GetService(ctx, &metav1.GetOptions{
			Name: "demo-nginx.default",
		})
		assert.Nil(t, err)

		{
			itmList, err := c.ListService(ctx, &corev1.ListServiceOptions{})
			assert.Nil(t, err)

			assert.True(t, len(itmList.Items) > 0)
		}
	}

	{
		_, err = c.DeleteService(ctx, &metav1.DeleteOptions{
			Name: "default.octelium-api",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteService(ctx, &metav1.DeleteOptions{
			Name: "auth.octelium-api",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteService(ctx, &metav1.DeleteOptions{
			Name: "default.default",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteService(ctx, &metav1.DeleteOptions{
			Name: "dns.octelium",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteService(ctx, &metav1.DeleteOptions{
			Name: "portal.default",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteNamespace(ctx, &metav1.DeleteOptions{
			Name: "default",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteNamespace(ctx, &metav1.DeleteOptions{
			Name: "octelium",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteUser(ctx, &metav1.DeleteOptions{
			Name: "octelium",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteNamespace(ctx, &metav1.DeleteOptions{
			Name: "octelium-api",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteCredential(ctx, &metav1.DeleteOptions{
			Name: "root-init",
		})
		assert.Nil(t, err)
	}

	return nil
}

func (s *server) runOcteliumctlCommands(ctx context.Context) error {
	t := s.t

	{
		args := []string{
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
		}

		for _, arg := range args {
			assert.Nil(t, s.runCmd(ctx, fmt.Sprintf("octeliumctl get %s", arg)))
		}

	}

	out, err := s.getCmd(ctx, "octeliumctl get svc -o json").CombinedOutput()
	assert.Nil(t, err)

	res := &corev1.ServiceList{}

	zap.L().Debug("Command out", zap.String("out", string(out)))

	err = pbutils.UnmarshalJSON(out, res)
	assert.Nil(t, err)

	assert.True(t, len(res.Items) > 0)

	return nil
}

func (s *server) runOcteliumCommands(ctx context.Context) error {
	t := s.t

	{
		args := []string{
			"service", "svc",
			"namespace", "ns",
		}

		for _, arg := range args {
			assert.Nil(t, s.runCmd(ctx, fmt.Sprintf("octelium get %s", arg)))
		}

		assert.Nil(t, s.runCmd(ctx, "octelium status"))
	}

	out, err := s.getCmd(ctx, "octelium get svc -o json").CombinedOutput()
	assert.Nil(t, err)

	res := &userv1.ServiceList{}

	zap.L().Debug("Command out", zap.String("out", string(out)))

	err = pbutils.UnmarshalJSON(out, res)
	assert.Nil(t, err)

	assert.True(t, len(res.Items) > 0)

	return nil
}

func (s *server) httpCPublic(svc string) *resty.Client {
	return s.httpC().SetBaseURL(fmt.Sprintf("https://%s.localhost", svc))
}

func (s *server) httpCPublicAccessToken(svc, accessToken string) *resty.Client {
	return s.httpC().SetBaseURL(fmt.Sprintf("https://%s.localhost", svc)).SetAuthScheme("Bearer").
		SetAuthToken(accessToken)
}

func (s *server) httpCPublicAccessTokenCheck(svc, accessToken string) {
	t := s.t

	res, err := s.httpCPublicAccessToken(svc, accessToken).R().Get("/")
	assert.Nil(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode())
}

func (s *server) httpC() *resty.Client {
	return resty.New().SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: true,
	}).SetRetryCount(20).SetRetryWaitTime(500 * time.Millisecond).SetRetryMaxWaitTime(2 * time.Second).
		AddRetryCondition(func(r *resty.Response, err error) bool {
			if r.StatusCode() >= 500 && r.StatusCode() < 600 {
				return true
			}
			return false
		}).
		AddRetryHook(func(r *resty.Response, err error) {
			zap.L().Debug("Retrying....", zap.Error(err))
		}).SetTimeout(40 * time.Second).SetLogger(zap.S())
}

func (s *server) runOcteliumctlApplyCommands(ctx context.Context) error {
	t := s.t
	{
		wsSrv := &tstSrvHTTP{
			port: 16000,
			isWS: true,
		}

		assert.Nil(t, wsSrv.run(ctx))
		defer wsSrv.close()
	}

	{
		mcpSrv := &mcpServer{
			port: 16001,
		}

		assert.Nil(t, mcpSrv.run(ctx))
		defer mcpSrv.close()
	}

	{
		assert.Nil(t, s.runCmd(ctx, "octeliumctl create secret password --value password"))
		assert.Nil(t, s.runCmd(ctx, "octeliumctl create secret kubeconfig -f /etc/rancher/k3s/k3s.yaml"))
	}

	{
		rootDir, err := os.MkdirTemp("", "octelium-cfg-*")
		assert.Nil(t, err)

		assert.Nil(t, os.WriteFile(path.Join(rootDir, "cfg.yaml"), []byte(cfg1), 0644))

		assert.Nil(t, s.runCmd(ctx, fmt.Sprintf("octeliumctl apply %s", rootDir)))
		assert.Nil(t, s.runCmd(ctx, fmt.Sprintf("octeliumctl apply %s/cfg.yaml", rootDir)))

		{
			res, err := s.httpCPublic("nginx-anonymous").R().Get("/")
			assert.Nil(t, err)
			assert.Equal(t, http.StatusOK, res.StatusCode())
		}
		{
			res, err := s.httpCPublic("nginx").R().Get("/")
			assert.Nil(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.StatusCode())
		}

		{
			connCmd, err := s.startOcteliumConnectRootless(ctx, []string{
				"-p nginx:15001",
				"-p google:15002",
				"-p postgres-main:15003",
				"-p essh:15004",
				"-p pg.production:15005",
				"-p redis:15006",
				"-p ws-echo:15007",
				"-p nats:15008",
				"-p mariadb:15009",
				"-p minio:15010",
				"-p opensearch:15011",
				"-p mcp-echo:15012",
				"--essh",
				"--serve-all",
			})
			assert.Nil(t, err)

			{
				res, err := s.httpC().R().Get("http://localhost:15001")
				assert.Nil(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode())

				_, err = html.Parse(strings.NewReader(string(res.Body())))
				assert.Nil(t, err)
			}

			{
				res, err := s.httpC().R().Get("http://localhost:15002")
				assert.Nil(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode())

				_, err = html.Parse(strings.NewReader(string(res.Body())))
				assert.Nil(t, err)
			}

			{
				db, err := postgresutils.NewDBWithURL(
					postgresutils.GetPostgresURLFromArgs(&postgresutils.PostgresDBArgs{
						Host:  "localhost",
						NoSSL: true,
						Port:  15003,
					}))
				assert.Nil(t, err)

				defer db.Close()

				_, err = db.Exec("SELECT current_database();")
				assert.Nil(t, err)
			}

			{
				db, err := postgresutils.NewDBWithURL(
					postgresutils.GetPostgresURLFromArgs(&postgresutils.PostgresDBArgs{
						Host:     "localhost",
						NoSSL:    true,
						Username: "postgres",
						Password: "wrong-password",
						Port:     15005,
					}))
				assert.Nil(t, err)

				defer db.Close()

				_, err = db.Exec("SELECT current_database();")
				assert.NotNil(t, err)
			}

			{

				db, err := postgresutils.NewDBWithURL(
					postgresutils.GetPostgresURLFromArgs(&postgresutils.PostgresDBArgs{
						Host:     "localhost",
						NoSSL:    true,
						Username: "postgres",
						Password: "password",
						Port:     15005,
					}))
				assert.Nil(t, err)

				defer db.Close()

				assert.Nil(t, db.Ping())
				_, err = db.Exec("SELECT current_database();")
				assert.Nil(t, err)

				assert.Nil(t, postgresutils.Migrate(ctx, db))
			}

			{

				out, err := s.getCmd(ctx,
					"octelium status -o json").CombinedOutput()
				assert.Nil(t, err)

				res := &userv1.GetStatusResponse{}

				err = pbutils.UnmarshalJSON(out, res)
				assert.Nil(t, err)

				assert.Nil(t, s.runCmd(ctx,
					fmt.Sprintf(`ssh -vvv -p 15004 %s@localhost 'ls -la'`, res.Session.Metadata.Name)))
				assert.Nil(t, s.runCmd(ctx,
					fmt.Sprintf(`ssh -p 15004 %s@localhost 'ls -la /etc'`, res.Session.Metadata.Name)))
			}

			{
				redisC := redis.NewClient(&redis.Options{
					Addr: "localhost:15006",
				})

				key := utilrand.GetRandomStringCanonical(32)
				val := utilrand.GetRandomStringCanonical(32)

				assert.Nil(t, redisC.Set(ctx, key, val, 3*time.Second).Err())
				time.Sleep(1 * time.Second)

				ret, err := redisC.Get(ctx, key).Result()
				assert.Nil(t, err)
				assert.Equal(t, val, ret)

				time.Sleep(3 * time.Second)

				_, err = redisC.Get(ctx, key).Result()
				assert.NotNil(t, err)
				assert.Equal(t, redis.Nil, err)
			}

			{
				wsClient := websocket.Dialer{
					ReadBufferSize:  1024,
					WriteBufferSize: 1024,
				}

				wsC, _, err := wsClient.DialContext(ctx, "ws://localhost:15007/", http.Header{})
				assert.Nil(t, err)

				for range 5 {
					msg := utilrand.GetRandomBytesMust(32)
					err = wsC.WriteMessage(websocket.BinaryMessage, msg)
					assert.Nil(t, err)
					_, read, err := wsC.ReadMessage()
					assert.Nil(t, err)
					assert.True(t, utils.SecureBytesEqual(msg, read))
					time.Sleep(1 * time.Second)
				}

				wsC.Close()
			}

			{
				nc, err := nats.Connect("nats://localhost:15008",
					nats.RetryOnFailedConnect(true),
					nats.ReconnectWait(3*time.Second))
				assert.Nil(t, err)

				defer nc.Drain()

				subj := utilrand.GetRandomStringCanonical(32)

				dataList := [][]byte{}
				for range 12 {
					dataList = append(dataList, utilrand.GetRandomBytesMust(32))
				}

				curIdx := 0
				nc.Subscribe(subj, func(m *nats.Msg) {
					assert.True(t, utils.SecureBytesEqual(dataList[curIdx], m.Data))
					curIdx++
					zap.L().Debug("Cur nats idx", zap.Int("idx", curIdx))
				})

				for i := range len(dataList) {
					assert.Nil(t, nc.Publish(subj, dataList[i]))
					time.Sleep(500 * time.Millisecond)
				}

			}

			{
				dsn := "root:password@tcp(localhost:15009)/"
				db, err := sql.Open("mysql", dsn)
				assert.Nil(t, err)

				defer db.Close()

				assert.Nil(t, db.Ping())

				_, err = db.Exec("CREATE DATABASE IF NOT EXISTS mydb")
				assert.Nil(t, err)

				rows, err := db.Query("SHOW DATABASES")
				assert.Nil(t, err)
				defer rows.Close()

				for rows.Next() {
					var name string
					if err := rows.Scan(&name); err != nil {
						log.Fatal(err)
					}
					fmt.Println(" -", name)
				}

				assert.Nil(t, rows.Err())
			}

			{
				client := mcp.NewClient(&mcp.Implementation{
					Name:    "echo-client",
					Version: "1.0.0",
				}, nil)

				session, err := client.Connect(ctx,
					&mcp.StreamableClientTransport{Endpoint: "http://localhost:15012"}, nil)
				assert.Nil(t, err)
				defer session.Close()

				toolsResult, err := session.ListTools(ctx, nil)
				assert.Nil(t, err)

				assert.True(t, slices.ContainsFunc(toolsResult.Tools, func(r *mcp.Tool) bool {
					return r.Name == "echo"
				}))

				input := utilrand.GetRandomString(32)

				result, err := session.CallTool(ctx, &mcp.CallToolParams{
					Name: "echo",
					Arguments: map[string]any{
						"input": input,
					},
				})
				assert.Nil(t, err)

				textContent, ok := result.Content[0].(*mcp.TextContent)
				assert.True(t, ok)
				assert.Equal(t, input, textContent)
			}

			{
				c, err := minio.New("localhost:15010", &minio.Options{
					Creds:      credentials.NewStaticV4("minioadmin", "minioadmin", ""),
					MaxRetries: 20,
				})
				assert.Nil(t, err)

				bucketName := "my-bucket"

				err = c.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{Region: ""})
				assert.Nil(t, err)

				_, err = c.FPutObject(ctx,
					bucketName, "octelium", "~/go/bin/octelium", minio.PutObjectOptions{})
				assert.Nil(t, err)

				_, err = c.FPutObject(ctx,
					bucketName, "octops", "~/go/bin/octops", minio.PutObjectOptions{})
				assert.Nil(t, err)

				err = c.FGetObject(ctx, bucketName, "octelium", "/tmp/octelium", minio.GetObjectOptions{})
				assert.Nil(t, err)

				err = c.FGetObject(ctx, bucketName, "octops", "/tmp/octops", minio.GetObjectOptions{})
				assert.Nil(t, err)

				{
					f1, err := getFileSha256("~/go/bin/octelium")
					assert.Nil(t, err)

					f2, err := getFileSha256("/tmp/octelium")
					assert.Nil(t, err)

					assert.True(t, utils.SecureBytesEqual(f1, f2))
				}

				{
					f1, err := getFileSha256("~/go/bin/octops")
					assert.Nil(t, err)

					f2, err := getFileSha256("/tmp/octops")
					assert.Nil(t, err)

					assert.True(t, utils.SecureBytesEqual(f1, f2))
				}
			}

			{
				cfg := elasticsearch.Config{
					Addresses: []string{
						"http://localhost:15011",
					},
					Username:   "admin",
					Password:   "Password_123456",
					MaxRetries: 20,
				}

				c, err := elasticsearch.NewClient(cfg)
				assert.Nil(t, err)

				resI, err := c.Info()
				assert.Nil(t, err)
				defer resI.Body.Close()

				res, err := io.ReadAll(resI.Body)
				assert.Nil(t, err)
				zap.L().Debug("OpenSearch info", zap.String("info", string(res)))

				_, err = c.Indices.Create("octelium-index")
				assert.Nil(t, err)
			}

			assert.Nil(t, s.runCmd(ctx, "octelium disconnect"))

			connCmd.Wait()

			zap.L().Debug("octelium connect exited")
		}
	}

	return nil
}

func (s *server) runOcteliumctlAccessToken(ctx context.Context) error {
	t := s.t

	out, err := s.getCmd(ctx,
		"octeliumctl create cred --user root --policy allow-all --type access-token -o json").CombinedOutput()
	assert.Nil(t, err)

	res := &corev1.CredentialToken{}

	zap.L().Debug("Command out", zap.String("out", string(out)))

	err = pbutils.UnmarshalJSON(out, res)
	assert.Nil(t, err)

	{
		s.httpCPublicAccessTokenCheck("demo-nginx", res.GetAccessToken().AccessToken)
	}

	return nil
}

func (s *server) runOcteliumctlAuthToken(ctx context.Context) error {
	t := s.t

	out, err := s.getCmd(ctx,
		"octeliumctl create cred --user root --policy allow-all -o json").CombinedOutput()
	assert.Nil(t, err)

	res := &corev1.CredentialToken{}

	zap.L().Debug("Command out", zap.String("out", string(out)))

	err = pbutils.UnmarshalJSON(out, res)
	assert.Nil(t, err)

	{

		tmpDir, err := os.MkdirTemp("/tmp", "octelium-*")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(tmpDir)

		cmd := s.getCmd(ctx, fmt.Sprintf("octelium login --auth-token %s",
			res.GetAuthenticationToken().AuthenticationToken))
		cmd.Env = append(os.Environ(), fmt.Sprintf("OCTELIUM_HOME=%s", tmpDir))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		assert.Nil(t, cmd.Run())
	}

	return nil
}

func (s *server) runOcteliumConnectCommands(ctx context.Context) error {
	t := s.t

	ctx, cancel := context.WithTimeout(ctx, 500*time.Second)
	defer cancel()

	{
		err := s.runCmd(ctx,
			fmt.Sprintf("octelium connect -p %s:14041", utilrand.GetRandomStringCanonical(8)),
		)
		assert.NotNil(t, err)
	}

	/*
		{
			connCmd, err := s.startOcteliumConnect(ctx, []string{
				"--no-dns",
			})
			assert.Nil(t, err)

			out, err := s.getCmd(ctx,
				"octeliumctl get svc demo-nginx -o json").CombinedOutput()
			assert.Nil(t, err)

			svc := &corev1.Service{}
			assert.Nil(t, pbutils.UnmarshalJSON(out, svc))

			{
				res, err := resty.New().SetDebug(true).
					SetRetryCount(10).
					R().Get(fmt.Sprintf("http://%s",
					net.JoinHostPort(svc.Status.Addresses[0].DualStackIP.Ipv6,
						fmt.Sprintf("%d", svc.Status.Port))))
				assert.Nil(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode())
			}

			assert.Nil(t, s.runCmd(ctx, "octelium disconnect"))

			connCmd.Wait()

			zap.L().Debug("octelium connect exited")
		}
	*/

	{
		connCmd, err := s.startOcteliumConnectRootless(ctx, []string{
			"-p demo-nginx:15001",
		})
		assert.Nil(t, err)

		{
			res, err := s.httpC().R().Get("http://localhost:15001")
			assert.Nil(t, err)
			assert.Equal(t, http.StatusOK, res.StatusCode())
		}

		assert.Nil(t, s.runCmd(ctx, "octelium disconnect"))

		connCmd.Wait()

		zap.L().Debug("octelium connect exited")
	}

	return nil
}

func Run(ctx context.Context) error {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(logger)

	s, err := initServer(ctx)
	if err != nil {
		return err
	}

	if err := s.run(ctx); err != nil {
		return err
	}

	if s.t.errs > 0 {
		panic(fmt.Sprintf("e2e err: %d", s.t.errs))
	}

	return nil
}

type CustomT struct {
	errs int
}

func (t *CustomT) Errorf(format string, args ...interface{}) {
	t.errs++
	zap.S().Errorf(format, args...)
}

func (t *CustomT) FailNow() {
	panic("")
}

func getK8sC() (kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", "/etc/rancher/k3s/k3s.yaml")
	if err != nil {
		return nil, err
	}

	k8sC, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return k8sC, nil
}

func (s *server) runK8sInitChecks(ctx context.Context) error {
	t := s.t

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	assert.Nil(t, k8sutils.WaitReadinessDeployment(ctx, s.k8sC, "octelium-nocturne"))
	assert.Nil(t, k8sutils.WaitReadinessDeployment(ctx, s.k8sC, "octelium-octovigil"))
	assert.Nil(t, k8sutils.WaitReadinessDeployment(ctx, s.k8sC, "octelium-ingress"))
	assert.Nil(t, k8sutils.WaitReadinessDeployment(ctx, s.k8sC, "octelium-rscserver"))
	assert.Nil(t, k8sutils.WaitReadinessDeployment(ctx, s.k8sC, "octelium-ingress-dataplane"))

	assert.Nil(t, k8sutils.WaitReadinessDaemonsetWithNS(ctx, s.k8sC, "octelium-gwagent", vutils.K8sNS))

	return nil
}

func getFileSha256(pth string) ([]byte, error) {
	f, err := os.Open(pth)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
