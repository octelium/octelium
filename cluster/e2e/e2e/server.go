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
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/user"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
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
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.uber.org/zap"
	"golang.org/x/net/html"
	"golang.org/x/oauth2/clientcredentials"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type server struct {
	domain         string
	homedir        string
	t              *CustomT
	k8sC           kubernetes.Interface
	externalIP     string
	createdAt      time.Time
	installedAt    time.Time
	kubeConfigPath string
}

func initServer(ctx context.Context) (*server, error) {

	ret := &server{
		domain:         "localhost",
		t:              &CustomT{},
		createdAt:      time.Now(),
		kubeConfigPath: "/etc/rancher/k3s/k3s.yaml",
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
	s.installedAt = time.Now()

	assert.Nil(t, s.installClusterCert(ctx))

	{
		cmd := s.getCmd(ctx,
			`ip addr show $(ip route show default | ip route show default | awk '/default/ {print $5}') | grep "inet " | awk '{print $2}' | cut -d'/' -f1`)
		out, err := cmd.CombinedOutput()
		assert.Nil(t, err)
		s.externalIP = strings.TrimSpace(string(out))
		zap.L().Debug("The VM IP addr", zap.String("addr", s.externalIP))
	}

	{
		os.Setenv("OCTELIUM_DOMAIN", s.domain)

		os.Unsetenv("OCTELIUM_INSECURE_TLS")
		os.Setenv("OCTELIUM_INSECURE_TLS", "false")
		os.Setenv("OCTELIUM_PRODUCTION", "true")
		os.Setenv("HOME", s.homedir)
		os.Setenv("KUBECONFIG", s.kubeConfigPath)
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
		k8sC, err := s.getK8sC()
		if err != nil {
			return err
		}
		s.k8sC = k8sC

		assert.Nil(t, s.runK8sInitChecks(ctx))
	}

	{

		/*
			s.startKubectlLog(ctx, "-l octelium.com/svc=dns.octelium -c managed")
			s.startKubectlLog(ctx, "-l octelium.com/component=nocturne")
			s.startKubectlLog(ctx, "-l octelium.com/component=gwagent")
			s.startKubectlLog(ctx, "-l octelium.com/component=rscserver")
			s.startKubectlLog(ctx, "-l octelium.com/component=octovigil")
		*/
		s.startKubectlLog(ctx, "-l octelium.com/component=collector")

		assert.Nil(t, s.runCmd(ctx, "kubectl get pods -A"))
		assert.Nil(t, s.runCmd(ctx, "kubectl get deployment -A"))
		assert.Nil(t, s.runCmd(ctx, "kubectl get svc -A"))
		assert.Nil(t, s.runCmd(ctx, "kubectl get daemonset -A"))

		assert.Nil(t, s.waitDeploymentSvc(ctx, "demo-nginx"))
		assert.Nil(t, s.waitDeploymentSvc(ctx, "portal"))
		assert.Nil(t, s.waitDeploymentSvc(ctx, "default"))
	}

	{
		assert.Nil(t, s.runCmd(ctx, "octelium version"))
		assert.Nil(t, s.runCmd(ctx, "octelium version -o json"))
		assert.Nil(t, s.runCmd(ctx, "octeliumctl version"))
		assert.Nil(t, s.runCmd(ctx, "octelium status"))

		assert.Nil(t, s.runCmd(ctx, "octeliumctl get rgn default"))
		assert.Nil(t, s.runCmd(ctx, "octeliumctl get gw -o yaml"))
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

	if err := s.runOcteliumConnectQUIC(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlAccessToken(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlOAuth2CC(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlAuthToken(ctx); err != nil {
		return err
	}

	if err := s.checkComponents(ctx); err != nil {
		return err
	}

	/*
		if err := s.runOcteliumContainer(ctx); err != nil {
			return err
		}
	*/

	zap.L().Debug("Test done", zap.Duration("duration", time.Since(s.createdAt)))

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

			for _, svc := range itmList.Items {
				assert.NotNil(t, svc.Status.RegionRef)
				assert.NotNil(t, svc.Status.NamespaceRef)
				assert.True(t, len(svc.Status.Addresses) > 0)
				assert.True(t, svc.Status.Port > 0)
			}
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
	return resty.New().SetRetryCount(20).SetRetryWaitTime(500 * time.Millisecond).SetRetryMaxWaitTime(2 * time.Second).
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
	if err := cliutils.OpenDB(""); err != nil {
		return err
	}
	defer cliutils.CloseDB()

	conn, err := client.GetGRPCClientConn(ctx, s.domain)
	assert.Nil(t, err)
	defer conn.Close()

	coreC := corev1.NewMainServiceClient(conn)
	{
		_, err = coreC.ListService(ctx, &corev1.ListServiceOptions{})
		assert.Nil(t, err)
	}

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
				"-p clickhouse:15013",
				"-p ollama:15014",
				"-p mongo:15015",
				"--essh",
				"--serve-all",
			})
			assert.Nil(t, err)

			{
				assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "nginx"))
				res, err := s.httpC().R().Get("http://localhost:15001")
				assert.Nil(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode())

				_, err = html.Parse(strings.NewReader(string(res.Body())))
				assert.Nil(t, err)
			}

			/*
				{
					svc, err := coreC.GetService(ctx, &metav1.GetOptions{
						Name: "nginx.default",
					})
					assert.Nil(t, err)

					assert.Equal(t, 80, svc.Status.Port)

					svc.Spec.Port = 9999

					svc, err = coreC.UpdateService(ctx, svc)
					assert.Nil(t, err)

					assert.Equal(t, 9999, svc.Status.Port)

					time.Sleep(1 * time.Second)

					for range 10 {
						res, err := s.httpC().R().Get("http://localhost:15001")
						assert.Nil(t, err)
						assert.Equal(t, http.StatusOK, res.StatusCode())

						_, err = html.Parse(strings.NewReader(string(res.Body())))
						assert.Nil(t, err)
						time.Sleep(1 * time.Second)
					}
				}
			*/

			{
				res, err := s.httpC().R().Get("http://localhost:15002")
				assert.Nil(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode())

				_, err = html.Parse(strings.NewReader(string(res.Body())))
				assert.Nil(t, err)
			}

			{
				db, err := connectWithRetry("postgres",
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
				db, err := sql.Open("postgres",
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

				db, err := connectWithRetry("postgres",
					postgresutils.GetPostgresURLFromArgs(&postgresutils.PostgresDBArgs{
						Host:     "localhost",
						NoSSL:    true,
						Username: "postgres",
						Password: "password",
						Port:     15005,
					}))
				assert.Nil(t, err)

				defer db.Close()

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
					fmt.Sprintf(`ssh -p 15004 %s@localhost 'echo hello world'`, res.Session.Metadata.Name)))
			}

			{
				assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "redis"))
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

				{
					assert.Nil(t, redisC.Set(ctx,
						utilrand.GetRandomStringCanonical(32),
						utilrand.GetRandomStringCanonical(12*1024*1024), 3*time.Second).Err())
				}
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
				assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "nats"))
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
				assert.Equal(t, input, textContent.Text)
			}

			{
				assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "opensearch"))
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

				idx := "octelium-index"
				_, err = c.Indices.Create(idx)
				assert.Nil(t, err)

				type myDoc struct {
					ID    int    `json:"id"`
					Name  string `json:"name"`
					Price int    `json:"price"`
				}

				for range 50 {
					doc := &myDoc{
						ID:    utilrand.GetRandomRangeMath(1, math.MaxInt32),
						Name:  utilrand.GetRandomString(10 * 1000),
						Price: utilrand.GetRandomRangeMath(1, 4000),
					}

					docJSON, _ := json.Marshal(doc)

					_, err = c.Index(
						idx,
						bytes.NewReader(docJSON),
						c.Index.WithContext(ctx),
					)
					assert.Nil(t, err)
				}

				assert.Nil(t, s.runCmd(ctx, "octeliumctl del svc opensearch"))
			}
			{
				assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "clickhouse"))
				assert.Nil(t, s.waitDeploymentSvc(ctx, "clickhouse"))
				conn := clickhouse.OpenDB(&clickhouse.Options{
					Addr: []string{"localhost:15013"},
					Auth: clickhouse.Auth{
						Username: "octelium",
						Password: "password",
					},
				})

				assert.Nil(t, conn.Ping())

				conn.Exec(`DROP TABLE IF EXISTS example`)
				_, err = conn.Exec(`CREATE TABLE IF NOT EXISTS example (Col1 UInt8, Col2 String) engine=Memory`)
				assert.Nil(t, err)

				arg := utilrand.GetRandomString(32)
				_, err = conn.Exec(fmt.Sprintf("INSERT INTO example VALUES (1, '%s')", arg))
				assert.Nil(t, err)

				row := conn.QueryRow("SELECT * FROM example")
				var col1 uint8
				var col2 string
				assert.Nil(t, row.Scan(&col1, &col2))
				assert.Equal(t, int(col1), 1)
				assert.Equal(t, arg, col2)

				assert.Nil(t, s.runCmd(ctx, "octeliumctl del svc clickhouse"))
				assert.NotNil(t, s.runCmd(ctx, "octeliumctl del svc clickhouse"))
			}

			{
				assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "mariadb"))
				assert.Nil(t, s.waitDeploymentSvc(ctx, "mariadb"))

				db, err := connectWithRetry("mysql", "root:@tcp(localhost:15009)/mysql")
				assert.Nil(t, err)
				defer db.Close()

				_, err = db.Exec("CREATE DATABASE IF NOT EXISTS mydb")
				assert.Nil(t, err)

				_, err = db.Query("SHOW DATABASES")
				assert.Nil(t, err)

				/*
					defer rows.Close()

					for rows.Next() {
						var name string
						assert.Nil(t, rows.Scan(&name))
					}

					assert.Nil(t, rows.Err())
				*/
				assert.Nil(t, s.runCmd(ctx, "octeliumctl del svc mariadb"))
			}

			{
				tmpDir, err := os.MkdirTemp("/tmp", "octelium-*")
				assert.Nil(t, err)
				defer os.RemoveAll(tmpDir)

				assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "minio"))
				assert.Nil(t, s.waitDeploymentSvc(ctx, "minio"))
				s.logServiceUpstream(ctx, "minio")
				// s.logVigil(ctx, "minio")

				c, err := minio.New("localhost:15010", &minio.Options{
					Creds:  credentials.NewStaticV4("wrong", "identity", ""),
					Secure: false,
					Region: "us-east-1",
				})
				assert.Nil(t, err)

				// c.TraceOn(os.Stderr)

				bucketName := utilrand.GetRandomStringCanonical(6)

				err = c.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{Region: "us-east-1"})
				assert.Nil(t, err)

				zap.L().Debug("Successfully created bucket", zap.String("bucket", bucketName))

				doFn := func(pth string) {

					name := utilrand.GetRandomStringCanonical(8)
					downloadPath := path.Join(tmpDir, name)
					info, err := c.FPutObject(ctx,
						bucketName, name, pth, minio.PutObjectOptions{
							ContentType: "application/octet-stream",
						})
					assert.Nil(t, err)

					zap.L().Debug("fputObject", zap.String("path", pth), zap.Any("info", info))

					stat, err := c.StatObject(ctx, bucketName, name, minio.StatObjectOptions{})
					assert.Nil(t, err)

					zap.L().Debug("object stat", zap.String("path", pth), zap.Any("info", stat))

					err = c.FGetObject(ctx,
						bucketName, name, downloadPath, minio.GetObjectOptions{})
					assert.Nil(t, err)

					zap.L().Debug("fgetObject done", zap.String("path", pth))

					/*
						f1, s1, err := calculateSHA256(pth)
						assert.Nil(t, err)

						f2, s2, err := calculateSHA256(downloadPath)
						assert.Nil(t, err)

						assert.Equal(t, f1, f2)
						assert.Equal(t, s1, s2)
					*/

				}

				files := []string{
					s.kubeConfigPath,
					"/usr/local/bin/octeliumctl",
					"/usr/local/bin/octops",
				}

				for _, f := range files {
					doFn(f)
				}

				assert.Nil(t, s.runCmd(ctx, "octeliumctl del svc minio"))
				assert.NotNil(t, s.runCmd(ctx, "octeliumctl del svc minio"))
			}

			{
				uri := "mongodb://octelium:password@localhost:15015"

				type mongoUser struct {
					Name      string    `bson:"name"`
					Email     string    `bson:"email"`
					Age       int       `bson:"age"`
					CreatedAt time.Time `bson:"created_at"`
				}

				client, err := mongo.Connect(options.Client().ApplyURI(uri))
				assert.Nil(t, err)

				assert.Nil(t, client.Ping(ctx, nil))

				collection := client.Database("testdb").Collection("users")

				usr := &mongoUser{
					Name:      utilrand.GetRandomStringCanonical(8),
					Email:     fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
					CreatedAt: time.Now(),
					Age:       21,
				}
				_, err = collection.InsertOne(ctx, usr)
				assert.Nil(t, err)

				var foundUser mongoUser
				err = collection.FindOne(ctx, bson.M{
					"email": usr.Email,
				}).Decode(&foundUser)
				assert.Nil(t, err)

				assert.Equal(t, usr.Name, foundUser.Name)
				assert.Equal(t, usr.Email, foundUser.Email)
				assert.Equal(t, usr.Age, foundUser.Age)

				assert.Nil(t, client.Disconnect(ctx))
			}
			{
				assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "ollama"))
				assert.Nil(t, s.waitDeploymentSvc(ctx, "ollama"))
				s.execServiceUpstream(ctx, "ollama", "ollama run qwen3:0.6b")

				time.Sleep(5 * time.Second)

				c := openai.NewClient(
					option.WithBaseURL("http://localhost:15014/v1"),
					option.WithMaxRetries(20),
				)

				{
					started := time.Now()
					_, err := c.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
						Messages: []openai.ChatCompletionMessageParamUnion{
							openai.UserMessage("What is zero trust?"),
						},
						Model: "qwen3:0.6b",
					})
					assert.Nil(t, err)

					zap.L().Debug("Chat completion output",
						zap.Duration("duration", time.Since(started)))
				}

				{

					started := time.Now()

					stream := c.Chat.Completions.NewStreaming(ctx, openai.ChatCompletionNewParams{
						Messages: []openai.ChatCompletionMessageParamUnion{
							openai.UserMessage("What are the largest cities in the world?"),
						},
						Model: "qwen3:0.6b",
					})

					acc := openai.ChatCompletionAccumulator{}

					count := 0
					totalLen := 0
					for stream.Next() {
						chunk := stream.Current()
						acc.AddChunk(chunk)

						if len(chunk.Choices) > 0 {
							count++
							totalLen += len(chunk.Choices[0].Delta.Content)
						}
					}

					zap.L().Debug("Total openAI chat completion streaming chunks",
						zap.Int("count", count), zap.Int("totalLen", totalLen),
						zap.Duration("duration", time.Since(started)))
					assert.Nil(t, stream.Err())
					assert.True(t, count > 10)

					zap.L().Debug("Complete answer", zap.String("val", acc.Choices[0].Message.Content))
				}

				assert.Nil(t, s.runCmd(ctx, "octeliumctl del svc ollama"))
			}

			assert.Nil(t, s.runCmd(ctx, "octelium disconnect"))

			connCmd.Wait()

			zap.L().Debug("octelium connect exited")
		}
	}

	return nil
}

func (s *server) runOcteliumConnectQUIC(ctx context.Context) error {
	t := s.t

	connCmd, err := s.startOcteliumConnectRootless(ctx, []string{
		"--tunnel-mode quicv0",
		"-p nginx:15001",
	})
	assert.Nil(t, err)

	time.Sleep(2 * time.Second)

	{
		assert.Nil(t, s.waitDeploymentSvcUpstream(ctx, "nginx"))
		res, err := s.httpC().R().Get("http://localhost:15001")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode())

		_, err = html.Parse(strings.NewReader(string(res.Body())))
		assert.Nil(t, err)
	}

	assert.Nil(t, s.runCmd(ctx, "octelium disconnect"))
	connCmd.Wait()

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

func (s *server) runOcteliumctlOAuth2CC(ctx context.Context) error {
	t := s.t

	out, err := s.getCmd(ctx,
		"octeliumctl create cred --user root --policy allow-all --type oauth2 -o json").CombinedOutput()
	assert.Nil(t, err)

	res := &corev1.CredentialToken{}

	zap.L().Debug("Command out", zap.String("out", string(out)))

	err = pbutils.UnmarshalJSON(out, res)
	assert.Nil(t, err)

	{

		conf := &clientcredentials.Config{
			ClientID:     res.GetOauth2Credentials().ClientID,
			ClientSecret: res.GetOauth2Credentials().ClientSecret,
			TokenURL:     fmt.Sprintf("https://%s/oauth2/token", s.domain),
		}

		tkn, err := conf.Token(ctx)
		assert.Nil(t, err)

		s.httpCPublicAccessTokenCheck("demo-nginx", tkn.AccessToken)
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
		assert.Nil(t, err)
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

func (s *server) runOcteliumContainer(ctx context.Context) error {
	t := s.t

	out, err := s.getCmd(ctx,
		"octeliumctl create cred --user root --policy allow-all -o json").CombinedOutput()
	assert.Nil(t, err)

	res := &corev1.CredentialToken{}

	zap.L().Debug("Command out", zap.String("out", string(out)))

	err = pbutils.UnmarshalJSON(out, res)
	assert.Nil(t, err)

	{
		cmd := s.getCmd(ctx,
			fmt.Sprintf(
				"docker run --net host ghcr.io/octelium/octelium:main connect --domain %s --auth-token %s -p nginx:17001",
				s.domain,
				res.GetAuthenticationToken().AuthenticationToken))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		assert.Nil(t, cmd.Start())

		time.Sleep(5 * time.Second)

		res, err := s.httpC().R().Get("http://localhost:17001")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode())
		cmd.Process.Kill()
		time.Sleep(2 * time.Second)
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

func (s *server) getK8sC() (kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", s.kubeConfigPath)
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

	assert.Nil(t, s.waitDeploymentComponent(ctx, "nocturne"))
	assert.Nil(t, s.waitDeploymentComponent(ctx, "octovigil"))
	assert.Nil(t, s.waitDeploymentComponent(ctx, "ingress"))
	assert.Nil(t, s.waitDeploymentComponent(ctx, "rscserver"))
	assert.Nil(t, s.waitDeploymentComponent(ctx, "ingress-dataplane"))

	assert.Nil(t, k8sutils.WaitReadinessDaemonsetWithNS(ctx, s.k8sC, "octelium-gwagent", vutils.K8sNS))

	return nil
}

func (s *server) waitDeploymentComponent(ctx context.Context, name string) error {
	return k8sutils.WaitReadinessDeployment(ctx, s.k8sC, fmt.Sprintf("octelium-%s", name))
}

func (s *server) waitDeploymentSvc(ctx context.Context, name string) error {
	return k8sutils.WaitReadinessDeployment(ctx, s.k8sC, k8sutils.GetSvcHostname(&corev1.Service{
		Metadata: &metav1.Metadata{
			Name: vutils.GetServiceFullNameFromName(name),
		},
	}))
}

func (s *server) waitDeploymentSvcUpstream(ctx context.Context, name string) error {
	return k8sutils.WaitReadinessDeployment(ctx, s.k8sC, k8sutils.GetSvcK8sUpstreamHostname(&corev1.Service{
		Metadata: &metav1.Metadata{
			Name: vutils.GetServiceFullNameFromName(name),
		},
	}, ""))
}

func (s *server) execServiceUpstream(ctx context.Context, svc string, cmd string) error {
	return s.runCmd(ctx,
		fmt.Sprintf(
			`kubectl exec -n octelium -it $(kubectl get pod -n octelium -l octelium.com/svc=%s,octelium.com/component=svc-k8s-upstream -o jsonpath='{.items[0].metadata.name}') -- %s`,
			vutils.GetServiceFullNameFromName(svc), cmd))
}

func (s *server) logServiceUpstream(ctx context.Context, svc string) error {
	cmdStr := fmt.Sprintf(
		`kubectl logs -f -n octelium -l octelium.com/component=svc-k8s-upstream,octelium.com/svc=%s`,
		vutils.GetServiceFullNameFromName(svc))

	cmd := s.getCmd(ctx, cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Start()
}

func (s *server) logVigil(ctx context.Context, svc string) error {
	cmdStr := fmt.Sprintf(
		`kubectl logs -f -n octelium -l octelium.com/component=svc,octelium.com/svc=%s`,
		vutils.GetServiceFullNameFromName(svc))

	cmd := s.getCmd(ctx, cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Start()
}

func calculateSHA256(filePath string) (string, int64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	written, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), written, nil
}

func connectWithRetry(driverName, dsn string) (*sql.DB, error) {
	var db *sql.DB
	var err error

	maxRetries := 30

	for attempt := 1; ; attempt++ {
		db, err = sql.Open(driverName, dsn)
		if err == nil {
			err = db.Ping()
			if err == nil {
				return db, nil
			}
		}

		if maxRetries > 0 && attempt >= maxRetries {
			break
		}

		zap.L().Debug("Retrying connection to db", zap.String("dsn", dsn), zap.Error(err))
		time.Sleep(1 * time.Second)
	}

	return nil, fmt.Errorf("could not connect to database: %w", err)
}

func getFileSize(pth string) int64 {

	fileInfo, err := os.Stat(pth)
	if err != nil {
		return 0
	}
	return fileInfo.Size()

}

func (s *server) listComponentPods(ctx context.Context, name string) (*k8scorev1.PodList, error) {
	return s.k8sC.CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{
		LabelSelector: fmt.Sprintf("octelium.com/component=%s", name),
	})
}

func (s *server) getComponentPod(ctx context.Context, name string) (*k8scorev1.Pod, error) {
	podList, err := s.listComponentPods(ctx, name)
	if err != nil {
		return nil, err
	}

	if len(podList.Items) < 1 {
		return nil, errors.Errorf("No pods")
	}

	return &podList.Items[0], nil
}

func (s *server) checkComponentRestarts(ctx context.Context, name string) error {

	pod, err := s.getComponentPod(ctx, name)
	if err != nil {
		return err
	}

	totalRestarts := 0
	for _, cs := range pod.Status.ContainerStatuses {
		totalRestarts += int(cs.RestartCount)
	}

	assert.Zero(s.t, totalRestarts)

	return nil
}

func (s *server) checkComponents(ctx context.Context) error {

	t := s.t

	components := []string{
		"ingress",
		"ingress-dataplane",
		"nocturne",
		"rscserver",
		"octovigil",
		"gwagent",
	}

	zap.L().Debug("Starting checking components",
		zap.Duration("installedSince", time.Since(s.installedAt)))

	for _, comp := range components {
		assert.Nil(t, s.checkComponentRestarts(ctx, comp))
	}

	return nil
}

func (s *server) installClusterCert(ctx context.Context) error {

	t := s.t

	domain := s.domain
	sans := []string{
		domain,
		fmt.Sprintf("*.%s", domain),

		fmt.Sprintf("*.octelium.%s", domain),
		fmt.Sprintf("*.octelium-api.%s", domain),

		fmt.Sprintf("*.local.%s", domain),
		fmt.Sprintf("*.default.%s", domain),
		fmt.Sprintf("*.default.local.%s", domain),

		fmt.Sprintf("*.octelium.local.%s", domain),
		fmt.Sprintf("*.octelium-api.local.%s", domain),
	}

	zap.L().Debug("Setting initial Cluster Certificate",
		zap.String("domain", domain),
		zap.Strings("sans", sans))

	initCrt, err := utils_cert.GenerateSelfSignedCert(domain, sans, 4*12*30*24*time.Hour)
	if err != nil {
		return err
	}

	crtPEM, err := initCrt.GetCertPEM()
	assert.Nil(t, err)

	privPEM, err := initCrt.GetPrivateKeyPEM()
	assert.Nil(t, err)

	keyPath := "/tmp/octelium-private-key.pem"
	certPath := "/tmp/octelium-cert.pem"

	assert.Nil(t, os.WriteFile(keyPath, []byte(privPEM), 0644))
	assert.Nil(t, os.WriteFile(certPath, []byte(crtPEM), 0644))

	if err := s.runCmd(ctx,
		fmt.Sprintf("sudo cp %s /usr/local/share/ca-certificates/octelium-cluster.crt", certPath)); err != nil {
		return err
	}

	if err := s.runCmd(ctx, "sudo update-ca-certificates"); err != nil {
		return err
	}

	cmdStr := fmt.Sprintf(`octops cert %s --key %s --cert %s --kubeconfig %s`,
		s.domain, keyPath, certPath, s.kubeConfigPath)
	if err := s.runCmd(ctx, cmdStr); err != nil {
		return err
	}

	return nil
}
