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
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type server struct {
	domain  string
	homedir string
	t       *CustomT
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
	}
	{
		s.runCmd(ctx, "id")
	}
	{
		zap.L().Info("Env vars", zap.Strings("env", os.Environ()))
	}
	{
		out, err := s.getCmd(ctx, "octeliumctl version -o json").CombinedOutput()
		assert.Nil(t, err)
		zap.L().Info("octeliumctl version", zap.String("out", string(out)))
	}

	{
		s.startKubectlLog(ctx, "-l octelium.com/svc=dns.octelium -c managed")
		s.startKubectlLog(ctx, "-l octelium.com/component=nocturne")
		s.startKubectlLog(ctx, "-l octelium.com/component=gwagent")
		s.startKubectlLog(ctx, "-l octelium.com/component=rscserver")
	}

	{
		assert.Nil(t, s.runCmd(ctx, "octelium status"))
	}
	{
		res, err := resty.New().SetDebug(true).SetTLSClientConfig(&tls.Config{
			InsecureSkipVerify: true,
		}).
			SetRetryCount(10).
			R().
			Get("https://localhost")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode())
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
			Name: "dns.octelium",
		})
		assert.True(t, grpcerr.IsUnauthorized(err))

		_, err = c.DeleteService(ctx, &metav1.DeleteOptions{
			Name: "portal.default",
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

		res, err := resty.New().SetDebug(true).SetTLSClientConfig(&tls.Config{
			InsecureSkipVerify: true,
		}).
			SetRetryCount(10).
			R().SetAuthScheme("Bearer").
			SetAuthToken(res.GetAccessToken().AccessToken).
			Get("https://demo-nginx.localhost")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode())

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
			res, err := resty.New().SetDebug(true).
				SetRetryCount(10).
				R().Get("http://localhost:15001")
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
