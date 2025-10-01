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
	"os/signal"
	"os/user"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
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
		os.Setenv("OCTELIUM_QUIC", "true")
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
		assert.Nil(t, s.runCmd(ctx, "octelium status"))
	}

	if err := s.runOcteliumctlEmbedded(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlCommands(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumConnectCommands(ctx); err != nil {
		return err
	}

	if err := s.runOcteliumctlAccessToken(ctx); err != nil {
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

	itmList, err := c.ListService(ctx, &corev1.ListServiceOptions{})
	assert.Nil(t, err)

	assert.True(t, len(itmList.Items) > 0)

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
	}

	return nil
}

func (s *server) runOcteliumctlCommands(ctx context.Context) error {
	t := s.t

	out, err := s.getCmd(ctx, "octeliumctl get svc -o json").CombinedOutput()
	assert.Nil(t, err)

	res := &corev1.ServiceList{}

	zap.L().Debug("Command out", zap.String("out", string(out)))

	err = pbutils.UnmarshalJSON(out, res)
	assert.Nil(t, err)

	assert.True(t, len(res.Items) > 0)

	return nil
}

func (s *server) runOcteliumctlAccessToken(ctx context.Context) error {
	t := s.t

	out, err := s.getCmd(ctx,
		"octeliumctl create cred --user root --policy allow-all --type access-token").CombinedOutput()
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

func (s *server) runOcteliumConnectCommands(ctx context.Context) error {
	t := s.t

	connCmd, err := s.startOcteliumConnectRootless(ctx, "-p demo-nginx:14041")
	assert.Nil(t, err)

	{
		res, err := resty.New().SetDebug(true).
			SetRetryCount(10).
			R().Get("http://localhost:14041")
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode())
	}

	{
		assert.Nil(t, s.runCmd(ctx, "octelium disconnect"))
	}

	connCmd.Wait()

	return nil
}

func Run() error {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(logger)

	ctx, cancelFn := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancelFn()

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
