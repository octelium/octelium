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
	"fmt"
	"os"
	"os/signal"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type server struct {
	domain    string
	octeliumC octeliumc.ClientInterface
	t         *CustomT
}

func initServer(ctx context.Context) (*server, error) {

	ret := &server{
		domain: "localhost",
		t:      &CustomT{},
	}

	return ret, nil
}

func (s *server) run(ctx context.Context) error {
	if err := s.installCluster(ctx); err != nil {
		return err
	}
	{
		os.Setenv("OCTELIUM_DOMAIN", s.domain)
		os.Setenv("OCTELIUM_INSECURE_TLS", "true")
		os.Setenv("OCTELIUM_QUIC", "true")
	}

	if err := s.runOcteliumctlEmbedded(ctx); err != nil {
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

	return nil
}

func Run() error {

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
