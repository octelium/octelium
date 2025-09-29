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
	"os"
	"os/signal"

	"github.com/octelium/octelium/cluster/common/octeliumc"
)

type server struct {
	domain string

	octeliumC octeliumc.ClientInterface
}

func initServer(ctx context.Context) (*server, error) {

	ret := &server{
		domain: "localhost",
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
	}

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

	return nil
}
