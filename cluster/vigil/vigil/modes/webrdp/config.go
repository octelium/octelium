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

package webrdp

import (
	"context"

	"github.com/octelium/octelium/cluster/vigil/vigil/modes/rdp"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (s *Server) getInjectedCredential(ctx context.Context) (*rdp.Credential, error) {
	svc := s.vCache.GetService()
	if svc == nil {
		return nil, errors.Errorf("could not get Service from vcache")
	}

	zap.L().Debug("Getting injected credential for service", zap.Any("svc", svc))

	return rdp.GetInjectedCredential(ctx, s.secretMan, svc.Spec.Config)
}

func (s *Server) getUpstreamTLSTrust() (*rdp.TLSTrustPolicy, error) {
	svc := s.vCache.GetService()
	if svc == nil {
		return nil, errors.Errorf("could not get Service from vcache")
	}

	return rdp.GetUpstreamTLSTrust(svc.Spec.Config)
}
