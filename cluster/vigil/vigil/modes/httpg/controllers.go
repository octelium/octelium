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

package httpg

/*
import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

func (s *Server) onServiceUpdate(ctx context.Context, new, old *corev1.Service) error {
	if !pbutils.IsEqual(new.Spec.GetUpstream(), old.Spec.GetUpstream()) {
		if err := s.lbManager.Set(ctx, new); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) onSessionUpdate(ctx context.Context, new, old *corev1.Session) error {
	svc := s.svc()
	if pbutils.IsEqual(new.Status.Connection, old.Status.Connection) {
		return nil
	}

	zap.L().Debug("Starting onSessionUpdate")

	switch {
	case ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(new)):
		s.lbManager.SetUpstreamSession(svc, new)
	case !ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(new)) &&
		ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(old)):
		s.lbManager.UnsetUpstreamSession(svc, new)
	}

	return nil
}
*/
