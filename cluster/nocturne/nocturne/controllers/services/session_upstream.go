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

package svccontroller

import (
	"context"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
)

func (c *Controller) handleUpdateSessionUpstream(ctx context.Context, svc *corev1.Service) error {
	sessL, err := upstream.SetServiceUpstreams(ctx, c.octeliumC, svc)
	if err != nil {
		return err
	}

	for _, sess := range sessL {
		_, err := c.octeliumC.CoreC().UpdateSession(ctx, sess)
		if err != nil {
			if grpcerr.IsNotFound(err) {
				continue
			}

			zap.L().Warn("Could not updateSession after setting Connection upstream",
				zap.String("sess", sess.Metadata.Name), zap.String("svc", svc.Metadata.Name))
		}
	}

	return nil
}

func (c *Controller) handleDeleteSessionUpstream(ctx context.Context, svc *corev1.Service) error {

	hostConns, err := upstream.GetServiceHostConns(ctx, c.octeliumC, svc)
	if err != nil {
		return err
	}

	for _, uConn := range hostConns {
	doDelUpstream:
		sess, err := c.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uConn.Metadata.Uid})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				continue
			}
			zap.L().Warn("Could not get Session to update upstreams after Service deletion",
				zap.String("sess", sess.Metadata.Name), zap.String("svc", svc.Metadata.Name))
			return err
		}

		if err := upstream.RemoveConnectionUpstreams(ctx, c.octeliumC, sess, svc); err != nil {
			zap.L().Warn("Could not remove Session upstreams after Service deletion",
				zap.String("sess", sess.Metadata.Name), zap.String("svc", svc.Metadata.Name))
			return err
		}

		if _, err := c.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
			switch {
			case grpcerr.IsNotFound(err):
			case grpcerr.IsResourceChanged(err):
				time.Sleep(100 * time.Millisecond)
				goto doDelUpstream
			default:
				zap.L().Warn("Could not update Session after removing upstreams on Service deletion",
					zap.String("sess", sess.Metadata.Name), zap.String("svc", svc.Metadata.Name))
			}
		}

	}

	return nil
}
