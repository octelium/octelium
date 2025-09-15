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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (c *Controller) handleAdd(ctx context.Context, svc *corev1.Service) error {

	svc, err := c.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	if err != nil {
		return errors.Errorf("Could not get Service: %+v", err)
	}

	conns, err := upstream.SetServiceUpstreams(ctx, c.octeliumC, svc)
	if err != nil {
		return errors.Errorf("Could not set service upstreams: %+v", err)
	}

	/*
		_, err = c.octeliumC.CoreC().UpdateService(ctx, svc)
		if err != nil {
			return errors.Errorf("Could not update service: %+v", err)
		}
	*/

	for _, conn := range conns {
		_, err := c.octeliumC.CoreC().UpdateSession(ctx, conn)
		if err != nil {
			return errors.Errorf("Could not update conn %s upstreams after svc %s add", conn.Metadata.Name, svc.Metadata.Name)
		}
	}

	return nil
}

func (c *Controller) handleUpdateSession(ctx context.Context, svc *corev1.Service) error {

	svc, err := c.octeliumC.CoreC().GetService(ctx,
		&rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil
		}
		return err
	}

	sessL, err := upstream.SetServiceUpstreams(ctx, c.octeliumC, svc)
	if err != nil {
		return err
	}

	for _, sess := range sessL {
		_, err := c.octeliumC.CoreC().UpdateSession(ctx, sess)
		if err != nil {
			return errors.Errorf("Could not update Session %s upstreams after svc %s add", sess.Metadata.Name, svc.Metadata.Name)
		}
	}

	/*
		_, err = c.octeliumC.CoreC().UpdateService(ctx, svc)
		if err != nil {
			zap.S().Errorf("Could not update service: %+v", err)
			return err
		}
	*/

	return nil
}

func (c *Controller) handleDelete(ctx context.Context, n *corev1.Service) error {

	hostConns, err := upstream.GetServiceHostConns(ctx, c.octeliumC, n)
	if err != nil {
		return err
	}

	for _, uConn := range hostConns {

		sess, err := c.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uConn.Metadata.Uid})
		if err != nil {
			zap.S().Errorf("Could not get Session %s upstreams after svc %s delete", sess.Metadata.Name, n.Metadata.Name)
			return err
		}

		if err := upstream.RemoveConnectionUpstreams(ctx, c.octeliumC, sess, n); err != nil {
			zap.S().Errorf("Could not remove upstreams for Session %s after svc %s delete", sess.Metadata.Name, n.Metadata.Name)
			return err
		}

		if _, err := c.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
			zap.S().Errorf("Could not update Session %s upstreams after svc %s delete", sess.Metadata.Name, n.Metadata.Name)
			return err
		}

	}

	return nil
}
