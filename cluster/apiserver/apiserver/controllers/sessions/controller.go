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

package conncontroller

import (
	"context"

	"slices"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

type Controller struct {
	octeliumC octeliumc.ClientInterface
	ctlI      CtlI
}

func NewController(octeliumC octeliumc.ClientInterface, ctlI CtlI) *Controller {
	return &Controller{
		octeliumC: octeliumC,
		ctlI:      ctlI,
	}
}

type CtlI interface {
	SendMessage(msg *userv1.ConnectResponse, sessUID string) error
}

func (c *Controller) OnAdd(ctx context.Context, sess *corev1.Session) error {
	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Session) error {
	if new.Status.Type != corev1.Session_Status_CLIENT {
		return nil
	}

	if !new.Status.IsConnected && old.Status.IsConnected {
		if err := c.sendDisconnect(new); err != nil {
			zap.L().Warn("Could not sendDisconnect", zap.Error(err))
		}
	}

	if err := c.checkSessionHostedSvc(ctx, new, old); err != nil {
		return err
	}

	return nil
}

func (c *Controller) checkSessionHostedSvc(ctx context.Context, new, old *corev1.Session) error {

	if pbutils.IsEqual(new.Status, old.Status) {
		return nil
	}

	newConn := new.Status.Connection
	oldConn := old.Status.Connection

	if pbutils.IsEqual(newConn, oldConn) {
		return nil
	}
	if newConn == nil || oldConn == nil {
		return nil
	}

	if pbutils.IsEqual(&corev1.Session_Status_Connection{
		Upstreams: newConn.Upstreams,
	}, &corev1.Session_Status_Connection{
		Upstreams: oldConn.Upstreams,
	}) {
		return nil
	}

	var added []*corev1.Session_Status_Connection_Upstream
	var updated []*corev1.Session_Status_Connection_Upstream
	var deleted []*corev1.Session_Status_Connection_Upstream

	for _, itm := range oldConn.Upstreams {
		if slices.IndexFunc(newConn.Upstreams, func(s *corev1.Session_Status_Connection_Upstream) bool {
			return s.ServiceRef.Uid == itm.ServiceRef.Uid
		}) == -1 {
			deleted = append(deleted, itm)
		}
	}

	for _, itm := range newConn.Upstreams {
		if slices.IndexFunc(oldConn.Upstreams, func(s *corev1.Session_Status_Connection_Upstream) bool {
			return s.ServiceRef.Uid == itm.ServiceRef.Uid
		}) == -1 {
			added = append(added, itm)
		}
	}

	for _, itm := range oldConn.Upstreams {
		idx := slices.IndexFunc(newConn.Upstreams, func(s *corev1.Session_Status_Connection_Upstream) bool {
			return s.ServiceRef.Uid == itm.ServiceRef.Uid && !pbutils.IsEqual(itm, s)
		})

		if idx >= 0 {
			updated = append(updated, newConn.Upstreams[idx])
		}
	}

	for _, svc := range added {
		zap.L().Debug("Sending addService msg to connected Session",
			zap.String("sessionName", new.Metadata.Name),
			zap.String("svcUID", svc.NamespaceRef.Uid))
		if err := c.ctlI.SendMessage(&userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_AddService_{
				AddService: &userv1.ConnectResponse_AddService{
					Service: upstream.GetHostServicesFromUpstream(svc, new),
				},
			},
		}, new.Metadata.Uid); err != nil {
			zap.L().Warn("Could not send addService msg", zap.Error(err))
		}
	}

	for _, svc := range updated {
		zap.L().Debug("Sending updateService msg to connected Session",
			zap.String("sessionName", new.Metadata.Name),
			zap.String("svcUID", svc.NamespaceRef.Uid))
		if err := c.ctlI.SendMessage(&userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_UpdateService_{
				UpdateService: &userv1.ConnectResponse_UpdateService{
					Service: upstream.GetHostServicesFromUpstream(svc, new),
				},
			},
		}, new.Metadata.Uid); err != nil {
			zap.L().Warn("Could not send updateService msg", zap.Error(err))
		}
	}

	for _, svc := range deleted {
		zap.L().Debug("Sending deleteService msg to connected Session",
			zap.String("sessionName", new.Metadata.Name),
			zap.String("svcUID", svc.NamespaceRef.Uid))
		if err := c.ctlI.SendMessage(&userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_DeleteService_{
				DeleteService: &userv1.ConnectResponse_DeleteService{
					Name: svc.ServiceRef.Name,
					// Namespace: svc.NamespaceRef.Name,
				},
			},
		}, new.Metadata.Uid); err != nil {
			zap.L().Warn("Could not send deleteService msg", zap.Error(err))
		}
	}

	return nil
}

func (c *Controller) OnDelete(ctx context.Context, sess *corev1.Session) error {
	if sess.Status.Type != corev1.Session_Status_CLIENT {
		return nil
	}

	if sess.Status.Connection == nil {
		return nil
	}

	return c.doDelete(ctx, sess)
}

func (c *Controller) doDelete(ctx context.Context, sess *corev1.Session) error {
	if sess.Status.Connection == nil {
		return nil
	}

	return c.sendDisconnect(sess)
}

func (c *Controller) sendDisconnect(sess *corev1.Session) error {
	zap.L().Debug("Sending doDisconnect msg to connected Session", zap.String("sessName", sess.Metadata.Name))
	return c.ctlI.SendMessage(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_Disconnect_{
			Disconnect: &userv1.ConnectResponse_Disconnect{},
		},
	}, sess.Metadata.Uid)
}
