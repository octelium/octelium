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
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type Controller struct {
	octeliumC octeliumc.ClientInterface
	ctlI      CtlI
}

const ns = "octelium"

type CtlI interface {
	BroadcastMessage(msg *userv1.ConnectResponse) error
	SendMessage(msg *userv1.ConnectResponse, sessUID string) error
}

func NewController(octeliumC octeliumc.ClientInterface, ctlI CtlI) *Controller {
	return &Controller{
		octeliumC: octeliumC,
		ctlI:      ctlI,
	}
}

func (c *Controller) OnAdd(ctx context.Context, svc *corev1.Service) error {

	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, newSvc, oldSvc *corev1.Service) error {

	if newSvc.Metadata.Name == "dns.octelium" {
		if !proto.Equal(&corev1.Service_Status{
			Addresses: newSvc.Status.Addresses,
		}, &corev1.Service_Status{
			Addresses: oldSvc.Status.Addresses,
		}) {
			zap.L().Debug("Broadcasting DNS Service addresses after change...")
			if err := c.setDNSState(newSvc); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Controller) OnDelete(ctx context.Context, svc *corev1.Service) error {

	return nil
}
