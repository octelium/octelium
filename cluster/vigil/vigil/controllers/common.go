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

package controllers

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
)

type ServiceController struct {
	FnOnAdd    func(ctx context.Context, svc *corev1.Service) error
	FnOnUpdate func(ctx context.Context, new, old *corev1.Service) error
	FnOnDelete func(ctx context.Context, svc *corev1.Service) error
}

func (c *ServiceController) OnAdd(ctx context.Context, svc *corev1.Service) error {
	if c.FnOnAdd != nil {
		return c.FnOnAdd(ctx, svc)
	}
	return nil
}

func (c *ServiceController) OnUpdate(ctx context.Context, new, old *corev1.Service) error {
	if c.FnOnUpdate != nil {
		return c.FnOnUpdate(ctx, new, old)
	}
	return nil
}

func (c *ServiceController) OnDelete(ctx context.Context, svc *corev1.Service) error {
	if c.FnOnDelete != nil {
		return c.FnOnDelete(ctx, svc)
	}

	return nil
}

type SessionController struct {
	FnOnAdd    func(ctx context.Context, svc *corev1.Session) error
	FnOnUpdate func(ctx context.Context, new, old *corev1.Session) error
	FnOnDelete func(ctx context.Context, svc *corev1.Session) error
}

func (c *SessionController) OnAdd(ctx context.Context, svc *corev1.Session) error {
	if c.FnOnAdd != nil {
		return c.FnOnAdd(ctx, svc)
	}
	return nil
}

func (c *SessionController) OnUpdate(ctx context.Context, new, old *corev1.Session) error {
	if c.FnOnUpdate != nil {
		return c.FnOnUpdate(ctx, new, old)
	}
	return nil
}

func (c *SessionController) OnDelete(ctx context.Context, svc *corev1.Session) error {
	if c.FnOnDelete != nil {
		return c.FnOnDelete(ctx, svc)
	}

	return nil
}
