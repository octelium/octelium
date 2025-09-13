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

package watchers

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
)

type CoreV1Watcher struct {
	octeliumC octeliumc.ClientInterface
}

func NewCoreV1(octeliumC octeliumc.ClientInterface) *CoreV1Watcher {
	return &CoreV1Watcher{
		octeliumC: octeliumC,
	}
}

func (c *CoreV1Watcher) Service(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Service) error,
	onUpdate func(ctx context.Context, new, old *corev1.Service) error,
	onDelete func(ctx context.Context, item *corev1.Service) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindService, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Namespace(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Namespace) error,
	onUpdate func(ctx context.Context, new, old *corev1.Namespace) error,
	onDelete func(ctx context.Context, item *corev1.Namespace) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindNamespace, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Secret(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Secret) error,
	onUpdate func(ctx context.Context, new, old *corev1.Secret) error,
	onDelete func(ctx context.Context, item *corev1.Secret) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindSecret, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) User(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.User) error,
	onUpdate func(ctx context.Context, new, old *corev1.User) error,
	onDelete func(ctx context.Context, item *corev1.User) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindUser, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Policy(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Policy) error,
	onUpdate func(ctx context.Context, new, old *corev1.Policy) error,
	onDelete func(ctx context.Context, item *corev1.Policy) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindPolicy, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Group(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Group) error,
	onUpdate func(ctx context.Context, new, old *corev1.Group) error,
	onDelete func(ctx context.Context, item *corev1.Group) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindGroup, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Config(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Config) error,
	onUpdate func(ctx context.Context, new, old *corev1.Config) error,
	onDelete func(ctx context.Context, item *corev1.Config) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindConfig, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Device(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Device) error,
	onUpdate func(ctx context.Context, new, old *corev1.Device) error,
	onDelete func(ctx context.Context, item *corev1.Device) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindDevice, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Session(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Session) error,
	onUpdate func(ctx context.Context, new, old *corev1.Session) error,
	onDelete func(ctx context.Context, item *corev1.Session) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindSession, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) IdentityProvider(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.IdentityProvider) error,
	onUpdate func(ctx context.Context, new, old *corev1.IdentityProvider) error,
	onDelete func(ctx context.Context, item *corev1.IdentityProvider) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindIdentityProvider, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Gateway(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Gateway) error,
	onUpdate func(ctx context.Context, new, old *corev1.Gateway) error,
	onDelete func(ctx context.Context, item *corev1.Gateway) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindGateway, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) PolicyTrigger(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.PolicyTrigger) error,
	onUpdate func(ctx context.Context, new, old *corev1.PolicyTrigger) error,
	onDelete func(ctx context.Context, item *corev1.PolicyTrigger) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindPolicyTrigger, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Region(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Region) error,
	onUpdate func(ctx context.Context, new, old *corev1.Region) error,
	onDelete func(ctx context.Context, item *corev1.Region) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindRegion, onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Credential(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Credential) error,
	onUpdate func(ctx context.Context, new, old *corev1.Credential) error,
	onDelete func(ctx context.Context, item *corev1.Credential) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, string(ucorev1.KindCredential), onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) Authenticator(
	ctx context.Context,
	opts *Opts,
	onCreate func(ctx context.Context, item *corev1.Authenticator) error,
	onUpdate func(ctx context.Context, new, old *corev1.Authenticator) error,
	onDelete func(ctx context.Context, item *corev1.Authenticator) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, string(ucorev1.KindAuthenticator), onCreate, onUpdate, onDelete)
}

func (c *CoreV1Watcher) ClusterConfig(
	ctx context.Context,
	opts *Opts,
	onUpdate func(ctx context.Context, new, old *corev1.ClusterConfig) error,
) error {
	return runWatcherCoreV1(ctx, c.octeliumC, opts, ucorev1.KindClusterConfig, nil, onUpdate, nil)
}

func runWatcherCoreV1[T ucorev1.ResourceObjectRefG](
	ctx context.Context, octeliumC octeliumc.ClientInterface,
	opts *Opts,
	kind string,
	onCreate func(ctx context.Context, item T) error,
	onUpdate func(ctx context.Context, new, old T) error,
	onDelete func(ctx context.Context, item T) error,
) error {

	var doOnCreate func(ctx context.Context, itm umetav1.ResourceObjectI) error
	var doOnUpdate func(ctx context.Context, new, old umetav1.ResourceObjectI) error
	var doOnDelete func(ctx context.Context, itm umetav1.ResourceObjectI) error

	if onCreate != nil {
		doOnCreate = func(ctx context.Context, itm umetav1.ResourceObjectI) error {
			return onCreate(ctx, itm.(T))
		}
	}

	if onUpdate != nil {
		doOnUpdate = func(ctx context.Context, new, old umetav1.ResourceObjectI) error {
			return onUpdate(ctx, new.(T), old.(T))
		}
	}

	if onDelete != nil {
		doOnDelete = func(ctx context.Context, itm umetav1.ResourceObjectI) error {
			return onDelete(ctx, itm.(T))
		}
	}

	watcher, err := NewWatcher(ucorev1.API, ucorev1.Version, kind,
		doOnCreate, doOnUpdate, doOnDelete,
		octeliumC.CoreC(), func() (umetav1.ResourceObjectI, error) {
			return ucorev1.NewObject(kind)
		},
	)
	if err != nil {
		return err
	}

	return watcher.Run(ctx)
}
