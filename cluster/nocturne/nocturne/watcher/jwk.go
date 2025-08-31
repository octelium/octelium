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

package watcher

import (
	"context"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/jwkctl/jwkutils"
	"go.uber.org/zap"
)

func (w *Watcher) runJWKSecret(ctx context.Context) {
	zap.L().Debug("starting watching root Secrets")

	tickerCh := time.NewTicker(10 * time.Minute)
	defer tickerCh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			if err := w.doRunJWKSecret(ctx); err != nil {
				zap.L().Error("Could not run root Secret watcher doFn", zap.Error(err))
			}
		}
	}
}

func secretHasBeenRotated(secret *corev1.Secret) bool {
	_, ok := secret.Metadata.SystemLabels["key-rotated"]
	return ok
}

const durationYear = 24 * 30 * 12 * time.Hour
const durationMonth = 24 * 30 * time.Hour

func (w *Watcher) doRunJWKSecret(ctx context.Context) error {

	secrets, err := w.octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{
		SystemLabels: map[string]string{
			"octelium-root-secret": "true",
		},
	})
	if err != nil {
		return err
	}

	for _, secret := range secrets.Items {
		if err := w.doProcessJWKSecret(ctx, secret); err != nil {
			return err
		}
	}

	return nil
}

func (w *Watcher) doProcessJWKSecret(ctx context.Context, secret *corev1.Secret) error {
	if w.needsRotation(secret) {
		zap.L().Debug("The root Secret needs rotation",
			zap.Any("secretMetadata", secret.Metadata))

		if _, err := jwkutils.CreateJWKSecret(ctx, w.octeliumC); err != nil {
			return err
		}

		secret.Metadata.SystemLabels["key-rotated"] = "true"
		if _, err := w.octeliumC.CoreC().UpdateSecret(ctx, secret); err != nil {
			return err
		}

		zap.L().Debug("The root Secret successfully rotated",
			zap.Any("secretMetadata", secret.Metadata))
	}

	if w.needsDeletion(secret) {
		zap.L().Debug("The root Secret is old and is getting deleted",
			zap.Any("secretMetadata", secret.Metadata))

		if _, err := w.octeliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{Uid: secret.Metadata.Uid}); err != nil {
			return err
		}

		zap.L().Debug("The root Secret successfully deleted",
			zap.Any("secretMetadata", secret.Metadata))
	}

	return nil
}

func (w *Watcher) needsRotation(secret *corev1.Secret) bool {
	return time.Now().After(secret.Metadata.CreatedAt.AsTime().Add(durationMonth)) && !secretHasBeenRotated(secret)
}

func (w *Watcher) needsDeletion(secret *corev1.Secret) bool {
	return time.Now().After(secret.Metadata.CreatedAt.AsTime().Add(durationYear))
}
