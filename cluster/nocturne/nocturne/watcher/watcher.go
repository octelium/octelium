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

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"go.uber.org/zap"
)

type Watcher struct {
	octeliumC octeliumc.ClientInterface
}

func InitWatcher(octeliumC octeliumc.ClientInterface) *Watcher {
	return &Watcher{
		octeliumC: octeliumC,
	}
}

func (w *Watcher) runSessions(ctx context.Context) {
	zap.S().Debugf("starting session watcher")

	doRun := func() error {
		sessList, err := w.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{})
		if err != nil {
			return err
		}
		for _, sess := range sessList.Items {
			if time.Now().After(sess.Spec.ExpiresAt.AsTime()) {
				zap.S().Debugf("Deleting the expired session %s", sess.Metadata.Name)
				if _, err := w.octeliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{Name: sess.Metadata.Name}); err != nil {
					return err
				}
			}

			if sess.Status.Authentication != nil {
				if expiresAt := sess.Status.Authentication.SetAt.AsTime().Add(umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo()); !expiresAt.IsZero() && time.Now().After(expiresAt) {
					zap.S().Debugf("Deleting Session with expired refresh token %s", sess.Metadata.Name)
					if _, err := w.octeliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{Name: sess.Metadata.Name}); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	tickerCh := time.NewTicker(10 * time.Minute)
	defer tickerCh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			if err := doRun(); err != nil {
				zap.L().Error("Could not run Session watcher doFn", zap.Error(err))
			}
		}
	}
}

func (w *Watcher) runTokens(ctx context.Context) {

	zap.S().Debugf("starting Credential watcher loop")

	doRun := func() error {

		tknList, err := w.octeliumC.CoreC().ListCredential(ctx, &rmetav1.ListOptions{})
		if err != nil {
			return err
		}

		for _, tkn := range tknList.Items {
			if tkn.Spec.ExpiresAt.IsValid() && time.Now().After(tkn.Spec.ExpiresAt.AsTime()) {
				if _, err := w.octeliumC.CoreC().DeleteCredential(ctx, &rmetav1.DeleteOptions{Name: tkn.Metadata.Name}); err != nil {
					return err
				}
			}
		}
		return nil
	}

	tickerCh := time.NewTicker(13 * time.Minute)
	defer tickerCh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			if err := doRun(); err != nil {
				zap.L().Error("Could not run Credential watcher doFn", zap.Error(err))
			}
		}
	}
}

func (w *Watcher) runUsers(ctx context.Context) {
	zap.S().Debugf("starting User watcher loop")

	tickerCh := time.NewTicker(11 * time.Minute)
	defer tickerCh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			if err := w.doRunUsers(ctx); err != nil {
				zap.L().Error("Could not run User watcher doFn", zap.Error(err))
			}
		}
	}
}

func (w *Watcher) doRunUsers(ctx context.Context) error {

	/*
		usrList, err := w.octeliumC.CoreC().ListUser(ctx, &rmetav1.ListOptions{})
		if err != nil {
			return err
		}

		for _, usr := range usrList.Items {
			if usr.Metadata.DeleteAt == "" {
				continue
			}

			expiryTime, err := time.Parse(time.RFC3339, usr.Metadata.DeleteAt)
			if err != nil {
				return err
			}

			if time.Now().After(expiryTime) {
				zap.S().Debugf("Removing temporary User %s", usr.Metadata.Name)
				if _, err := w.octeliumC.CoreC().DeleteUser(ctx, &rmetav1.DeleteOptions{Name: usr.Metadata.Name}); err != nil {
					return err
				}
			}
		}
	*/

	return nil
}

func (w *Watcher) runSecrets(ctx context.Context) {
	zap.S().Debugf("starting Secret watcher loop")

	tickerCh := time.NewTicker(7 * time.Minute)
	defer tickerCh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			if err := w.doRunSecrets(ctx); err != nil {
				zap.L().Error("Could not run Secret watcher doFn", zap.Error(err))
			}
		}
	}
}

func (w *Watcher) doRunSecrets(ctx context.Context) error {
	/*
		secretList, err := w.octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{})
		if err != nil {
			return err
		}

		for _, secret := range secretList.Items {

			if secret.Spec.ExpiresAt == "" {
				continue
			}

			deleteAt, err := time.Parse(time.RFC3339, secret.Spec.ExpiresAt)
			if err != nil {
				return err
			}

			if time.Now().After(deleteAt) {
				if _, err := w.octeliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{Uid: secret.Metadata.Uid}); err != nil {
					if !grpcerr.IsNotFound(err) {
						return err
					}
				}
			}
		}
	*/

	return nil
}

func (w *Watcher) Run(ctx context.Context) {
	go w.runSessions(ctx)
	go w.runTokens(ctx)
	go w.runUsers(ctx)
	go w.runSecrets(ctx)
	go w.runJWKSecret(ctx)
}
