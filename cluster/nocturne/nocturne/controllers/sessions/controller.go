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

package sesscontroller

import (
	"context"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/upstream"
	"go.uber.org/zap"
)

const (
	reconcileInterval    = 5 * time.Minute
	orphanReleaseRounds  = 3
	listSessionsPageSize = 500
)

type Controller struct {
	octeliumC octeliumc.ClientInterface

	mu      sync.Mutex
	indexes map[string][]upstream.ConnIndex

	orphans map[upstream.ConnIndex]int
}

func NewController(
	octeliumC octeliumc.ClientInterface,
) *Controller {
	return &Controller{
		octeliumC: octeliumC,
		indexes:   make(map[string][]upstream.ConnIndex),
		orphans:   make(map[upstream.ConnIndex]int),
	}
}

func (c *Controller) OnAdd(ctx context.Context, sess *corev1.Session) error {
	c.setIndexes(sess)
	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Session) error {
	c.setIndexes(new)
	return nil
}

func (c *Controller) OnDelete(ctx context.Context, sess *corev1.Session) error {
	c.deleteIndexes(sess)

	if sess.Status == nil || sess.Status.Connection == nil ||
		len(sess.Status.Connection.Addresses) == 0 {
		return nil
	}

	zap.L().Debug("Releasing the Connection addresses of the deleted Session",
		zap.String("name", sess.Metadata.Name))

	return upstream.RemoveAllAddressFromConnection(ctx, c.octeliumC, sess)
}

func (c *Controller) setIndexes(sess *corev1.Session) {
	if sess.Metadata == nil {
		return
	}

	indexes := upstream.GetConnectionIndexes(sess)

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(indexes) == 0 {
		delete(c.indexes, sess.Metadata.Uid)
		return
	}

	c.indexes[sess.Metadata.Uid] = indexes
}

func (c *Controller) deleteIndexes(sess *corev1.Session) {
	if sess.Metadata == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.indexes, sess.Metadata.Uid)
}

func (c *Controller) Run(ctx context.Context) {
	tickerCh := time.NewTicker(reconcileInterval)
	defer tickerCh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			if err := c.reconcile(ctx); err != nil {
				zap.L().Warn("Could not reconcile the Connection addresses", zap.Error(err))
			}
		}
	}
}

func (c *Controller) reconcile(ctx context.Context) error {
	sessList, err := c.listSessions(ctx)
	if err != nil {
		return err
	}

	owned := c.getOwnedIndexes(sessList)

	released, err := upstream.ReleaseConnIndexes(ctx, c.octeliumC,
		func(active []upstream.ConnIndex) []upstream.ConnIndex {
			return c.selectOrphans(active, owned)
		})
	if err != nil {
		return err
	}

	for _, itm := range released {
		zap.L().Info("Released an orphan Connection address",
			zap.String("type", itm.Type.String()), zap.Uint32("index", itm.Index))
	}

	return nil
}

func (c *Controller) listSessions(ctx context.Context) ([]*corev1.Session, error) {
	var ret []*corev1.Session
	var page uint32
	for {
		itmList, err := c.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
			Paginate:     true,
			ItemsPerPage: listSessionsPageSize,
			Page:         page,
		})
		if err != nil {
			return nil, err
		}

		ret = append(ret, itmList.Items...)
		if itmList.ListResponseMeta == nil || !itmList.ListResponseMeta.HasMore {
			return ret, nil
		}

		page = page + 1
	}
}

func (c *Controller) getOwnedIndexes(sessList []*corev1.Session) map[upstream.ConnIndex]bool {
	ret := make(map[upstream.ConnIndex]bool)

	setOwned := func(itm upstream.ConnIndex) {
		switch itm.Type {
		case corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_QUICV0:
			ret[itm] = true
		default:
			ret[upstream.ConnIndex{
				Type:  corev1.Session_Status_Connection_WIREGUARD,
				Index: itm.Index,
			}] = true
			ret[upstream.ConnIndex{
				Type:  corev1.Session_Status_Connection_QUICV0,
				Index: itm.Index,
			}] = true
		}
	}

	for _, sess := range sessList {
		for _, itm := range upstream.GetConnectionIndexes(sess) {
			setOwned(itm)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, indexes := range c.indexes {
		for _, itm := range indexes {
			setOwned(itm)
		}
	}

	return ret
}

func (c *Controller) selectOrphans(active []upstream.ConnIndex,
	owned map[upstream.ConnIndex]bool) []upstream.ConnIndex {
	orphans := make(map[upstream.ConnIndex]int)

	var ret []upstream.ConnIndex
	for _, itm := range active {
		if owned[itm] {
			continue
		}

		if _, ok := orphans[itm]; ok {
			continue
		}

		orphans[itm] = c.orphans[itm] + 1
		if orphans[itm] >= orphanReleaseRounds {
			ret = append(ret, itm)
		}
	}

	for _, itm := range ret {
		delete(orphans, itm)
	}

	c.orphans = orphans

	return ret
}
