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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	staleConnectionDuration = 1 * time.Hour
	staleConnectionGrace    = 30 * time.Minute
	disconnectMaxAttempts   = 3
)

type lastSeenObservation struct {
	lastSeenAt time.Time
	since      time.Time
}

func getConnectionLastSeenAt(conn *corev1.Session_Status_Connection) *timestamppb.Timestamp {
	switch {
	case conn.LastSeenAt.IsValid() &&
		(!conn.StartedAt.IsValid() || conn.LastSeenAt.AsTime().After(conn.StartedAt.AsTime())):
		return conn.LastSeenAt
	case conn.StartedAt.IsValid():
		return conn.StartedAt
	default:
		return nil
	}
}

func isConnectionStale(sess *corev1.Session, now time.Time) bool {
	if sess.Status == nil || !sess.Status.IsConnected || sess.Status.Connection == nil {
		return false
	}

	lastSeenAt := getConnectionLastSeenAt(sess.Status.Connection)
	if lastSeenAt == nil {
		return false
	}

	return now.Sub(lastSeenAt.AsTime()) > staleConnectionDuration
}

func (c *Controller) selectStaleConnections(sessList []*corev1.Session, now time.Time) []*corev1.Session {
	observed := make(map[string]lastSeenObservation)

	var ret []*corev1.Session
	for _, sess := range sessList {
		if sess.Metadata == nil || sess.Status == nil || sess.Status.Connection == nil {
			continue
		}

		lastSeenAt := getConnectionLastSeenAt(sess.Status.Connection)
		if lastSeenAt == nil {
			continue
		}

		obs, ok := c.lastSeen[sess.Metadata.Uid]
		if !ok || !obs.lastSeenAt.Equal(lastSeenAt.AsTime()) {
			obs = lastSeenObservation{
				lastSeenAt: lastSeenAt.AsTime(),
				since:      now,
			}
		}
		observed[sess.Metadata.Uid] = obs

		if isConnectionStale(sess, now) && now.Sub(obs.since) >= staleConnectionGrace {
			ret = append(ret, sess)
		}
	}

	c.lastSeen = observed

	return ret
}

func (c *Controller) disconnectStaleConnections(ctx context.Context,
	sessList []*corev1.Session, now time.Time) {
	for _, sess := range c.selectStaleConnections(sessList, now) {
		if err := c.disconnectStaleConnection(ctx, sess.Metadata.Uid,
			getConnectionLastSeenAt(sess.Status.Connection)); err != nil {
			zap.L().Warn("Could not disconnect the stale Connection",
				zap.String("sess", sess.Metadata.Name), zap.Error(err))
		}
	}
}

func (c *Controller) disconnectStaleConnection(ctx context.Context,
	uid string, lastSeenAt *timestamppb.Timestamp) error {
	for attempt := 1; ; attempt++ {
		sess, err := c.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uid})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				return nil
			}
			return err
		}

		if !isConnectionStale(sess, time.Now()) ||
			!pbutils.IsEqual(getConnectionLastSeenAt(sess.Status.Connection), lastSeenAt) {
			return nil
		}

		conn := sess.Status.Connection

		upstream.SetDisconnected(sess, lastSeenAt)

		if _, err := c.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
			switch {
			case grpcerr.IsNotFound(err):
				return nil
			case grpcerr.IsResourceChanged(err) && attempt < disconnectMaxAttempts:
				continue
			default:
				return err
			}
		}

		zap.L().Info("Disconnected a stale Connection",
			zap.String("sess", sess.Metadata.Name), zap.Time("lastSeenAt", lastSeenAt.AsTime()))

		return upstream.RemoveAllAddressFromConnection(ctx, c.octeliumC, &corev1.Session{
			Metadata: sess.Metadata,
			Status: &corev1.Session_Status{
				Connection: conn,
			},
		})
	}
}
