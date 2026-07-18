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

package user

import (
	"context"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

const (
	sessionSendQueueSize = 256
	sessionSendTimeout   = 15 * time.Second
)

type Server struct {
	octeliumC octeliumc.ClientInterface

	userv1.UnimplementedMainServiceServer
	connServer *connServer
}

func NewServer(octeliumC octeliumc.ClientInterface) *Server {
	return &Server{
		octeliumC: octeliumC,
		connServer: &connServer{
			connectedSessMap: make(map[string]*connectedSession),
		},
	}
}

func (s *Server) ConnServer() ConnServerI {
	return s.connServer
}

type ConnServerI interface {
	BroadcastMessage(msg *userv1.ConnectResponse) error
	SendMessage(msg *userv1.ConnectResponse, sessUID string) error
}

type connectedSession struct {
	sess   *corev1.Session
	stream userv1.MainService_ConnectServer

	sendCh chan *userv1.ConnectResponse
	ctx    context.Context
	cancel context.CancelFunc
}

func (cs *connectedSession) Done() <-chan struct{} {
	return cs.ctx.Done()
}

func (cs *connectedSession) enqueue(msg *userv1.ConnectResponse) bool {
	select {
	case cs.sendCh <- msg:
		return true
	default:
		return false
	}
}

func (cs *connectedSession) runSendLoop() {
	for {
		select {
		case <-cs.ctx.Done():
			return
		case msg := <-cs.sendCh:
			timer := time.AfterFunc(sessionSendTimeout, cs.cancel)
			err := cs.stream.Send(msg)
			timer.Stop()
			if err != nil {
				zap.L().Debug("Could not send message to Session stream, closing",
					zap.String("sessUID", cs.sess.Metadata.Uid), zap.Error(err))
				cs.cancel()
				return
			}
		}
	}
}

type connServer struct {
	sync.RWMutex
	connectedSessMap map[string]*connectedSession
}

func (s *connServer) addConnectedSess(
	streamCtx context.Context,
	sess *corev1.Session,
	stream userv1.MainService_ConnectServer,
) *connectedSession {
	ctx, cancel := context.WithCancel(streamCtx)

	cs := &connectedSession{
		sess:   sess,
		stream: stream,
		sendCh: make(chan *userv1.ConnectResponse, sessionSendQueueSize),
		ctx:    ctx,
		cancel: cancel,
	}

	s.Lock()
	if old, ok := s.connectedSessMap[sess.Metadata.Uid]; ok {
		old.cancel()
	}
	s.connectedSessMap[sess.Metadata.Uid] = cs
	s.Unlock()

	go cs.runSendLoop()

	return cs
}

func (s *connServer) removeConnectedSess(cs *connectedSession) {
	s.Lock()
	if cur, ok := s.connectedSessMap[cs.sess.Metadata.Uid]; ok && cur == cs {
		delete(s.connectedSessMap, cs.sess.Metadata.Uid)
	}
	s.Unlock()

	cs.cancel()
}

func (s *connServer) BroadcastMessage(msg *userv1.ConnectResponse) error {
	if msg.CreatedAt == nil {
		msg.CreatedAt = pbutils.Now()
	}

	zap.L().Debug("Broadcasting message", zap.Any("msg", msg))

	s.RLock()
	conns := make([]*connectedSession, 0, len(s.connectedSessMap))
	for _, conn := range s.connectedSessMap {
		conns = append(conns, conn)
	}
	s.RUnlock()

	for _, conn := range conns {
		if !conn.enqueue(msg) {
			zap.L().Warn("Session send queue is full",
				zap.String("sessUID", conn.sess.Metadata.Uid))
			conn.cancel()
		}
	}

	return nil
}

func (s *connServer) SendMessage(msg *userv1.ConnectResponse, sessUID string) error {
	s.RLock()
	conn, ok := s.connectedSessMap[sessUID]
	s.RUnlock()
	if !ok {
		return nil
	}

	if msg.CreatedAt == nil {
		msg.CreatedAt = pbutils.Now()
	}

	zap.L().Debug("Sending unicast msg", zap.Any("msg", msg), zap.String("sessUID", sessUID))

	if !conn.enqueue(msg) {
		zap.L().Warn("Session send queue is full. Dropping msg",
			zap.String("sessUID", sessUID))
		conn.cancel()
	}

	return nil
}
