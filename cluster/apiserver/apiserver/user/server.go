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
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"go.uber.org/zap"
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
}

type connServer struct {
	sync.RWMutex
	connectedSessMap map[string]*connectedSession
}

func (s *connServer) BroadcastMessage(msg *userv1.ConnectResponse) error {
	s.RLock()
	defer s.RUnlock()
	zap.L().Debug("Broadcasting message", zap.Any("msg", msg))
	for _, conn := range s.connectedSessMap {
		conn.stream.Send(msg)
	}

	return nil
}

func (s *connServer) SendMessage(msg *userv1.ConnectResponse, sessUID string) error {
	s.RLock()
	defer s.RUnlock()
	conn, ok := s.connectedSessMap[sessUID]
	if !ok {
		return nil
	}

	zap.L().Debug("Sending unicast msg", zap.Any("msg", msg), zap.String("sessUID", sessUID))

	return conn.stream.Send(msg)
}

func (s *connServer) addConnectedSess(sess *corev1.Session, stream userv1.MainService_ConnectServer) {
	s.Lock()
	s.connectedSessMap[sess.Metadata.Uid] = &connectedSession{
		sess:   sess,
		stream: stream,
	}
	s.Unlock()
}

func (s *connServer) removeConnectedSess(sessUID string) {
	s.Lock()
	delete(s.connectedSessMap, sessUID)
	s.Unlock()
}
