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
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func checkIfCanConnect(i *userctx.UserCtx) error {
	switch {
	case ucorev1.ToSession(i.Session).IsClient():
		return nil
	default:
		return serr.InvalidArg("Invalid Session type")
	}
}

func (s *Server) Connect(stream userv1.MainService_ConnectServer) error {
	ctx := stream.Context()

	i, err := userctx.GetUserCtx(ctx)
	if err != nil {
		return err
	}

	if err := checkIfCanConnect(i); err != nil {
		return err
	}

	initReq, err := stream.Recv()
	if err != nil {
		return serr.InternalWithErr(err)
	}
	req := initReq.GetInitialize()
	if req == nil {
		return serr.InvalidArg("First message must be initialize")
	}

	if i.Session.Status.Connection != nil {
		zap.L().Debug("There is an old active Connection on this Session. Disconnecting it first...")
		if _, err := s.doDisconnect(ctx, i); err != nil {
			return err
		}
	}

	connState, err := s.DoInitConnect(ctx, req)
	if err != nil {
		return err
	}

	if err := stream.Send(connState); err != nil {
		return serr.InternalWithErr(err)
	}

	zap.L().Debug("Starting the connect loop", zap.String("sessionName", i.Session.Metadata.Name))

	tickerCh := time.NewTicker(5 * time.Minute)
	defer tickerCh.Stop()

	defer s.doDisconnect(context.Background(), i)

	s.connServer.addConnectedSess(i.Session, stream)
	defer s.connServer.removeConnectedSess(i.Session.Metadata.Uid)

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("Exiting GetConnectionState",
				zap.String("sessName", i.Session.Metadata.Name), zap.Error(ctx.Err()))
			return nil
		case <-tickerCh.C:
			if sess, err := s.octeliumC.CoreC().GetSession(ctx,
				&rmetav1.GetOptions{Uid: i.Session.Metadata.Uid}); err == nil {

				if sess.Status.Connection != nil {
					sess.Status.Connection.LastSeenAt = pbutils.Now()
					if _, err := s.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
						if grpcerr.IsNotFound(err) {
							return nil
						}

						zap.L().Warn("Could not update Session after updating lastSeen",
							zap.String("name", i.Session.Metadata.Name), zap.Error(err))
					}
				} else {
					zap.L().Debug("Session's Connection is nil. Exiting the loop")
					return nil
				}

			} else {
				if grpcerr.IsNotFound(err) {
					return nil
				}

				zap.L().Warn("Could not get Session to update lastSeen",
					zap.String("name", i.Session.Metadata.Name), zap.Error(err))
			}

		}
	}
}

func (s *Server) DoInitConnect(ctx context.Context, req *userv1.ConnectRequest_Initialize) (*userv1.ConnectResponse, error) {

	i, err := userctx.GetUserCtx(ctx)
	if err != nil {
		return nil, err
	}

	sess, err := s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: i.Session.Metadata.Uid})
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	hasV4 := req.L3Mode == userv1.ConnectRequest_Initialize_V4 || req.L3Mode == userv1.ConnectRequest_Initialize_BOTH
	hasV6 := req.L3Mode == userv1.ConnectRequest_Initialize_V6 || req.L3Mode == userv1.ConnectRequest_Initialize_BOTH

	if hasV4 && !ucorev1.ToClusterConfig(cc).HasV4() {
		return nil, serr.InvalidArg("The Cluster does not support v4 only networking")
	}

	if hasV6 && !ucorev1.ToClusterConfig(cc).HasV6() {
		return nil, serr.InvalidArg("The Cluster does not support v6 only networking")
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	reqServices, err := func() ([]*corev1.Session_Status_Connection_ServiceOptions_RequestedService, error) {
		if req.ServiceOptions == nil || len(req.ServiceOptions.Services) == 0 {
			return nil, nil
		}

		if err := apivalidation.ValidatePort(int(req.ServiceOptions.PortStart)); err != nil {
			return nil, err
		}

		if len(req.ServiceOptions.Services) > 128 {
			return nil, serr.InvalidArg("Too many Services to host!")
		}

		var ret []*corev1.Session_Status_Connection_ServiceOptions_RequestedService
		for _, svcReq := range req.ServiceOptions.Services {

			svc, err := s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: vutils.GetServiceFullNameFromName(svcReq.Name)})
			if err != nil {
				switch {
				case grpcerr.IsNotFound(err):
					zap.L().Debug("The served Service does not exist. Skipping....", zap.String("svc", svcReq.Name))
					continue
				default:
					return nil, serr.InternalWithErr(err)
				}
			}

			if err := apivalidation.CheckIsUserHidden(svc); err != nil {
				return nil, err
			}

			ret = append(ret, &corev1.Session_Status_Connection_ServiceOptions_RequestedService{
				ServiceRef:   umetav1.GetObjectReference(svc),
				NamespaceRef: svc.Status.NamespaceRef,
			})
		}
		return ret, nil
	}()
	if err != nil {
		return nil, err
	}

	publishedServices, err := func() ([]*corev1.Session_Status_Connection_PublishedService, error) {
		if len(req.PublishedServices) == 0 {
			return nil, nil
		}
		if len(req.PublishedServices) > 128 {
			return nil, serr.InvalidArg("Too many published Services")
		}

		var ret []*corev1.Session_Status_Connection_PublishedService
		for _, svcReq := range req.PublishedServices {
			svc, err := s.octeliumC.CoreC().GetService(ctx,
				&rmetav1.GetOptions{
					Name: vutils.GetServiceFullNameFromName(svcReq.Name),
				})
			if err != nil {
				switch {
				case grpcerr.IsNotFound(err):
					zap.L().Debug("The published Service does not exist. Skipping....", zap.String("svc", svcReq.Name))
					continue
				default:
					return nil, serr.InternalWithErr(err)
				}
			}
			if err := apivalidation.CheckIsUserHidden(svc); err != nil {
				return nil, err
			}

			if !govalidator.IsPort(fmt.Sprintf("%d", svcReq.Port)) {
				return nil, serr.InvalidArg("Invalid port: %d", svcReq.Port)
			}

			switch svcReq.Address {
			case "", "localhost":
			default:
				if !govalidator.IsIP(svcReq.Address) {
					return nil, serr.InvalidArg("Invalid address: %s", svcReq.Address)
				}
			}

			ret = append(ret, &corev1.Session_Status_Connection_PublishedService{
				ServiceRef: umetav1.GetObjectReference(svc),
				Port:       int32(svcReq.Port),
				Address: func() string {
					if svcReq.Address != "" {
						return svcReq.Address
					}
					return "localhost"
				}(),
			})
		}
		return ret, nil
	}()
	if err != nil {
		return nil, err
	}

	if req.ESSHPort != 0 {
		if err := apivalidation.ValidatePort(int(req.ESSHPort)); err != nil {
			return nil, err
		}
	}

	sess.Status.IsConnected = true
	pubKey := privateKey.PublicKey()
	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	sess.Status.Connection = &corev1.Session_Status_Connection{
		StartedAt: pbutils.Now(),
		Type: func() corev1.Session_Status_Connection_Type {
			switch req.ConnectionType {
			case userv1.ConnectRequest_Initialize_QUICV0:
				return corev1.Session_Status_Connection_QUICV0
			default:
				return corev1.Session_Status_Connection_WIREGUARD
			}
		}(),
		PublishedServices: publishedServices,
		IgnoreDNS:         req.IgnoreDNS,

		X25519PublicKey:  pubKey[:],
		Ed25519PublicKey: ed25519Pub[:],
		ESSHEnable:       req.ESSHEnable,
		ESSHPort: func() int32 {
			if !req.ESSHEnable {
				return 0
			}
			if req.ESSHPort != 0 {
				return req.ESSHPort
			}
			return 22022
		}(),

		L3Mode: func() corev1.Session_Status_Connection_L3Mode {
			var ret corev1.Session_Status_Connection_L3Mode
			switch ucorev1.ToClusterConfig(cc).GetNetworkMode() {
			case corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK:
				ret = corev1.Session_Status_Connection_BOTH
			case corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY:
				ret = corev1.Session_Status_Connection_V4
			case corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY:
				ret = corev1.Session_Status_Connection_V6
			}

			if ret == corev1.Session_Status_Connection_BOTH {
				if req.L3Mode == userv1.ConnectRequest_Initialize_V4 {
					ret = corev1.Session_Status_Connection_V4
				}
				if req.L3Mode == userv1.ConnectRequest_Initialize_V6 {
					ret = corev1.Session_Status_Connection_V6
				}
			}

			return ret
		}(),

		ServiceOptions: func() *corev1.Session_Status_Connection_ServiceOptions {
			opts := req.ServiceOptions
			if opts == nil {
				return nil
			}

			return &corev1.Session_Status_Connection_ServiceOptions{
				ServeAll:          opts.ServeAll,
				RequestedServices: reqServices,

				PortStart: func() int32 {
					if opts.PortStart != 0 {
						return opts.PortStart
					}
					return 23000
				}(),
			}
		}(),
	}

	sess.Status.TotalConnections = sess.Status.TotalConnections + 1

	if err := upstream.AddAddressToConnection(ctx, s.octeliumC, sess); err != nil {
		return nil, serr.InternalWithErr(err)
	}

	if req.ServiceOptions != nil {
		svcOpts := req.ServiceOptions

		if svcOpts.ServeAll || len(svcOpts.Services) > 0 {

			svcs, err := s.octeliumC.CoreC().ListService(ctx, &rmetav1.ListOptions{
				SpecLabels: map[string]string{
					fmt.Sprintf("host-user-%s", i.User.Metadata.Name): i.User.Metadata.Uid,
				},
			})
			if err != nil {
				return nil, serr.InternalWithErr(err)
			}
			zap.L().Debug("Found candidate Services to serve by User",
				zap.Int("len", len(svcs.Items)), zap.String("user", i.User.Metadata.Name))

			for _, svc := range svcs.Items {
				if upstream.ServeService(svc, sess) {
					if err := upstream.SetConnectionUpstreams(ctx, s.octeliumC, sess, svc); err != nil {
						return nil, serr.InternalWithErr(err)
					}
				}
			}

		}
	}

	connState, err := getConnectionState(ctx, s.octeliumC, sess, cc, privateKey, ed25519Priv)
	if err != nil {
		return nil, err
	}

	_, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return connState, nil
}

func (s *Server) Disconnect(ctx context.Context, req *userv1.DisconnectRequest) (*userv1.DisconnectResponse, error) {

	i, err := userctx.GetUserCtx(ctx)
	if err != nil {
		return nil, err
	}

	_, err = s.doDisconnect(ctx, i)
	if err != nil {
		return nil, err
	}

	return &userv1.DisconnectResponse{}, nil
}

func (s *Server) doDisconnect(ctx context.Context, i *userctx.UserCtx) (*userv1.DisconnectResponse, error) {

	if err := checkIfCanConnect(i); err != nil {
		return nil, err
	}
	zap.L().Debug("Starting disconnecting Session", zap.String("uid", i.Session.Metadata.Uid))
	sess, err := s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: i.Session.Metadata.Uid})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, grpcutils.NotFound("Session has been removed")
		}
		return nil, serr.InternalWithErr(err)
	}

	switch sess.Status.Type {
	case corev1.Session_Status_CLIENT:
	default:
		return nil, serr.InvalidArg("Session type must be CLIENT")
	}

	if !sess.Status.IsConnected || sess.Status.Connection == nil {
		return &userv1.DisconnectResponse{}, nil
	}

	if err := upstream.RemoveAllAddressFromConnection(ctx, s.octeliumC, sess); err != nil {
		zap.L().Warn("Could not remove addresses from connection", zap.Error(err))
	}

	{
		maxLen := 100

		if len(sess.Status.LastConnections) >= maxLen {
			sess.Status.LastConnections = sess.Status.LastConnections[:maxLen-2]
		}

		sess.Status.LastConnections = append([]*corev1.Session_Status_LastConnection{
			{
				StartedAt: sess.Status.Connection.StartedAt,
				EndedAt:   pbutils.Now(),
			},
		}, sess.Status.LastConnections...)
	}

	sess.Status.IsConnected = false
	sess.Status.Connection = nil

	if _, err := s.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
		return nil, serr.InternalWithErr(err)
	}

	zap.L().Debug("Successfully disconnected Session", zap.String("sess", i.Session.Metadata.Name))

	return &userv1.DisconnectResponse{}, nil
}
