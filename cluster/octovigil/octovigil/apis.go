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

package octovigil

import (
	"context"
	"errors"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/octovigil/octovigil/acache"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type internalService struct {
	coctovigilv1.UnimplementedInternalServiceServer
	s *Server
}

func (s *internalService) AuthenticateAndAuthorize(
	ctx context.Context, req *coctovigilv1.AuthenticateAndAuthorizeRequest) (
	*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
	// zap.L().Debug("Received AuthenticateAndAuthorize request", zap.String("svcUID", req.ServiceUID))
	// startedAt := time.Now()

	svc, err := s.s.cache.GetService(req.ServiceUID)
	if err != nil {
		if !errors.Is(err, acache.ErrNotFound) {
			return nil, grpcutils.InternalWithErr(err)
		}
		svc, err = s.s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
			Uid: req.ServiceUID,
		})
		if err != nil {
			return nil, err
		}
		s.s.cache.SetService(svc)
	}

	resp, err := s.s.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
		Service: svc,
		Request: req.Request,
	})
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	/*
		zap.L().Debug("AuthenticateAndAuthorize request done",
			zap.Float32("time", float32(time.Since(startedAt).Nanoseconds())/1000000))
	*/
	return resp, nil
}

func (s *internalService) GetDownstreamFromSessionUID(
	ctx context.Context, req *coctovigilv1.GetDownstreamFromSessionUIDRequest) (
	*coctovigilv1.GetDownstreamFromSessionUIDResponse, error) {

	// startedAt := time.Now()
	di, err := s.s.cache.GetDownstreamInfoBySessionIdentifier(req.SessionUID)
	if err != nil {
		if errors.Is(err, acache.SessionNotFound) {
			return nil, grpcutils.NotFound("Session UID not Found")
		}
		return nil, grpcutils.InternalWithErr(err)
	}

	/*
		zap.L().Debug("GetDownstreamFromSessionUID request done",
			zap.Float32("time", float32(time.Since(startedAt).Nanoseconds())/1000000))
	*/
	return &coctovigilv1.GetDownstreamFromSessionUIDResponse{
		Session: di.Session,
		User:    di.User,
		Groups:  di.Groups,
		Device:  di.Device,
	}, nil
}

func (s *internalService) Authorize(
	ctx context.Context, req *coctovigilv1.AuthorizeRequest) (
	*coctovigilv1.AuthorizeResponse, error) {
	// zap.L().Debug("Received AuthenticateAndAuthorize request", zap.String("svcUID", req.ServiceUID))
	// startedAt := time.Now()

	svc, err := s.s.cache.GetService(req.ServiceUID)
	if err != nil {
		if !errors.Is(err, acache.ErrNotFound) {
			return nil, grpcutils.InternalWithErr(err)
		}
		svc, err = s.s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
			Uid: req.ServiceUID,
		})
		if err != nil {
			return nil, err
		}
		s.s.cache.SetService(svc)
	}

	di, err := s.s.cache.GetDownstreamInfoBySessionIdentifier(req.SessionUID)
	if err != nil {
		return nil, err
	}

	isAuthorized, reason, err := s.s.isAuthorizedWithMetrics(ctx, s.s.getReqCtx(di, req.Request, svc))
	if err != nil {
		return nil, err
	}

	/*
		zap.L().Debug("Authorize request done",
			zap.Float32("time", float32(time.Since(startedAt).Nanoseconds())/1000000))
	*/

	return &coctovigilv1.AuthorizeResponse{
		IsAuthorized: isAuthorized,
		Reason:       reason,
	}, nil
}

func (s *internalService) Evaluate(
	ctx context.Context, req *coctovigilv1.EvaluateRequest) (
	*coctovigilv1.EvaluateResponse, error) {
	reqCtxMap, err := pbutils.ConvertToMap(req.Ctx)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}
	allRules, err := s.s.getEvaluatePolicyRules(ctx, req, reqCtxMap)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}
	resp, err := s.s.doGetDecision(ctx, reqCtxMap, allRules)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	return &coctovigilv1.EvaluateResponse{
		Effect: resp.effect,
	}, nil
}
