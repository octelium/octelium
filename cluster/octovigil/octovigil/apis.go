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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/octovigil/octovigil/acache"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type internalService struct {
	coctovigilv1.UnimplementedInternalServiceServer
	s *Server
}

func validateAuthorization(authorization *coctovigilv1.Authorization) error {
	if authorization == nil {
		return nil
	}
	for _, policy := range authorization.InlinePolicies {
		if policy == nil || policy.Spec == nil {
			return grpcutils.InvalidArg("Invalid inlinePolicy")
		}
	}
	return nil
}

func (s *internalService) AuthenticateAndAuthorize(
	ctx context.Context, req *coctovigilv1.AuthenticateAndAuthorizeRequest) (
	*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
	if req == nil {
		return nil, grpcutils.InvalidArg("Nil request")
	}
	if err := validateAuthorization(req.Additional); err != nil {
		return nil, err
	}
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
		Service:    svc,
		Request:    req.Request,
		Additional: req.Additional,
	})
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	if resp.RequestContext != nil {
		if req.OmitRequest {
			resp.RequestContext.Request = nil
		}

		if req.ServiceResourceVersion != "" &&
			req.ServiceResourceVersion == svc.GetMetadata().GetResourceVersion() {
			resp.RequestContext.Service = nil
		}

		if req.OmitUnchangedIdentity {
			resp.IdentityFingerprint = getIdentityFingerprint(resp.RequestContext)
			if len(resp.IdentityFingerprint) > 0 &&
				bytes.Equal(resp.IdentityFingerprint, req.IdentityFingerprint) {
				resp.RequestContext.Session = nil
				resp.RequestContext.User = nil
				resp.RequestContext.Groups = nil
				resp.RequestContext.Device = nil
				resp.RequestContext.Namespace = nil
				resp.IsIdentityOmitted = true
			}
		}
	}

	/*
		zap.L().Debug("AuthenticateAndAuthorize request done",
			zap.Float32("time", float32(time.Since(startedAt).Nanoseconds())/1000000))
	*/
	return resp, nil
}

const identityFingerprintVersion = 1

func getIdentityFingerprint(reqCtx *corev1.RequestContext) []byte {
	if reqCtx.GetSession() == nil {
		return nil
	}

	ret := []byte{identityFingerprintVersion}

	var ok bool
	if ret, ok = appendIdentityMetadata(ret, reqCtx.Session.Metadata); !ok {
		return nil
	}

	if reqCtx.User == nil {
		ret = append(ret, 0)
	} else if ret, ok = appendIdentityMetadata(ret, reqCtx.User.Metadata); !ok {
		return nil
	}

	ret = binary.AppendUvarint(ret, uint64(len(reqCtx.Groups)))
	for _, grp := range reqCtx.Groups {
		if grp == nil {
			return nil
		}
		if ret, ok = appendIdentityMetadata(ret, grp.Metadata); !ok {
			return nil
		}
	}

	if reqCtx.Device == nil {
		ret = append(ret, 0)
	} else {
		if ret, ok = appendIdentityMetadata(ret, reqCtx.Device.Metadata); !ok {
			return nil
		}

		status := reqCtx.Device.Status
		ret = append(ret,
			getIdentityFingerprintBool(status.GetPosture() != nil),
			getIdentityFingerprintBool(status.GetProbeAttempt() != nil))
		ret = binary.AppendUvarint(ret, uint64(status.GetBinding().GetAssurance()))
	}

	if reqCtx.Namespace == nil {
		ret = append(ret, 0)
	} else if ret, ok = appendIdentityMetadata(ret, reqCtx.Namespace.Metadata); !ok {
		return nil
	}

	sum := sha256.Sum256(ret)
	return sum[:]
}

func appendIdentityMetadata(b []byte, md *metav1.Metadata) ([]byte, bool) {
	if md.GetUid() == "" || md.GetResourceVersion() == "" {
		return nil, false
	}

	b = append(b, 1)
	b = binary.AppendUvarint(b, uint64(len(md.Uid)))
	b = append(b, md.Uid...)
	b = binary.AppendUvarint(b, uint64(len(md.ResourceVersion)))
	b = append(b, md.ResourceVersion...)

	return b, true
}

func getIdentityFingerprintBool(v bool) byte {
	if v {
		return 1
	}
	return 0
}

func (s *internalService) GetDownstreamFromSessionUID(
	ctx context.Context, req *coctovigilv1.GetDownstreamFromSessionUIDRequest) (
	*coctovigilv1.GetDownstreamFromSessionUIDResponse, error) {
	if req == nil {
		return nil, grpcutils.InvalidArg("Nil request")
	}

	// startedAt := time.Now()
	di, err := s.s.getDownstreamInfo(ctx, req.SessionUID)
	if err != nil {
		if errors.Is(err, acache.SessionNotFound) {
			return nil, grpcutils.NotFound("Session UID not Found")
		}
		return nil, err
	}

	/*
		zap.L().Debug("GetDownstreamFromSessionUID request done",
			zap.Float32("time", float32(time.Since(startedAt).Nanoseconds())/1000000))
	*/
	return &coctovigilv1.GetDownstreamFromSessionUIDResponse{
		Session: di.Session,
		User:    di.User,
		Groups:  di.Groups,
		Device:  getEffectiveDevice(di.Device, di.Session, time.Now()),
	}, nil
}

func (s *internalService) Authorize(
	ctx context.Context, req *coctovigilv1.AuthorizeRequest) (
	*coctovigilv1.AuthorizeResponse, error) {
	if req == nil {
		return nil, grpcutils.InvalidArg("Nil request")
	}
	if err := validateAuthorization(req.Additional); err != nil {
		return nil, err
	}
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

	di, err := s.s.getDownstreamInfo(ctx, req.SessionUID)
	if err != nil {
		return nil, err
	}

	isAuthorized, reason, err := s.s.isAuthorizedWithMetrics(ctx,
		s.s.getReqCtx(di, req.Request, svc), req.Additional)
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
	if req == nil {
		return nil, grpcutils.InvalidArg("Nil request")
	}
	for _, policy := range req.InlinePolicies {
		if policy == nil || policy.Policy == nil || policy.Policy.Spec == nil {
			return nil, grpcutils.InvalidArg("Invalid inlinePolicy")
		}
	}
	reqCtxMap, err := pbutils.ConvertToMap(req.Ctx)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}
	allRules, err := s.s.getEvaluatePolicyRules(ctx, req, reqCtxMap)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	resp, err := s.s.doGetDecision(ctx, reqCtxMap, allRules, false)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	return &coctovigilv1.EvaluateResponse{
		Effect: resp.effect,
	}, nil
}
