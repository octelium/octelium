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

package authserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
)

func (s *server) doBuildDevice(ctx context.Context,
	cc *corev1.ClusterConfig, req *authv1.RegisterDeviceBeginRequest,
	usr *corev1.User) (*corev1.Device, error) {

	var macAddrs []string

	for _, addr := range req.Info.MacAddresses {
		hw, err := net.ParseMAC(addr)
		if err != nil {
			return nil, err
		}
		macAddrs = append(macAddrs, hw.String())
	}

	deviceReq := &corev1.Device{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s-%s",
				strings.ToLower(req.Info.OsType.String()),
				utilrand.GetRandomStringLowercase(8)),
		},

		Spec: &corev1.Device_Spec{
			State: func() corev1.Device_Spec_State {
				switch usr.Spec.Type {
				case corev1.User_Spec_HUMAN:
					if cc.Spec.Device != nil && cc.Spec.Device.Human != nil &&
						cc.Spec.Device.Human.DefaultState != corev1.Device_Spec_STATE_UNKNOWN {
						return cc.Spec.Device.Human.DefaultState
					}
				case corev1.User_Spec_WORKLOAD:
					if cc.Spec.Device != nil && cc.Spec.Device.Workload != nil &&
						cc.Spec.Device.Workload.DefaultState != corev1.Device_Spec_STATE_UNKNOWN {
						return cc.Spec.Device.Workload.DefaultState
					}
				}
				return corev1.Device_Spec_ACTIVE
			}(),
		},

		Status: &corev1.Device_Status{
			UserRef:      umetav1.GetObjectReference(usr),
			OsType:       corev1.Device_Status_OSType(req.Info.OsType),
			Hostname:     req.Info.Hostname,
			Id:           req.Info.Id,
			SerialNumber: req.Info.SerialNumber,
			MacAddresses: macAddrs,
		},
	}

	return deviceReq, nil
}

func (s *server) doRegisterDeviceBegin(ctx context.Context, req *authv1.RegisterDeviceBeginRequest) (*authv1.RegisterDeviceBeginResponse, error) {

	if err := s.validateRegisterDeviceBeginRequest(req); err != nil {
		return nil, err
	}

	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if sess.Status.Type != corev1.Session_Status_CLIENT {
		return nil, s.errPermissionDenied("Not a CLIENT Session")
	}

	if err := s.checkSessionValid(sess); err != nil {
		return nil, err
	}

	if sess.Status.DeviceRef != nil {
		return nil, grpcutils.AlreadyExists("This Device is already registered")
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}
	if err := s.checkCanCreateDevice(ctx, cc, usr, sess, req); err != nil {
		return nil, err
	}

	ret := &authv1.RegisterDeviceBeginResponse{
		Uid: utilrand.GetRandomStringCanonical(10),
	}

	reqMap := map[string]any{
		"req":     pbutils.MustConvertToMap(req),
		"resp":    pbutils.MustConvertToMap(ret),
		"sessUID": sess.Metadata.Uid,
	}
	reqMapBytes, err := json.Marshal(reqMap)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	if _, err := s.octeliumC.CacheC().SetCache(ctx, &rcachev1.SetCacheRequest{
		Key:  s.getDeviceRegistrationKey(ret.Uid),
		Data: reqMapBytes,
		Duration: &metav1.Duration{
			Type: &metav1.Duration_Seconds{
				Seconds: 20,
			},
		},
	}); err != nil {
		return nil, s.errInternalErr(err)
	}

	return ret, nil
}

func (s *server) doRegisterDeviceFinish(ctx context.Context, reqi *authv1.RegisterDeviceFinishRequest) (*authv1.RegisterDeviceFinishResponse, error) {

	if err := s.validateRegisterDeviceFinishRequest(reqi); err != nil {
		return nil, err
	}

	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.checkSessionValid(sess); err != nil {
		return nil, err
	}

	req, err := s.loadDeviceRegistrationBeginReq(ctx, sess, reqi)
	if err != nil {
		return nil, err
	}

	if err := s.validateRegisterDeviceBeginRequest(req); err != nil {
		return nil, s.errInvalidArgErr(err)
	}

	if sess.Status.Type != corev1.Session_Status_CLIENT {
		return nil, s.errPermissionDenied("Not a CLIENT Session")
	}

	if sess.Status.DeviceRef != nil {
		return nil, grpcutils.AlreadyExists("This Device is already registered")
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	if dev, err := s.getDeviceByID(ctx, req.Info.Id); err == nil &&
		dev.Status.UserRef != nil &&
		dev.Status.UserRef.Uid == usr.Metadata.Uid {
		return nil, grpcutils.AlreadyExists("This Device is already registered")
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	devReq, err := s.doBuildDevice(ctx, cc, req, usr)
	if err != nil {
		return nil, err
	}

	dev, err := s.octeliumC.CoreC().CreateDevice(ctx, devReq)
	if err != nil {
		return nil, err
	}

	sess.Status.DeviceRef = umetav1.GetObjectReference(dev)
	_, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	return &authv1.RegisterDeviceFinishResponse{}, nil
}

func (s *server) loadDeviceRegistrationBeginReq(ctx context.Context, sess *corev1.Session, reqi *authv1.RegisterDeviceFinishRequest) (*authv1.RegisterDeviceBeginRequest, error) {

	resp, err := s.octeliumC.CacheC().GetCache(ctx, &rcachev1.GetCacheRequest{
		Key:    s.getDeviceRegistrationKey(reqi.Uid),
		Delete: true,
	})
	if err != nil {
		return nil, err
	}

	respMap := make(map[string]any)
	if err := json.Unmarshal(resp.Data, &respMap); err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}
	sessUID := respMap["sessUID"].(string)
	if sessUID != sess.Metadata.Uid {
		return nil, grpcutils.InvalidArg("Invalid Session")
	}

	beginResponseMap, ok := respMap["resp"].(map[string]any)
	if !ok || beginResponseMap == nil {
		return nil, grpcutils.InvalidArg("nil beginResponse")
	}

	beginReqMap, ok := respMap["req"].(map[string]any)
	if !ok || beginResponseMap == nil {
		return nil, grpcutils.InvalidArg("nil beginRequest")
	}

	beginResp := &authv1.RegisterDeviceBeginResponse{}

	if err := pbutils.UnmarshalFromMap(beginResponseMap, beginResp); err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	beginReq := &authv1.RegisterDeviceBeginRequest{}

	if err := pbutils.UnmarshalFromMap(beginReqMap, beginReq); err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	if len(reqi.Responses) != len(beginResp.Requests) {
		return nil, grpcutils.InvalidArg("Invalid responses len")
	}

	for _, req := range beginResp.Requests {
		if !slices.ContainsFunc(reqi.Responses, func(a *authv1.RegisterDeviceFinishRequest_Response) bool {
			return a.Uid == req.Uid
		}) {
			return nil, grpcutils.InvalidArg("Response of uid does not exist: %s", req.Uid)
		}
	}

	return beginReq, nil
}

func (s *server) getDeviceRegistrationKey(uid string) []byte {
	return []byte(fmt.Sprintf("octelium.dev-registration.%s", uid))
}

var rgxDeviceID = regexp.MustCompile(`^[a-f0-9]{64}$`)

var rgxDeviceRegistrationUID = regexp.MustCompile(`^[a-z0-9]{10}$`)

func (s *server) validateRegisterDeviceBeginRequest(req *authv1.RegisterDeviceBeginRequest) error {
	if req == nil {
		return s.errInvalidArg("Nil req")
	}

	if req.Info == nil {
		return s.errInvalidArg("Nil info")
	}

	info := req.Info

	{
		if info.Id == "" {
			return errors.Errorf("Empty ID")
		}

		if !rgxDeviceID.MatchString(info.Id) {
			return errors.Errorf("Invalid ID: %s", info.Id)
		}
	}

	if info.Hostname != "" {
		if len(info.Hostname) > 32 {
			return errors.Errorf("Hostname is too long")
		}
	}

	if info.SerialNumber != "" {
		if len(info.SerialNumber) > 128 {
			return errors.Errorf("Serial Number is too long")
		}

		if len(info.SerialNumber) < 6 {
			return errors.Errorf("Serial Number is too short")
		}

		switch strings.ToLower(info.SerialNumber) {
		case "0", "default string", "null", "nil":
			return errors.Errorf("Invalid serial number")
		}
	}

	switch info.OsType {
	case authv1.RegisterDeviceBeginRequest_Info_OS_TYPE_UNKNOWN:
		return errors.Errorf("Unknown osType")
	case authv1.RegisterDeviceBeginRequest_Info_ANDROID, authv1.RegisterDeviceBeginRequest_Info_IOS:
		return errors.Errorf("Unsupported osType")
	}

	if len(info.MacAddresses) > 0 {
		if len(info.MacAddresses) > 16 {
			return errors.Errorf("Too many mac addrs")
		}

		for _, addr := range info.MacAddresses {
			if !govalidator.IsMAC(addr) {
				return errors.Errorf("Invalid mac addr: %s", addr)
			}
		}
	}

	return nil
}

func (s *server) validateRegisterDeviceFinishRequest(req *authv1.RegisterDeviceFinishRequest) error {
	if req == nil {
		return s.errInvalidArg("Nil req")
	}
	if !rgxDeviceRegistrationUID.MatchString(req.Uid) {
		return s.errInvalidArg("invalid UID")
	}
	if len(req.Responses) > 0 {
		if len(req.Responses) > 100 {
			return s.errInvalidArg("Too many responses")
		}

		for _, resp := range req.Responses {
			if !rgxDeviceRegistrationUID.MatchString(resp.Uid) {
				return s.errInvalidArg("invalid UID")
			}

			switch resp.Type.(type) {
			case *authv1.RegisterDeviceFinishRequest_Response_Command_:
				if len(resp.GetCommand().Output) > 10000 {
					return s.errInvalidArg("Output is too large")
				}
			case *authv1.RegisterDeviceFinishRequest_Response_File_:
				if len(resp.GetFile().Output) > 10000 {
					return s.errInvalidArg("Output is too large")
				}
			default:
				return s.errInvalidArg("Invalid response type")
			}
		}
	}

	return nil
}

const defaultMaxDevicePerUser = 32

func (s *server) checkCanCreateDevice(ctx context.Context,
	cc *corev1.ClusterConfig, usr *corev1.User, sess *corev1.Session, req *authv1.RegisterDeviceBeginRequest) error {
	{
		devList, err := s.octeliumC.CoreC().ListDevice(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.id", req.Info.Id),
			},
		})
		if err != nil {
			return s.errInternalErr(err)
		}
		if len(devList.Items) > 0 {
			dev := devList.Items[0]
			if dev.Status.UserRef.Uid != usr.Metadata.Uid {
				return s.errInvalidArg("Invalid ID")
			}
			sess.Status.DeviceRef = umetav1.GetObjectReference(dev)
			_, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
			if err != nil {
				return s.errInternalErr(err)
			}
			return s.errAlreadyExists("Device is already registered")
		}
	}

	if req.Info.SerialNumber != "" {
		devList, err := s.octeliumC.CoreC().ListDevice(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.serialNumber", req.Info.SerialNumber),
			},
		})
		if err != nil {
			return s.errInternalErr(err)
		}
		if len(devList.Items) > 0 {
			dev := devList.Items[0]
			if dev.Status.UserRef.Uid != usr.Metadata.Uid {
				return s.errInvalidArg("Invalid serial number")
			}
			sess.Status.DeviceRef = umetav1.GetObjectReference(dev)
			_, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
			if err != nil {
				return s.errInternalErr(err)
			}
			return s.errAlreadyExists("Device is already registered")
		}
	}

	{
		var maxPerUser uint32
		switch usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			if cc.Spec.Device != nil && cc.Spec.Device.Human != nil && cc.Spec.Device.Human.MaxPerUser > 0 {
				maxPerUser = cc.Spec.Device.Human.MaxPerUser
			}
		case corev1.User_Spec_WORKLOAD:
			if cc.Spec.Device != nil && cc.Spec.Device.Workload != nil && cc.Spec.Device.Workload.MaxPerUser > 0 {
				maxPerUser = cc.Spec.Device.Workload.MaxPerUser
			}
		}
		if maxPerUser == 0 {
			maxPerUser = defaultMaxDevicePerUser
		}

		if maxPerUser > 10000 {
			maxPerUser = 10000
		}

		devList, err := s.octeliumC.CoreC().ListDevice(ctx, urscsrv.FilterByUser(usr))
		if err != nil {
			return s.errInternalErr(err)
		}
		if len(devList.Items) >= int(maxPerUser) {
			return s.errPermissionDenied("Limit of Devices has been exceeded")
		}
	}

	return nil
}

func (s *server) getDeviceByID(ctx context.Context, id string) (*corev1.Device, error) {
	devList, err := s.octeliumC.CoreC().ListDevice(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldEQValStr("status.id", id),
		},
	})
	if err != nil {
		return nil, s.errInternalErr(err)
	}
	if len(devList.Items) != 1 {
		return nil, s.errNotFound("Invalid Device ID")
	}

	return devList.Items[0], nil
}
