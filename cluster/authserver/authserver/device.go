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
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (s *server) doBuildDevice(ctx context.Context,
	cc *corev1.ClusterConfig, info *authv1.RegisterDeviceRequest_Info,
	usr *corev1.User) (*corev1.Device, error) {

	macAddrs, err := getDeviceMacAddresses(info)
	if err != nil {
		return nil, err
	}

	deviceReq := &corev1.Device{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s-%s",
				strings.ToLower(info.OsType.String()),
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
			OsType:       corev1.Device_Status_OSType(info.OsType),
			Hostname:     info.Hostname,
			Id:           info.Id,
			SerialNumber: info.SerialNumber,
			MacAddresses: macAddrs,
		},
	}

	return deviceReq, nil
}

func getDeviceMacAddresses(info *authv1.RegisterDeviceRequest_Info) ([]string, error) {
	var ret []string

	for _, addr := range info.MacAddresses {
		hw, err := net.ParseMAC(addr)
		if err != nil {
			return nil, err
		}
		ret = append(ret, hw.String())
	}

	return ret, nil
}

func (s *server) doRegisterDevice(ctx context.Context, req *authv1.RegisterDeviceRequest) (*authv1.RegisterDeviceResponse, error) {

	if err := s.validateRegisterDeviceRequest(req); err != nil {
		return nil, s.errInvalidArgErr(err)
	}

	sess, err := s.getDeviceRegistrationSession(ctx)
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	dev, err := s.checkCanCreateDevice(ctx, cc, usr, req.Info)
	if err != nil {
		return nil, err
	}

	if dev == nil {
		devReq, err := s.doBuildDevice(ctx, cc, req.Info, usr)
		if err != nil {
			return nil, err
		}

		dev, err = s.octeliumC.CoreC().CreateDevice(ctx, devReq)
		if err != nil {
			return nil, err
		}
	}

	sess.Status.DeviceRef = umetav1.GetObjectReference(dev)
	if _, err := s.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
		return nil, s.errInternalErr(err)
	}

	return &authv1.RegisterDeviceResponse{}, nil
}

func (s *server) getDeviceRegistrationSession(ctx context.Context) (*corev1.Session, error) {
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

	return sess, nil
}

func (s *server) doRegisterDeviceBegin(ctx context.Context, req *authv1.RegisterDeviceBeginRequest) (*authv1.RegisterDeviceBeginResponse, error) {

	if err := s.validateRegisterDeviceBeginRequest(req); err != nil {
		return nil, s.errInvalidArgErr(err)
	}

	sess, err := s.getDeviceRegistrationSession(ctx)
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	existing, err := s.checkCanCreateDevice(ctx, cc, usr, req.Info)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		sess.Status.DeviceRef = umetav1.GetObjectReference(existing)
		if _, err := s.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
			return nil, s.errInternalErr(err)
		}
		return nil, s.errAlreadyExists("Device is already registered")
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

	devReq, err := s.doBuildDevice(ctx, cc, req.Info, usr)
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

	sessUID, ok := respMap["sessUID"].(string)
	if !ok || sessUID == "" {
		return nil, grpcutils.InvalidArg("Invalid session UID in registration state")
	}

	if sessUID != sess.Metadata.Uid {
		return nil, grpcutils.InvalidArg("Invalid Session")
	}

	beginResponseMap, ok := respMap["resp"].(map[string]any)
	if !ok || beginResponseMap == nil {
		return nil, grpcutils.InvalidArg("nil beginResponse")
	}

	beginReqMap, ok := respMap["req"].(map[string]any)
	if !ok || beginReqMap == nil {
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

	if beginResp.Uid != reqi.Uid {
		return nil, grpcutils.InvalidArg("Invalid registration UID")
	}

	return beginReq, nil
}

func (s *server) getDeviceRegistrationKey(uid string) []byte {
	return []byte(fmt.Sprintf("octelium.dev-registration.%s", uid))
}

var rgxDeviceID = regexp.MustCompile(`^[a-f0-9]{64}$`)

var rgxDeviceRegistrationUID = regexp.MustCompile(`^[a-z0-9]{10}$`)

func (s *server) validateRegisterDeviceRequest(req *authv1.RegisterDeviceRequest) error {
	if req == nil {
		return errors.Errorf("Nil req")
	}

	return s.validateDeviceInfo(req.Info)
}

func (s *server) validateRegisterDeviceBeginRequest(req *authv1.RegisterDeviceBeginRequest) error {
	if req == nil {
		return errors.Errorf("Nil req")
	}

	return s.validateDeviceInfo(req.Info)
}

func (s *server) validateDeviceInfo(info *authv1.RegisterDeviceRequest_Info) error {
	if info == nil {
		return errors.Errorf("Nil info")
	}

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
	case authv1.RegisterDeviceRequest_Info_LINUX,
		authv1.RegisterDeviceRequest_Info_WINDOWS,
		authv1.RegisterDeviceRequest_Info_MAC,
		authv1.RegisterDeviceRequest_Info_ANDROID,
		authv1.RegisterDeviceRequest_Info_IOS,
		authv1.RegisterDeviceRequest_Info_CHROMEOS:
	default:
		return errors.Errorf("Unknown osType")
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

	return nil
}

const defaultMaxDevicePerUser = 32

func (s *server) checkCanCreateDevice(ctx context.Context,
	cc *corev1.ClusterConfig, usr *corev1.User, info *authv1.RegisterDeviceRequest_Info) (*corev1.Device, error) {
	{
		devList, err := s.octeliumC.CoreC().ListDevice(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.id", info.Id),
			},
		})
		if err != nil {
			return nil, s.errInternalErr(err)
		}
		if len(devList.Items) > 0 {
			dev := devList.Items[0]
			if dev.Status.UserRef.Uid != usr.Metadata.Uid {
				return nil, s.errInvalidArg("Invalid ID")
			}
			return dev, nil
		}
	}

	devList, err := s.octeliumC.CoreC().ListDevice(ctx, urscsrv.FilterByUser(usr))
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	if info.SerialNumber != "" {
		for _, dev := range devList.Items {
			if dev.Status.SerialNumber == info.SerialNumber {
				return dev, nil
			}
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

		if len(devList.Items) >= int(maxPerUser) {
			return nil, s.errPermissionDenied("Limit of Devices has been exceeded")
		}
	}

	return nil, nil
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

const (
	probeAttemptDuration = 10 * time.Minute

	maxProbesPerAttempt = 64

	probeMaxTotalBytes = 128 * 1024

	defaultProbeMaxOutputBytes = 16384
	hardProbeMaxOutputBytes    = 65536

	maxProbeResultListItems   = 256
	maxProbeResultListItemLen = 1024
	maxProbeResultDetailLen   = 2048
)

var rgxProbeAttemptUID = regexp.MustCompile(`^[a-z0-9]{32}$`)

var rgxProbeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func (s *server) getProbeUserAndDevice(ctx context.Context, sess *corev1.Session) (*corev1.User, *corev1.Device, error) {
	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, nil, err
	}

	if usr.Spec.Type != corev1.User_Spec_HUMAN {
		return nil, nil, grpcutils.PermissionDenied("Not a human user")
	}

	dev, err := s.octeliumC.CoreC().GetDevice(ctx,
		apivalidation.ObjectReferenceToRGetOptions(sess.Status.DeviceRef))
	if err != nil {
		return nil, nil, err
	}

	if dev.Status.UserRef.GetUid() != usr.Metadata.Uid {
		return nil, nil, grpcutils.PermissionDenied("The Device belongs to another User")
	}

	if dev.Status.IsLocked {
		return nil, nil, grpcutils.PermissionDenied("The Device is locked")
	}

	if dev.Spec.State == corev1.Device_Spec_REJECTED {
		return nil, nil, grpcutils.PermissionDenied("The Device is rejected")
	}

	return usr, dev, nil
}

func (s *server) doRunDeviceProbeBegin(ctx context.Context,
	req *authv1.RunDeviceProbeBeginRequest) (*authv1.RunDeviceProbeBeginResponse, error) {

	if err := s.validateRunDeviceProbeBegin(req); err != nil {
		return nil, grpcutils.InvalidArg("Invalid request: %v", err)
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

	if sess.Status.DeviceRef == nil {
		return &authv1.RunDeviceProbeBeginResponse{}, nil
	}

	usr, dev, err := s.getProbeUserAndDevice(ctx, sess)
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	probing := cc.GetSpec().GetDevice().GetProbing()
	if probing.GetIsDisabled() {
		return &authv1.RunDeviceProbeBeginResponse{}, nil
	}

	now := time.Now()

	if attempt := dev.Status.ProbeAttempt; attempt != nil && !isProbeAttemptExpired(attempt, now) {
		switch attempt.State {
		case corev1.Device_Status_ProbeAttempt_ISSUED:
			if attempt.SessionRef.GetUid() == sess.Metadata.Uid {
				return getProbeBeginResponse(attempt), nil
			}
		case corev1.Device_Status_ProbeAttempt_SUBMITTED:
			return &authv1.RunDeviceProbeBeginResponse{}, nil
		}
	}

	probes := s.getIssuableProbes(ctx, cc, usr, dev, now)
	if len(probes) == 0 {
		return &authv1.RunDeviceProbeBeginResponse{}, nil
	}

	attempt := &corev1.Device_Status_ProbeAttempt{
		Uid:        utilrand.GetRandomStringCanonical(32),
		State:      corev1.Device_Status_ProbeAttempt_ISSUED,
		StartedAt:  pbutils.Timestamp(now),
		ExpiresAt:  pbutils.Timestamp(now.Add(probeAttemptDuration)),
		SessionRef: umetav1.GetObjectReference(sess),
		Probes:     probes,
	}

	dev.Status.ProbeAttempt = attempt

	if _, err := s.octeliumC.CoreC().UpdateDevice(ctx, dev); err != nil {
		return nil, err
	}

	return getProbeBeginResponse(attempt), nil
}

func getProbeBeginResponse(attempt *corev1.Device_Status_ProbeAttempt) *authv1.RunDeviceProbeBeginResponse {
	return &authv1.RunDeviceProbeBeginResponse{
		AttemptUID: attempt.Uid,
		Probes:     toAuthProbes(attempt.Probes),
	}
}

func isProbeAttemptExpired(attempt *corev1.Device_Status_ProbeAttempt, now time.Time) bool {
	if !attempt.ExpiresAt.IsValid() {
		return true
	}

	return !now.Before(attempt.ExpiresAt.AsTime())
}

func (s *server) getIssuableProbes(ctx context.Context,
	cc *corev1.ClusterConfig, usr *corev1.User, dev *corev1.Device, now time.Time) []*corev1.ClusterConfig_Status_Device_Probe {

	plan := cc.GetStatus().GetDevice()
	if plan == nil || len(plan.Probes) == 0 {
		return nil
	}

	ownerUID, ok := getProbeOwnerFilter(dev, now)
	if !ok {
		return nil
	}

	inputMap := map[string]any{
		"ctx": map[string]any{
			"user":   pbutils.MustConvertToMap(usr),
			"device": pbutils.MustConvertToMap(dev),
		},
	}

	var ret []*corev1.ClusterConfig_Status_Device_Probe
	seen := make(map[string]struct{})

	for _, p := range plan.Probes {
		if p == nil || p.OwnerRef.GetUid() == "" || !rgxProbeID.MatchString(p.Id) {
			continue
		}

		if ownerUID != "" && p.OwnerRef.Uid != ownerUID {
			continue
		}

		if _, ok := seen[p.Id]; ok {
			continue
		}

		if len(p.OsTypes) > 0 && !slices.Contains(p.OsTypes, dev.Status.OsType) {
			continue
		}

		if p.Type == nil {
			continue
		}

		if p.Condition != nil {
			ok, err := s.celEngine.EvalCondition(ctx, p.Condition, inputMap)
			if err != nil {
				zap.L().Warn("Could not evaluate probe condition",
					zap.String("probeID", p.Id), zap.Error(err))
				continue
			}
			if !ok {
				continue
			}
		}

		if len(ret) >= maxProbesPerAttempt {
			zap.L().Warn("The number of the applicable probes exceeds the maximum number of probes per attempt",
				zap.String("device", dev.Metadata.Name), zap.Int("maxProbes", maxProbesPerAttempt))
			break
		}

		cloned := pbutils.Clone(p).(*corev1.ClusterConfig_Status_Device_Probe)
		cloned.Condition = nil
		seen[p.Id] = struct{}{}
		ret = append(ret, cloned)
	}

	return ret
}

func getProbeOwnerFilter(dev *corev1.Device, now time.Time) (string, bool) {
	binding := dev.Status.Binding
	if binding == nil || binding.State != corev1.Device_Status_Binding_ACCEPTED {
		return "", true
	}

	if binding.Validity != corev1.Device_Status_Binding_VALID {
		return binding.OwnerRef.GetUid(), true
	}

	nextAt := binding.NextVerificationAt
	if nextAt.IsValid() && !now.Before(nextAt.AsTime()) {
		return binding.OwnerRef.GetUid(), true
	}

	return "", false
}

func (s *server) doRunDeviceProbeFinish(ctx context.Context,
	req *authv1.RunDeviceProbeFinishRequest) (*authv1.RunDeviceProbeFinishResponse, error) {

	if err := s.validateRunDeviceProbeFinish(req); err != nil {
		return nil, grpcutils.InvalidArg("Invalid request: %v", err)
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

	if sess.Status.DeviceRef == nil {
		return nil, grpcutils.InvalidArg("No Device is associated with this Session")
	}

	_, dev, err := s.getProbeUserAndDevice(ctx, sess)
	if err != nil {
		return nil, err
	}

	attempt := dev.Status.ProbeAttempt
	if attempt == nil || attempt.Uid != req.AttemptUID {
		return nil, grpcutils.InvalidArg("No matching pending probe attempt for this Device")
	}

	if attempt.SessionRef.GetUid() != sess.Metadata.Uid {
		return nil, grpcutils.PermissionDenied("The probe attempt belongs to another Session")
	}

	results, err := getProbeAttemptResults(attempt, req.Results)
	if err != nil {
		return nil, grpcutils.InvalidArg("Invalid results: %v", err)
	}

	switch attempt.State {
	case corev1.Device_Status_ProbeAttempt_ISSUED:
	case corev1.Device_Status_ProbeAttempt_SUBMITTED,
		corev1.Device_Status_ProbeAttempt_PROCESSED:
		if isProbeAttemptResultsEqual(attempt.Results, results) {
			return &authv1.RunDeviceProbeFinishResponse{}, nil
		}
		return nil, grpcutils.InvalidArg("Probe attempt results have already been submitted")
	default:
		return nil, grpcutils.InvalidArg("Invalid probe attempt state")
	}

	now := time.Now()

	if isProbeAttemptExpired(attempt, now) {
		dev.Status.ProbeAttempt = nil
		if _, uErr := s.octeliumC.CoreC().UpdateDevice(ctx, dev); uErr != nil {
			return nil, uErr
		}
		return nil, grpcutils.InvalidArg("Probe attempt expired")
	}

	attempt.Results = results
	attempt.State = corev1.Device_Status_ProbeAttempt_SUBMITTED
	attempt.SubmittedAt = pbutils.Timestamp(now)

	if _, err := s.octeliumC.CoreC().UpdateDevice(ctx, dev); err != nil {
		return nil, err
	}

	return &authv1.RunDeviceProbeFinishResponse{}, nil
}

func getProbeAttemptResults(attempt *corev1.Device_Status_ProbeAttempt,
	results []*authv1.DeviceProbeResult) ([]*corev1.Device_Status_ProbeAttempt_Result, error) {

	if len(results) != len(attempt.Probes) {
		return nil, errors.Errorf("Invalid results len")
	}

	probes := make(map[string]*corev1.ClusterConfig_Status_Device_Probe, len(attempt.Probes))
	for _, p := range attempt.Probes {
		probes[p.Id] = p
	}

	seen := make(map[string]struct{}, len(results))
	totalBytes := 0

	var ret []*corev1.Device_Status_ProbeAttempt_Result

	for _, r := range results {
		probe, ok := probes[r.ProbeID]
		if !ok {
			return nil, errors.Errorf("Unknown probeID: %s", r.ProbeID)
		}

		if _, ok := seen[r.ProbeID]; ok {
			return nil, errors.Errorf("Duplicate probeID: %s", r.ProbeID)
		}
		seen[r.ProbeID] = struct{}{}

		size := getProbeResultSize(r)
		if size > probeMaxOutputBytes(probe) {
			return nil, errors.Errorf("Output is too large for probeID: %s", r.ProbeID)
		}

		totalBytes += size
		if totalBytes > probeMaxTotalBytes {
			return nil, errors.Errorf("Total output is too large")
		}

		ret = append(ret, toCoreProbeResult(r))
	}

	return ret, nil
}

func isProbeAttemptResultsEqual(a, b []*corev1.Device_Status_ProbeAttempt_Result) bool {
	if len(a) != len(b) {
		return false
	}

	resultMap := make(map[string]*corev1.Device_Status_ProbeAttempt_Result, len(a))
	for _, r := range a {
		resultMap[r.ProbeID] = r
	}

	for _, r := range b {
		existing, ok := resultMap[r.ProbeID]
		if !ok || !pbutils.IsEqual(existing, r) {
			return false
		}
	}

	return true
}

func getProbeResultSize(r *authv1.DeviceProbeResult) int {
	switch r.Value.(type) {
	case *authv1.DeviceProbeResult_Text:
		return len(r.GetText())
	case *authv1.DeviceProbeResult_Data:
		return len(r.GetData())
	case *authv1.DeviceProbeResult_List_:
		ret := 0
		for _, itm := range r.GetList().GetItems() {
			ret += len(itm)
		}
		return ret
	default:
		return 0
	}
}

func toCoreProbeResult(r *authv1.DeviceProbeResult) *corev1.Device_Status_ProbeAttempt_Result {
	ret := &corev1.Device_Status_ProbeAttempt_Result{
		ProbeID:     r.ProbeID,
		Status:      corev1.Device_Status_ProbeAttempt_Result_Status(r.Status),
		IsTruncated: r.IsTruncated,
		ExitCode:    r.ExitCode,
		Detail:      r.Detail,
	}

	switch t := r.Value.(type) {
	case *authv1.DeviceProbeResult_Text:
		ret.Value = &corev1.Device_Status_ProbeAttempt_Result_Text{Text: t.Text}
	case *authv1.DeviceProbeResult_Data:
		ret.Value = &corev1.Device_Status_ProbeAttempt_Result_Data{Data: t.Data}
	case *authv1.DeviceProbeResult_List_:
		ret.Value = &corev1.Device_Status_ProbeAttempt_Result_List_{
			List: &corev1.Device_Status_ProbeAttempt_Result_List{
				Items: t.List.GetItems(),
			},
		}
	}

	return ret
}

func toAuthProbes(probes []*corev1.ClusterConfig_Status_Device_Probe) []*authv1.DeviceProbe {
	out := make([]*authv1.DeviceProbe, 0, len(probes))
	for _, p := range probes {
		out = append(out, toAuthProbe(p))
	}
	return out
}

func toAuthProbe(p *corev1.ClusterConfig_Status_Device_Probe) *authv1.DeviceProbe {
	wp := &authv1.DeviceProbe{
		ProbeID:          p.Id,
		RequireElevation: p.RequireElevation,
	}
	switch t := p.Type.(type) {
	case *corev1.ClusterConfig_Status_Device_Probe_RunCommand_:
		wp.Type = &authv1.DeviceProbe_RunCommand_{RunCommand: &authv1.DeviceProbe_RunCommand{
			Command:        t.RunCommand.Command,
			Args:           t.RunCommand.Args,
			TimeoutSeconds: t.RunCommand.TimeoutSeconds,
			MaxOutputBytes: t.RunCommand.MaxOutputBytes,
		}}
	case *corev1.ClusterConfig_Status_Device_Probe_ReadFile_:
		wp.Type = &authv1.DeviceProbe_ReadFile_{ReadFile: &authv1.DeviceProbe_ReadFile{
			Path:     t.ReadFile.Path,
			MaxBytes: t.ReadFile.MaxBytes,
		}}
	case *corev1.ClusterConfig_Status_Device_Probe_ReadRegistry_:
		wp.Type = &authv1.DeviceProbe_ReadRegistry_{ReadRegistry: &authv1.DeviceProbe_ReadRegistry{
			Key:  t.ReadRegistry.Key,
			Name: t.ReadRegistry.Name,
		}}
	case *corev1.ClusterConfig_Status_Device_Probe_PlatformIdentifier_:
		wp.Type = &authv1.DeviceProbe_PlatformIdentifier_{PlatformIdentifier: &authv1.DeviceProbe_PlatformIdentifier{
			Kind: authv1.DeviceProbe_PlatformIdentifier_Kind(t.PlatformIdentifier.Kind),
		}}
	}
	return wp
}

func probeMaxOutputBytes(p *corev1.ClusterConfig_Status_Device_Probe) int {
	declared := 0
	switch t := p.Type.(type) {
	case *corev1.ClusterConfig_Status_Device_Probe_RunCommand_:
		declared = int(t.RunCommand.MaxOutputBytes)
	case *corev1.ClusterConfig_Status_Device_Probe_ReadFile_:
		declared = int(t.ReadFile.MaxBytes)
	}

	if declared <= 0 {
		return defaultProbeMaxOutputBytes
	}
	if declared > hardProbeMaxOutputBytes {
		return hardProbeMaxOutputBytes
	}
	return declared
}

func (s *server) validateRunDeviceProbeBegin(req *authv1.RunDeviceProbeBeginRequest) error {
	if req == nil {
		return errors.Errorf("Nil req")
	}

	return nil
}

func (s *server) validateRunDeviceProbeFinish(req *authv1.RunDeviceProbeFinishRequest) error {
	if req == nil {
		return errors.Errorf("Nil req")
	}

	if !rgxProbeAttemptUID.MatchString(req.AttemptUID) {
		return errors.Errorf("Invalid attemptUID")
	}

	if len(req.Results) == 0 {
		return errors.Errorf("Empty results")
	}

	if len(req.Results) > maxProbesPerAttempt {
		return errors.Errorf("Too many results")
	}

	for _, r := range req.Results {
		if r == nil {
			return errors.Errorf("Nil result")
		}

		if !rgxProbeID.MatchString(r.ProbeID) {
			return errors.Errorf("Invalid probeID: %s", r.ProbeID)
		}

		if r.Status == authv1.DeviceProbeResult_STATUS_UNKNOWN {
			return errors.Errorf("Unknown result status")
		}

		if _, ok := authv1.DeviceProbeResult_Status_name[int32(r.Status)]; !ok {
			return errors.Errorf("Invalid result status")
		}

		if len(r.Detail) > maxProbeResultDetailLen {
			return errors.Errorf("Detail is too large")
		}

		switch r.Value.(type) {
		case nil:
		case *authv1.DeviceProbeResult_Text,
			*authv1.DeviceProbeResult_Data:
			if getProbeResultSize(r) > hardProbeMaxOutputBytes {
				return errors.Errorf("Output is too large")
			}
		case *authv1.DeviceProbeResult_List_:
			items := r.GetList().GetItems()
			if len(items) > maxProbeResultListItems {
				return errors.Errorf("Too many list items")
			}
			for _, itm := range items {
				if len(itm) > maxProbeResultListItemLen {
					return errors.Errorf("List item is too large")
				}
			}
		default:
			return errors.Errorf("Invalid result value type")
		}
	}

	return nil
}
