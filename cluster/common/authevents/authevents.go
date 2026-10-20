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

package authevents

import (
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rpubsubv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const TopicFailure = "octelium.authentication.failure.v1"

type Reason string

const (
	ReasonInvalidCredential     Reason = "INVALID_CREDENTIAL"
	ReasonExpiredCredential     Reason = "EXPIRED_CREDENTIAL"
	ReasonRevokedCredential     Reason = "REVOKED_CREDENTIAL"
	ReasonUserNotFound          Reason = "USER_NOT_FOUND"
	ReasonUserDeactivated       Reason = "USER_DEACTIVATED"
	ReasonUserLocked            Reason = "USER_LOCKED"
	ReasonDeniedByRule          Reason = "DENIED_BY_RULE"
	ReasonNotAllowed            Reason = "NOT_ALLOWED"
	ReasonLimitExceeded         Reason = "LIMIT_EXCEEDED"
	ReasonIdentityProviderError Reason = "IDENTITY_PROVIDER_ERROR"
	ReasonInternalError         Reason = "INTERNAL_ERROR"
)

const (
	fieldReason     = "reason"
	fieldCreatedAt  = "createdAt"
	fieldSessionRef = "sessionRef"
	fieldUserRef    = "userRef"
	fieldDeviceRef  = "deviceRef"
	fieldInfo       = "info"
)

type Failure struct {
	Reason     Reason
	CreatedAt  time.Time
	SessionRef *metav1.ObjectReference
	UserRef    *metav1.ObjectReference
	DeviceRef  *metav1.ObjectReference
	Info       *corev1.Session_Status_Authentication_Info
}

func (f *Failure) ToMessage() (*rpubsubv1.Message, error) {
	contentMap := map[string]any{
		fieldReason:    string(f.Reason),
		fieldCreatedAt: f.CreatedAt.UTC().Format(time.RFC3339Nano),
	}

	for key, msg := range map[string]proto.Message{
		fieldSessionRef: f.SessionRef,
		fieldUserRef:    f.UserRef,
		fieldDeviceRef:  f.DeviceRef,
		fieldInfo:       f.Info,
	} {
		if msg == nil || !msg.ProtoReflect().IsValid() {
			continue
		}

		msgMap, err := pbutils.ConvertToMap(msg)
		if err != nil {
			return nil, err
		}

		contentMap[key] = msgMap
	}

	content, err := structpb.NewStruct(contentMap)
	if err != nil {
		return nil, err
	}

	return &rpubsubv1.Message{
		Type: &rpubsubv1.Message_Content{
			Content: content,
		},
	}, nil
}

func ParseFailure(msg *rpubsubv1.Message) (*Failure, error) {
	if msg.GetContent() == nil {
		return nil, errors.Errorf("The message has no content")
	}

	contentMap := msg.GetContent().AsMap()

	ret := &Failure{}

	reason, _ := contentMap[fieldReason].(string)
	ret.Reason = Reason(reason)

	if createdAt, ok := contentMap[fieldCreatedAt].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
			ret.CreatedAt = t
		}
	}

	if ret.CreatedAt.IsZero() && msg.CreatedAt.IsValid() {
		ret.CreatedAt = msg.CreatedAt.AsTime()
	}

	if ret.CreatedAt.IsZero() {
		return nil, errors.Errorf("The message has no creation time")
	}

	getMessage := func(key string, out proto.Message) (bool, error) {
		msgMap, ok := contentMap[key].(map[string]any)
		if !ok {
			return false, nil
		}

		if err := pbutils.UnmarshalFromMap(msgMap, out); err != nil {
			return false, errors.Errorf("Could not unmarshal %s: %+v", key, err)
		}

		return true, nil
	}

	for key, ref := range map[string]**metav1.ObjectReference{
		fieldSessionRef: &ret.SessionRef,
		fieldUserRef:    &ret.UserRef,
		fieldDeviceRef:  &ret.DeviceRef,
	} {
		out := &metav1.ObjectReference{}
		found, err := getMessage(key, out)
		if err != nil {
			return nil, err
		}
		if found {
			*ref = out
		}
	}

	{
		out := &corev1.Session_Status_Authentication_Info{}
		found, err := getMessage(fieldInfo, out)
		if err != nil {
			return nil, err
		}
		if found {
			ret.Info = out
		}
	}

	return ret, nil
}
