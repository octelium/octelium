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
	"context"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxUserAgentLen = 220

type attemptCtxKey struct{}

type AttemptOpts struct {
	UserAgent     string
	ClientAddr    string
	ClusterConfig *corev1.ClusterConfig
}

type Attempt struct {
	mu sync.Mutex

	createdAt  time.Time
	info       *corev1.Session_Status_Authentication_Info
	reason     Reason
	sessionRef *metav1.ObjectReference
	userRef    *metav1.ObjectReference
	deviceRef  *metav1.ObjectReference

	isEligible  bool
	isVerified  bool
	isCommitted bool
}

func NewAttempt(ctx context.Context,
	typ corev1.Session_Status_Authentication_Info_Type, o *AttemptOpts) (context.Context, *Attempt) {
	ret := &Attempt{
		createdAt: time.Now(),
		info: &corev1.Session_Status_Authentication_Info{
			Type: typ,
		},
	}

	if o != nil {
		ret.info.Downstream = getDownstream(o)
	}

	return context.WithValue(ctx, attemptCtxKey{}, ret), ret
}

func getDownstream(o *AttemptOpts) *corev1.Session_Status_Authentication_Info_Downstream {
	ret := &corev1.Session_Status_Authentication_Info_Downstream{}

	if o.ClientAddr != "" && govalidator.IsIP(o.ClientAddr) &&
		o.ClusterConfig != nil && o.ClusterConfig.Spec != nil &&
		o.ClusterConfig.Spec.Ingress != nil && o.ClusterConfig.Spec.Ingress.UseForwardedForHeader {
		ret.IpAddress = o.ClientAddr
	}

	if o.UserAgent != "" && len(o.UserAgent) < maxUserAgentLen {
		ret.UserAgent = o.UserAgent
		uaParts := strings.Split(o.UserAgent, " ")
		if len(uaParts) > 0 && strings.HasPrefix(uaParts[0], "octelium-cli/") {
			if args := strings.Split(uaParts[0], "/"); len(args) == 2 {
				ret.ClientVersion = args[1]
			}
		}
	}

	if ret.IpAddress == "" && ret.UserAgent == "" {
		return nil
	}

	return ret
}

func GetAttempt(ctx context.Context) *Attempt {
	ret, _ := ctx.Value(attemptCtxKey{}).(*Attempt)
	return ret
}

func (a *Attempt) For(types ...corev1.Session_Status_Authentication_Info_Type) *Attempt {
	if a == nil {
		return nil
	}

	for _, typ := range types {
		if a.info.Type == typ {
			return a
		}
	}

	return nil
}

func (a *Attempt) SetEligible() {
	if a == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.isEligible = true
}

func (a *Attempt) SetVerified() {
	if a == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.isEligible = true
	a.isVerified = true
}

func (a *Attempt) SetReason(reason Reason) {
	if a == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reason == "" {
		a.reason = reason
	}
}

func (a *Attempt) SetSessionRef(ref *metav1.ObjectReference) {
	if a == nil || ref == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessionRef = ref
}

func (a *Attempt) SetSession(sess *corev1.Session) {
	if a == nil || sess == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessionRef = umetav1.GetObjectReference(sess)
	if sess.Status != nil {
		if sess.Status.UserRef != nil {
			a.userRef = sess.Status.UserRef
		}
		if sess.Status.DeviceRef != nil {
			a.deviceRef = sess.Status.DeviceRef
		}
	}
}

func (a *Attempt) SetUserRef(ref *metav1.ObjectReference) {
	if a == nil || ref == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.userRef = ref
}

func (a *Attempt) SetUser(usr *corev1.User) {
	if a == nil || usr == nil {
		return
	}

	a.SetUserRef(umetav1.GetObjectReference(usr))
}

func (a *Attempt) SetIdentityProvider(arg *corev1.Session_Status_Authentication_Info_IdentityProvider) {
	if a == nil || arg == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.info.Details = &corev1.Session_Status_Authentication_Info_IdentityProvider_{
		IdentityProvider: arg,
	}
}

func (a *Attempt) SetCredential(arg *corev1.Session_Status_Authentication_Info_Credential) {
	if a == nil || arg == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.info.Details = &corev1.Session_Status_Authentication_Info_Credential_{
		Credential: arg,
	}
}

func (a *Attempt) SetAuthenticator(arg *corev1.Session_Status_Authentication_Info_Authenticator) {
	if a == nil || arg == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.info.Details = &corev1.Session_Status_Authentication_Info_Authenticator_{
		Authenticator: arg,
	}
}

func (a *Attempt) Commit() {
	if a == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.isCommitted = true
}

func (a *Attempt) getFailure(err error) (*Failure, bool) {
	if a == nil || err == nil {
		return nil, false
	}

	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return nil, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.isEligible || a.isCommitted {
		return nil, false
	}

	reason := a.reason
	if reason == "" {
		switch status.Code(err) {
		case codes.Internal, codes.Unknown, codes.Unavailable, codes.DeadlineExceeded:
			reason = ReasonInternalError
		}
	}

	return &Failure{
		Reason:     reason,
		CreatedAt:  a.createdAt,
		SessionRef: a.sessionRef,
		UserRef:    a.userRef,
		DeviceRef:  a.deviceRef,
		Info:       pbutils.Clone(a.info).(*corev1.Session_Status_Authentication_Info),
	}, a.isVerified
}
