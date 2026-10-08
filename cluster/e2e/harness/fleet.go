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

package harness

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxSessionsPerUser   = 10000
	fleetAuthAttempts    = 6
	fleetCredentialTTL   = 24 * time.Hour
	fleetSessionSlack    = 32
	fleetDefaultParallel = 16
)

type FleetOpts struct {
	Sessions      int
	Users         int
	Concurrency   int
	SessionType   corev1.Session_Status_Type
	Authorization *corev1.User_Spec_Authorization
}

type FleetSession struct {
	UID          string
	User         *corev1.User
	AccessToken  string
	RefreshToken string
	CreatedAt    time.Time
}

type Fleet struct {
	h    *H
	opts FleetOpts

	Users       []*corev1.User
	Sessions    []*FleetSession
	Credentials []*corev1.Credential

	Auth *PoolResult

	tokens []string
	authC  authv1.MainServiceClient
	conn   *grpc.ClientConn
}

func SessionUIDFromToken(tkn string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(tkn)
	if err != nil {
		return "", errors.Errorf("Could not decode the token: %+v", err)
	}

	if len(raw) < 2 || raw[0] != 0x1 {
		return "", errors.Errorf("Unknown token format")
	}

	parsed := &authv1.TokenT0{}
	if err := pbutils.Unmarshal(raw[1:], parsed); err != nil {
		return "", errors.Errorf("Could not parse the token: %+v", err)
	}

	uid, err := uuid.FromBytes(parsed.GetContent().GetSubject())
	if err != nil {
		return "", errors.Errorf("Could not read the token subject: %+v", err)
	}

	return uid.String(), nil
}

func (h *H) AuthConn() (*grpc.ClientConn, error) {
	dialer, err := h.IngressDialer(h.APIServerName())
	if err != nil {
		return nil, err
	}

	return dialer.GRPCConn()
}

func (h *H) NewFleet(ctx context.Context, o FleetOpts) (*Fleet, error) {
	if o.Sessions <= 0 {
		return nil, errors.Errorf("A fleet needs at least one Session")
	}
	if o.Users <= 0 {
		o.Users = 1
	}
	if o.SessionType == corev1.Session_Status_TYPE_UNKNOWN {
		o.SessionType = corev1.Session_Status_CLIENT
	}
	if o.Concurrency <= 0 {
		o.Concurrency = fleetDefaultParallel
	}

	o.Users = min(o.Users, o.Sessions)

	perUser := (o.Sessions + o.Users - 1) / o.Users
	if perUser+fleetSessionSlack > maxSessionsPerUser {
		return nil, errors.Errorf(
			"%d Sessions over %d Users exceeds the limit of %d Sessions per User",
			o.Sessions, o.Users, maxSessionsPerUser)
	}

	workersPerUser := max(1, (o.Concurrency+o.Users-1)/o.Users)

	conn, err := h.AuthConn()
	if err != nil {
		return nil, err
	}

	ret := &Fleet{
		h:     h,
		opts:  o,
		conn:  conn,
		authC: authv1.NewMainServiceClient(conn),
	}

	prefix := fmt.Sprintf("chaos-%s", utilrand.GetRandomStringCanonical(6))

	for i := range o.Users {
		usr, err := h.coreC.CreateUser(ctx, &corev1.User{
			Metadata: &metav1.Metadata{Name: fmt.Sprintf("%s-%d", prefix, i)},
			Spec: &corev1.User_Spec{
				Type:          corev1.User_Spec_WORKLOAD,
				Authorization: o.Authorization,
				Session: &corev1.User_Spec_Session{
					MaxPerUser: uint32(min(maxSessionsPerUser, perUser*2+fleetSessionSlack)),
				},
			},
		})
		if err != nil {
			ret.Close(context.Background())
			return nil, errors.Errorf("Could not create the fleet User %d: %+v", i, err)
		}
		ret.Users = append(ret.Users, usr)
	}

	for _, usr := range ret.Users {
		for j := range workersPerUser {
			cred, err := h.coreC.CreateCredential(ctx, &corev1.Credential{
				Metadata: &metav1.Metadata{
					Name: fmt.Sprintf("%s-%d", usr.Metadata.Name, j),
				},
				Spec: &corev1.Credential_Spec{
					Type:        corev1.Credential_Spec_AUTH_TOKEN,
					User:        usr.Metadata.Name,
					SessionType: o.SessionType,
					ExpiresAt:   pbutils.Timestamp(time.Now().Add(fleetCredentialTTL)),
				},
			})
			if err != nil {
				ret.Close(context.Background())
				return nil, errors.Errorf("Could not create a fleet Credential: %+v", err)
			}
			ret.Credentials = append(ret.Credentials, cred)

			tkn, err := h.coreC.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
				CredentialRef: umetav1.GetObjectReference(cred),
			})
			if err != nil {
				ret.Close(context.Background())
				return nil, errors.Errorf("Could not generate a fleet Credential token: %+v", err)
			}

			ret.tokens = append(ret.tokens, tkn.GetAuthenticationToken().GetAuthenticationToken())
		}
	}

	if err := ret.authenticate(ctx); err != nil {
		if len(ret.Sessions) == 0 {
			ret.Close(context.Background())
			return nil, err
		}
		return ret, err
	}

	zap.L().Info("Created the fleet",
		zap.Int("users", len(ret.Users)),
		zap.Int("credentials", len(ret.Credentials)),
		zap.Int("sessions", len(ret.Sessions)),
		zap.String("auth", ret.Auth.String()))

	return ret, nil
}

func isRetryableAuthErr(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted:
		return true
	default:
		return false
	}
}

func (f *Fleet) authenticate(ctx context.Context) error {
	workers := len(f.tokens)

	var mu sync.Mutex
	var next atomic.Int64

	result := &PoolResult{
		Total:   f.opts.Sessions,
		Latency: &Latencies{},
		Errors:  NewErrorCounter(),
	}

	var wg sync.WaitGroup
	started := time.Now()

	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			usr := f.Users[(w*len(f.Users))/workers]
			tkn := f.tokens[w]

			for {
				if int(next.Add(1)) > f.opts.Sessions || ctx.Err() != nil {
					return
				}

				opStarted := time.Now()
				sess, err := f.authenticateOne(ctx, usr, tkn)
				if err != nil {
					result.Errors.Add(err)
					continue
				}

				result.Latency.Add(time.Since(opStarted))

				mu.Lock()
				f.Sessions = append(f.Sessions, sess)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	result.Elapsed = time.Since(started)
	result.Succeeded = len(f.Sessions)
	f.Auth = result

	if result.Succeeded < f.opts.Sessions {
		return errors.Errorf("Only %d of %d fleet Sessions authenticated: %s",
			result.Succeeded, f.opts.Sessions, result.Errors)
	}

	return nil
}

func (f *Fleet) authenticateOne(ctx context.Context, usr *corev1.User, tkn string) (*FleetSession, error) {
	var lastErr error

	for attempt := 1; attempt <= fleetAuthAttempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		res, err := f.authC.AuthenticateWithAuthenticationToken(attemptCtx,
			&authv1.AuthenticateWithAuthenticationTokenRequest{AuthenticationToken: tkn})
		cancel()

		if err == nil {
			uid, err := SessionUIDFromToken(res.AccessToken)
			if err != nil {
				return nil, err
			}

			return &FleetSession{
				UID:          uid,
				User:         usr,
				AccessToken:  res.AccessToken,
				RefreshToken: res.RefreshToken,
				CreatedAt:    time.Now(),
			}, nil
		}

		lastErr = err
		if !isRetryableAuthErr(err) || ctx.Err() != nil {
			return nil, err
		}

		if err := Sleep(ctx, ReconnectBackoff(attempt, 500*time.Millisecond, 4*time.Second)); err != nil {
			return nil, lastErr
		}
	}

	return nil, lastErr
}

func (f *Fleet) AuthConn() *grpc.ClientConn { return f.conn }

func (f *Fleet) BySessionUID() map[string]*FleetSession {
	ret := make(map[string]*FleetSession, len(f.Sessions))
	for _, sess := range f.Sessions {
		ret[sess.UID] = sess
	}
	return ret
}

func (f *Fleet) UserUIDs() map[string]bool {
	ret := make(map[string]bool, len(f.Users))
	for _, usr := range f.Users {
		ret[usr.Metadata.Uid] = true
	}
	return ret
}

func (f *Fleet) Close(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	for _, cred := range f.Credentials {
		if _, err := f.h.coreC.DeleteCredential(ctx,
			&metav1.DeleteOptions{Uid: cred.Metadata.Uid}); err != nil && !grpcerr.IsNotFound(err) {
			zap.L().Warn("Could not delete a fleet Credential",
				zap.String("name", cred.Metadata.Name), zap.Error(err))
		}
	}

	for _, usr := range f.Users {
		if _, err := f.h.coreC.DeleteUser(ctx,
			&metav1.DeleteOptions{Uid: usr.Metadata.Uid}); err != nil && !grpcerr.IsNotFound(err) {
			zap.L().Warn("Could not delete a fleet User",
				zap.String("name", usr.Metadata.Name), zap.Error(err))
		}
	}

	if f.conn != nil {
		f.conn.Close()
	}
}
