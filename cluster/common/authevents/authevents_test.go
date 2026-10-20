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
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rpubsubv1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakePubSub struct {
	rpubsubv1.MainServiceClient

	mu    sync.Mutex
	reqs  []*rpubsubv1.PublishRequest
	err   error
	noIDs bool
}

func (c *fakePubSub) Publish(ctx context.Context,
	req *rpubsubv1.PublishRequest, opts ...grpc.CallOption) (*rpubsubv1.PublishResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reqs = append(c.reqs, req)
	if c.err != nil {
		return nil, c.err
	}

	ret := &rpubsubv1.PublishResponse{}
	if !c.noIDs {
		for range req.Messages {
			ret.Ids = append(ret.Ids, []byte("1-0"))
		}
	}

	return ret, nil
}

func (c *fakePubSub) getReqs() []*rpubsubv1.PublishRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]*rpubsubv1.PublishRequest{}, c.reqs...)
}

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	pubSubC *fakePubSub
}

func (c *fakeOcteliumC) PubSubC() rpubsubv1.MainServiceClient {
	return c.pubSubC
}

func newObjRef(kind string) *metav1.ObjectReference {
	return &metav1.ObjectReference{
		ApiVersion: "core/v1",
		Kind:       kind,
		Name:       utilrand.GetRandomStringCanonical(8),
		Uid:        utilrand.GetRandomStringCanonical(16),
	}
}

func newVerifiedAttempt(ctx context.Context) (context.Context, *Attempt) {
	ctx, attempt := NewAttempt(ctx, corev1.Session_Status_Authentication_Info_REFRESH_TOKEN, nil)
	attempt.SetVerified()
	attempt.SetSessionRef(newObjRef("Session"))
	return ctx, attempt
}

func TestFailureMessage(t *testing.T) {
	{
		failure := &Failure{
			Reason:     ReasonUserNotFound,
			CreatedAt:  time.Now().Add(-1 * time.Minute),
			SessionRef: newObjRef("Session"),
			UserRef:    newObjRef("User"),
			DeviceRef:  newObjRef("Device"),
			Info: &corev1.Session_Status_Authentication_Info{
				Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
				Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
					IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
						IdentityProviderRef: newObjRef("IdentityProvider"),
						Type:                corev1.IdentityProvider_Status_OIDC,
						Identifier:          "john@example.com",
					},
				},
				Downstream: &corev1.Session_Status_Authentication_Info_Downstream{
					IpAddress: "203.0.113.7",
					UserAgent: "octelium-cli/1.2.3 linux",
				},
			},
		}

		msg, err := failure.ToMessage()
		assert.Nil(t, err)
		assert.NotNil(t, msg.GetContent())
		assert.Equal(t, string(ReasonUserNotFound), msg.GetContent().AsMap()["reason"])

		parsed, err := ParseFailure(msg)
		assert.Nil(t, err)
		assert.Equal(t, failure.Reason, parsed.Reason)
		assert.True(t, failure.CreatedAt.Equal(parsed.CreatedAt))
		assert.True(t, pbutils.IsEqual(failure.SessionRef, parsed.SessionRef))
		assert.True(t, pbutils.IsEqual(failure.UserRef, parsed.UserRef))
		assert.True(t, pbutils.IsEqual(failure.DeviceRef, parsed.DeviceRef))
		assert.True(t, pbutils.IsEqual(failure.Info, parsed.Info))
	}

	{
		failure := &Failure{
			Reason:    ReasonInvalidCredential,
			CreatedAt: time.Now(),
		}

		msg, err := failure.ToMessage()
		assert.Nil(t, err)

		parsed, err := ParseFailure(msg)
		assert.Nil(t, err)
		assert.Equal(t, ReasonInvalidCredential, parsed.Reason)
		assert.Nil(t, parsed.SessionRef)
		assert.Nil(t, parsed.UserRef)
		assert.Nil(t, parsed.Info)
	}

	{
		_, err := ParseFailure(&rpubsubv1.Message{
			Type: &rpubsubv1.Message_Data{
				Data: []byte("data"),
			},
		})
		assert.NotNil(t, err)
	}

	{
		msg := &rpubsubv1.Message{
			CreatedAt: pbutils.Now(),
			Type: &rpubsubv1.Message_Content{
				Content: pbutils.MapToStructMust(map[string]any{
					"reason": "SOME_FUTURE_REASON",
					"info": map[string]any{
						"type":         "CREDENTIAL",
						"unknownField": "value",
					},
				}),
			},
		}

		parsed, err := ParseFailure(msg)
		assert.Nil(t, err)
		assert.Equal(t, Reason("SOME_FUTURE_REASON"), parsed.Reason)
		assert.True(t, msg.CreatedAt.AsTime().Equal(parsed.CreatedAt))
		assert.Equal(t, corev1.Session_Status_Authentication_Info_CREDENTIAL, parsed.Info.Type)
	}

	{
		_, err := ParseFailure(&rpubsubv1.Message{
			Type: &rpubsubv1.Message_Content{
				Content: pbutils.MapToStructMust(map[string]any{
					"reason": string(ReasonInvalidCredential),
				}),
			},
		})
		assert.NotNil(t, err)
	}

	{
		_, err := ParseFailure(&rpubsubv1.Message{
			CreatedAt: pbutils.Now(),
			Type: &rpubsubv1.Message_Content{
				Content: pbutils.MapToStructMust(map[string]any{
					"reason":     string(ReasonInvalidCredential),
					"sessionRef": map[string]any{"uid": 1},
				}),
			},
		})
		assert.NotNil(t, err)
	}
}

func TestAttempt(t *testing.T) {
	ctx := context.Background()

	assert.Nil(t, GetAttempt(ctx))

	{
		var attempt *Attempt
		attempt.SetVerified()
		attempt.SetReason(ReasonExpiredCredential)
		attempt.Commit()
		assert.Nil(t, attempt.For(corev1.Session_Status_Authentication_Info_CREDENTIAL))
		failure, _ := attempt.getFailure(errors.New("err"))
		assert.Nil(t, failure)
	}

	{
		cc := &corev1.ClusterConfig{
			Spec: &corev1.ClusterConfig_Spec{
				Ingress: &corev1.ClusterConfig_Spec_Ingress{
					UseForwardedForHeader: true,
				},
			},
		}

		attemptCtx, attempt := NewAttempt(ctx, corev1.Session_Status_Authentication_Info_CREDENTIAL, &AttemptOpts{
			UserAgent:     "octelium-cli/1.2.3 linux",
			ClientAddr:    "203.0.113.7",
			ClusterConfig: cc,
		})
		assert.Equal(t, attempt, GetAttempt(attemptCtx))
		assert.Equal(t, attempt, GetAttempt(attemptCtx).For(
			corev1.Session_Status_Authentication_Info_REFRESH_TOKEN,
			corev1.Session_Status_Authentication_Info_CREDENTIAL))
		assert.Nil(t, GetAttempt(attemptCtx).For(corev1.Session_Status_Authentication_Info_REFRESH_TOKEN))

		failure, _ := attempt.getFailure(grpcutils.Unauthenticated(""))
		assert.Nil(t, failure)

		attempt.SetEligible()
		failure, isVerified := attempt.getFailure(grpcutils.Unauthenticated(""))
		assert.NotNil(t, failure)
		assert.False(t, isVerified)
		assert.Equal(t, Reason(""), failure.Reason)
		assert.Equal(t, "203.0.113.7", failure.Info.Downstream.IpAddress)
		assert.Equal(t, "octelium-cli/1.2.3 linux", failure.Info.Downstream.UserAgent)
		assert.Equal(t, "1.2.3", failure.Info.Downstream.ClientVersion)

		failure, _ = attempt.getFailure(grpcutils.Internal(""))
		assert.Equal(t, ReasonInternalError, failure.Reason)

		failure, _ = attempt.getFailure(errors.New("plain error"))
		assert.Equal(t, ReasonInternalError, failure.Reason)

		failure, _ = attempt.getFailure(context.Canceled)
		assert.Nil(t, failure)

		failure, _ = attempt.getFailure(status.Error(codes.Canceled, ""))
		assert.Nil(t, failure)

		failure, _ = attempt.getFailure(nil)
		assert.Nil(t, failure)

		attempt.SetReason(ReasonRevokedCredential)
		attempt.SetReason(ReasonInvalidCredential)
		credRef := newObjRef("Credential")
		attempt.SetCredential(&corev1.Session_Status_Authentication_Info_Credential{
			CredentialRef: credRef,
		})
		usrRef := newObjRef("User")
		attempt.SetUserRef(usrRef)
		attempt.SetVerified()

		failure, isVerified = attempt.getFailure(grpcutils.Internal(""))
		assert.True(t, isVerified)
		assert.Equal(t, ReasonRevokedCredential, failure.Reason)
		assert.True(t, pbutils.IsEqual(credRef, failure.Info.GetCredential().CredentialRef))
		assert.True(t, pbutils.IsEqual(usrRef, failure.UserRef))
		assert.Equal(t, corev1.Session_Status_Authentication_Info_CREDENTIAL, failure.Info.Type)

		failure.Info.Type = corev1.Session_Status_Authentication_Info_AUTHENTICATOR
		failure, _ = attempt.getFailure(grpcutils.Internal(""))
		assert.Equal(t, corev1.Session_Status_Authentication_Info_CREDENTIAL, failure.Info.Type)

		attempt.Commit()
		failure, _ = attempt.getFailure(grpcutils.Internal(""))
		assert.Nil(t, failure)
	}

	{
		_, attempt := NewAttempt(ctx, corev1.Session_Status_Authentication_Info_AUTHENTICATOR, &AttemptOpts{
			UserAgent:  "Mozilla/5.0",
			ClientAddr: "203.0.113.7",
			ClusterConfig: &corev1.ClusterConfig{
				Spec: &corev1.ClusterConfig_Spec{},
			},
		})
		attempt.SetVerified()

		sess := &corev1.Session{
			ApiVersion: "core/v1",
			Kind:       "Session",
			Metadata: &metav1.Metadata{
				Name: "sess",
				Uid:  utilrand.GetRandomStringCanonical(16),
			},
			Status: &corev1.Session_Status{
				UserRef:   newObjRef("User"),
				DeviceRef: newObjRef("Device"),
			},
		}
		attempt.SetSession(sess)

		failure, _ := attempt.getFailure(grpcutils.PermissionDenied(""))
		assert.Equal(t, "", failure.Info.Downstream.IpAddress)
		assert.Equal(t, "Mozilla/5.0", failure.Info.Downstream.UserAgent)
		assert.Equal(t, sess.Metadata.Uid, failure.SessionRef.Uid)
		assert.True(t, pbutils.IsEqual(sess.Status.UserRef, failure.UserRef))
		assert.True(t, pbutils.IsEqual(sess.Status.DeviceRef, failure.DeviceRef))
	}

	{
		_, attempt := NewAttempt(ctx, corev1.Session_Status_Authentication_Info_AUTHENTICATOR, &AttemptOpts{
			UserAgent: utilrand.GetRandomString(maxUserAgentLen),
		})
		attempt.SetEligible()

		failure, _ := attempt.getFailure(grpcutils.PermissionDenied(""))
		assert.Nil(t, failure.Info.Downstream)
	}
}

func TestPublisher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	{
		pubSubC := &fakePubSub{}
		p := NewPublisher(&PublisherOpts{
			OcteliumC: &fakeOcteliumC{
				pubSubC: pubSubC,
			},
		})

		var nilPublisher *Publisher
		assert.False(t, nilPublisher.Finish(nil, grpcutils.Internal("")))

		_, attempt := NewAttempt(ctx, corev1.Session_Status_Authentication_Info_REFRESH_TOKEN, nil)
		assert.False(t, p.Finish(attempt, grpcutils.Internal("")))

		_, attempt = newVerifiedAttempt(ctx)
		attempt.SetReason(ReasonRevokedCredential)
		for range keyLimit {
			assert.True(t, p.Finish(attempt, grpcutils.Unauthenticated("")))
		}
		assert.False(t, p.Finish(attempt, grpcutils.Unauthenticated("")))

		_, attempt = newVerifiedAttempt(ctx)
		assert.True(t, p.Finish(attempt, grpcutils.Unauthenticated("")))

		p.Run(ctx)

		assert.Eventually(t, func() bool {
			count := 0
			for _, req := range pubSubC.getReqs() {
				count += len(req.Messages)
			}
			return count == keyLimit+1
		}, 10*time.Second, 50*time.Millisecond)

		for _, req := range pubSubC.getReqs() {
			assert.Equal(t, TopicFailure, string(req.Topic))
			assert.True(t, req.IfExists)
			assert.Equal(t, uint32(topicMaxLength), req.MaxLength)
			assert.True(t, len(req.Messages) <= publisherMaxBatch)
			for _, msg := range req.Messages {
				failure, err := ParseFailure(msg)
				assert.Nil(t, err)
				assert.Equal(t, corev1.Session_Status_Authentication_Info_REFRESH_TOKEN, failure.Info.Type)
			}
		}
	}

	{
		p := NewPublisher(&PublisherOpts{
			OcteliumC: &fakeOcteliumC{
				pubSubC: &fakePubSub{},
			},
		})

		admitted := 0
		for range verifiedBurst * 2 {
			_, attempt := newVerifiedAttempt(ctx)
			if p.Finish(attempt, grpcutils.Unauthenticated("")) {
				admitted++
			}
		}
		assert.True(t, admitted >= verifiedBurst && admitted < verifiedBurst+10, admitted)

		admitted = 0
		for range unverifiedBurst * 2 {
			_, attempt := NewAttempt(ctx, corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER, nil)
			attempt.SetEligible()
			attempt.SetIdentityProvider(&corev1.Session_Status_Authentication_Info_IdentityProvider{
				IdentityProviderRef: newObjRef("IdentityProvider"),
			})
			if p.Finish(attempt, grpcutils.Unauthenticated("")) {
				admitted++
			}
		}
		assert.True(t, admitted >= unverifiedBurst && admitted < unverifiedBurst+5, admitted)
	}

	{
		pubSubC := &fakePubSub{
			noIDs: true,
		}
		p := NewPublisher(&PublisherOpts{
			OcteliumC: &fakeOcteliumC{
				pubSubC: pubSubC,
			},
		})
		p.Run(ctx)

		_, attempt := newVerifiedAttempt(ctx)
		assert.True(t, p.Finish(attempt, grpcutils.Unauthenticated("")))

		assert.Eventually(t, func() bool {
			return len(pubSubC.getReqs()) == 1 && time.Now().UnixNano() < p.pausedUntil.Load()
		}, 10*time.Second, 50*time.Millisecond)

		_, attempt = newVerifiedAttempt(ctx)
		assert.False(t, p.Finish(attempt, grpcutils.Unauthenticated("")))
	}

	{
		pubSubC := &fakePubSub{
			err: status.Error(codes.Unimplemented, ""),
		}
		p := NewPublisher(&PublisherOpts{
			OcteliumC: &fakeOcteliumC{
				pubSubC: pubSubC,
			},
		})
		p.Run(ctx)

		_, attempt := newVerifiedAttempt(ctx)
		assert.True(t, p.Finish(attempt, grpcutils.Unauthenticated("")))

		assert.Eventually(t, func() bool {
			return len(pubSubC.getReqs()) == 1 &&
				time.Until(time.Unix(0, p.pausedUntil.Load())) > pauseNoSubscriber
		}, 10*time.Second, 50*time.Millisecond)
	}

	{
		pubSubC := &fakePubSub{
			err: status.Error(codes.Unavailable, ""),
		}
		p := NewPublisher(&PublisherOpts{
			OcteliumC: &fakeOcteliumC{
				pubSubC: pubSubC,
			},
		})
		p.Run(ctx)

		_, attempt := newVerifiedAttempt(ctx)
		assert.True(t, p.Finish(attempt, grpcutils.Unauthenticated("")))

		assert.Eventually(t, func() bool {
			return len(pubSubC.getReqs()) == 1
		}, 10*time.Second, 50*time.Millisecond)

		_, attempt = newVerifiedAttempt(ctx)
		assert.True(t, p.Finish(attempt, grpcutils.Unauthenticated("")))
	}

	{
		p := NewPublisher(&PublisherOpts{
			OcteliumC: &fakeOcteliumC{
				pubSubC: &fakePubSub{},
			},
		})

		p.verifiedLimiter = rate.NewLimiter(rate.Inf, 0)

		admitted := 0
		for range publisherQueueSize + 10 {
			_, attempt := newVerifiedAttempt(ctx)
			if p.Finish(attempt, grpcutils.Unauthenticated("")) {
				admitted++
			}
		}
		assert.Equal(t, publisherQueueSize, admitted)
	}
}
