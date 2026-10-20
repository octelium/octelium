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
	"fmt"
	"sync/atomic"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rpubsubv1"
	"github.com/octelium/octelium/cluster/common/geoipctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	publisherQueueSize = 512
	publisherMaxBatch  = 50
	publishTimeout     = 5 * time.Second

	verifiedRate      = 20
	verifiedBurst     = 100
	unverifiedRate    = 2
	unverifiedBurst   = 20
	keyLimit          = 20
	keyWindow         = 1 * time.Minute
	keyCleanupWindow  = 2 * time.Minute
	topicMaxLength    = 5000
	topicMaxAgeMinute = 60

	pauseNoSubscriber  = 1 * time.Minute
	pauseUnimplemented = 5 * time.Minute
)

type PublisherOpts struct {
	OcteliumC octeliumc.ClientInterface
	GeoIPCtl  *geoipctl.Controller
}

type Publisher struct {
	octeliumC octeliumc.ClientInterface
	geoipCtl  *geoipctl.Controller

	ch chan *Failure

	verifiedLimiter   *rate.Limiter
	unverifiedLimiter *rate.Limiter
	keys              *cache.Cache

	pausedUntil atomic.Int64
}

func NewPublisher(o *PublisherOpts) *Publisher {
	return &Publisher{
		octeliumC:         o.OcteliumC,
		geoipCtl:          o.GeoIPCtl,
		ch:                make(chan *Failure, publisherQueueSize),
		verifiedLimiter:   rate.NewLimiter(verifiedRate, verifiedBurst),
		unverifiedLimiter: rate.NewLimiter(unverifiedRate, unverifiedBurst),
		keys:              cache.New(keyWindow, keyCleanupWindow),
	}
}

func (p *Publisher) Run(ctx context.Context) {
	go p.run(ctx)
}

func (p *Publisher) Finish(a *Attempt, err error) bool {
	if p == nil {
		return false
	}

	failure, isVerified := a.getFailure(err)
	if failure == nil {
		return false
	}

	return p.emit(failure, isVerified)
}

func (p *Publisher) emit(failure *Failure, isVerified bool) bool {
	if time.Now().UnixNano() < p.pausedUntil.Load() {
		return false
	}

	key := getFailureKey(failure, isVerified)
	if count, found := p.keys.Get(key); found && count.(int) >= keyLimit {
		return false
	}

	limiter := p.unverifiedLimiter
	if isVerified {
		limiter = p.verifiedLimiter
	}

	if !limiter.Allow() {
		return false
	}

	if _, err := p.keys.IncrementInt(key, 1); err != nil {
		p.keys.Set(key, 1, keyWindow)
	}

	select {
	case p.ch <- failure:
		return true
	default:
		return false
	}
}

func getFailureKey(failure *Failure, isVerified bool) string {
	var principal string

	switch {
	case failure.SessionRef.GetUid() != "":
		principal = failure.SessionRef.Uid
	case failure.Info.GetAuthenticator().GetAuthenticatorRef().GetUid() != "":
		principal = failure.Info.GetAuthenticator().GetAuthenticatorRef().GetUid()
	case failure.Info.GetCredential().GetCredentialRef().GetUid() != "":
		principal = failure.Info.GetCredential().GetCredentialRef().GetUid()
	case failure.UserRef.GetUid() != "":
		principal = failure.UserRef.Uid
	case failure.Info.GetIdentityProvider().GetIdentityProviderRef().GetUid() != "":
		principal = failure.Info.GetIdentityProvider().GetIdentityProviderRef().GetUid()
	}

	if isVerified {
		return fmt.Sprintf("v:%s:%s", failure.Reason, principal)
	}

	return fmt.Sprintf("u:%s:%s:%s", failure.Reason, principal,
		failure.Info.GetDownstream().GetIpAddress())
}

func (p *Publisher) pause(d time.Duration) {
	p.pausedUntil.Store(time.Now().Add(d).UnixNano())
}

func (p *Publisher) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case failure := <-p.ch:
			failures := []*Failure{failure}

		drain:
			for len(failures) < publisherMaxBatch {
				select {
				case failure := <-p.ch:
					failures = append(failures, failure)
				default:
					break drain
				}
			}

			p.publish(ctx, failures)
		}
	}
}

func (p *Publisher) publish(ctx context.Context, failures []*Failure) {
	var msgs []*rpubsubv1.Message

	for _, failure := range failures {
		if p.geoipCtl != nil && failure.Info.GetDownstream().GetIpAddress() != "" {
			failure.Info.Geoip = p.geoipCtl.ResolveStr(failure.Info.Downstream.IpAddress)
		}

		msg, err := failure.ToMessage()
		if err != nil {
			zap.L().Debug("Could not convert the authentication failure to a message", zap.Error(err))
			continue
		}

		msgs = append(msgs, msg)
	}

	if len(msgs) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()

	res, err := p.octeliumC.PubSubC().Publish(ctx, &rpubsubv1.PublishRequest{
		Topic:     []byte(TopicFailure),
		Messages:  msgs,
		MaxLength: topicMaxLength,
		MaxAge: &metav1.Duration{
			Type: &metav1.Duration_Minutes{
				Minutes: topicMaxAgeMinute,
			},
		},
		IfExists: true,
	}, grpc_retry.Disable())
	if err != nil {
		zap.L().Debug("Could not publish the authentication failures", zap.Error(err))
		if grpcerr.IsUnimplemented(err) {
			p.pause(pauseUnimplemented)
		}
		return
	}

	if len(res.Ids) == 0 {
		p.pause(pauseNoSubscriber)
	}
}
