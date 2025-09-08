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

package rscserver

import (
	"context"
	"regexp"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type regexResult struct {
	api     string
	version string
	verb    string
	kind    string
}

var rgxPath = regexp.MustCompile(`^\/octelium\.api\.rsc\.(?P<api>[a-z]{2,32})\.v1\.ResourceService\/(?P<verb>(Get|Create|List|Update|Delete|Watch))(?P<kind>[a-zA-Z]{2,32})$`)

func getRequestInfo(u string) (*regexResult, error) {

	match := rgxPath.FindStringSubmatch(u)

	ret := &regexResult{}

	if len(match) == 0 {
		return nil, errors.Errorf("Invalid path")
	}

	for i, name := range rgxPath.SubexpNames() {
		switch name {
		case "api":
			ret.api = match[i]
		case "verb":
			ret.verb = match[i]
		case "kind":
			ret.kind = match[i]
		}
	}

	ret.version = "v1"

	return ret, nil
}

func (s *Server) handleUnaryRequest(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	i, err := getRequestInfo(info.FullMethod)
	if err != nil {
		return handler(ctx, req)
	}
	startedAt := pbutils.Now()
	s.commonMetrics.atRequestStart()
	switch i.verb {
	case "Get":
		ret, err := s.doGet(ctx, req.(*rmetav1.GetOptions), i.api, i.version, i.kind)
		s.commonMetrics.atRequestEnd(startedAt.AsTime(),
			metric.WithAttributes(
				attribute.Bool("error", err != nil),
				attribute.String("op", "get"),
			))
		return ret, err
	case "List":
		retItems, listMeta, err := s.doList(ctx, req.(*rmetav1.ListOptions), i.api, i.version, i.kind)
		if err != nil {
			return nil, err
		}
		ret, err := s.toResourceList(retItems, listMeta, i.api, i.version, i.kind)
		s.commonMetrics.atRequestEnd(startedAt.AsTime(),
			metric.WithAttributes(
				attribute.Bool("error", err != nil),
				attribute.String("op", "list"),
			))
		return ret, err
	case "Create":
		ret, err := s.doCreate(ctx, req.(umetav1.ResourceObjectI), i.api, i.version, i.kind)
		s.commonMetrics.atRequestEnd(startedAt.AsTime(),
			metric.WithAttributes(
				attribute.Bool("error", err != nil),
				attribute.String("op", "create"),
			))
		return ret, err
	case "Update":
		ret, _, err := s.doUpdate(ctx, req.(umetav1.ResourceObjectI), i.api, i.version, i.kind)
		s.commonMetrics.atRequestEnd(startedAt.AsTime(),
			metric.WithAttributes(
				attribute.Bool("error", err != nil),
				attribute.String("op", "update"),
			))
		return ret, err
	case "Delete":
		ret, err := s.doDelete(ctx, req.(*rmetav1.DeleteOptions), i.api, i.version, i.kind)
		s.commonMetrics.atRequestEnd(startedAt.AsTime(),
			metric.WithAttributes(
				attribute.Bool("error", err != nil),
				attribute.String("op", "delete"),
			))
		return ret, err
	default:
		ret, err := handler(ctx, req)
		s.commonMetrics.atRequestEnd(startedAt.AsTime(),
			metric.WithAttributes(
				attribute.Bool("error", err != nil),
			))
		return ret, err
	}
}

func (s *Server) handleStreamRequest(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	i, err := getRequestInfo(info.FullMethod)
	if err != nil {
		return handler(srv, stream)
	}

	switch i.verb {
	case "Watch":
	default:
		return handler(srv, stream)
	}

	initReq := &rmetav1.WatchOptions{}
	if err := stream.RecvMsg(initReq); err != nil {
		return err
	}

	return s.doHandleStreamRequest(initReq, stream, i.api, i.version, i.kind)
}

func (s *Server) doHandleStreamRequest(req *rmetav1.WatchOptions, stream grpc.ServerStream, api, version, kind string) error {
	ctx := stream.Context()

	processCh := make(chan []byte, 8000)

	if !req.SkipInitial {
		itmList, _, err := s.doList(ctx, &rmetav1.ListOptions{}, api, version, kind)
		if err != nil {
			return err
		}

		for _, itm := range itmList {

			msg := &rmetav1.WatchEvent{
				Event: &rmetav1.WatchEvent_Event{
					ApiVersion: vutils.GetApiVersion(api, version),
					Kind:       kind,
					Type: &rmetav1.WatchEvent_Event_Create_{
						Create: &rmetav1.WatchEvent_Event_Create{
							Item: pbutils.MessageToAnyMust(itm),
						},
					},
				},
			}

			if err := stream.SendMsg(msg); err != nil {
				return err
			}
		}
	}

	sub := s.redisC.Subscribe(ctx, getRedisRscChannel(api, version, kind))
	defer sub.Close()

	go s.startStreamRecvLoop(ctx, sub, processCh)
	go s.startStreamSendLoop(ctx, processCh, stream, api, version, kind)

	<-ctx.Done()
	return nil
}

func (s *Server) startStreamSendLoop(ctx context.Context, ch <-chan []byte,
	stream grpc.ServerStream, api, version, kind string) {

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			if err := s.doProcessMsg(msg, stream, api, version, kind); err != nil {
				zap.L().Warn("Could not process msg", zap.Error(err))
			}
		}
	}
}

func (s *Server) doProcessMsg(msg []byte, stream grpc.ServerStream, api, version, kind string) error {
	resp := &rmetav1.WatchEvent{}

	if err := pbutils.Unmarshal(msg, resp); err != nil {
		return err
	}

	if err := stream.SendMsg(resp); err != nil {
		zap.L().Error("Could not send msg", zap.Error(err))
		return err
	}

	return nil
}

func (s *Server) startStreamRecvLoop(ctx context.Context, pubsub *redis.PubSub, processCh chan<- []byte) {

	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			if msg == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			processCh <- []byte(msg.Payload)
		}
	}
}
