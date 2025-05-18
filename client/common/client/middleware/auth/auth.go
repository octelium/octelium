// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"

	"github.com/octelium/octelium/client/common/authenticator"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func UnaryClientInterceptor(domain string, opts ...grpc.CallOption) grpc.UnaryClientInterceptor {

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

		token, err := getToken(ctx, domain)
		if err != nil {
			return err
		}

		ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-auth", token)
		// ctx = metadata.AppendToOutgoingContext(ctx, "user-agent", fmt.Sprintf("octelium-cli/%s", ldflags.GetVersion()))

		err = invoker(ctx, method, req, reply, cc, opts...)
		if err != nil {
			zap.S().Debugf("invoker error: %+v", err)
		}
		return err
	}
}

func StreamClientInterceptor(domain string, opts ...grpc.CallOption) grpc.StreamClientInterceptor {

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {

		token, err := getToken(ctx, domain)
		if err != nil {
			return nil, err
		}

		ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-auth", token)
		// ctx = metadata.AppendToOutgoingContext(ctx, "user-agent", fmt.Sprintf("octelium-cli/%s", ldflags.GetVersion()))

		clientStream, err := streamer(ctx, desc, cc, method, opts...)
		return clientStream, err
	}
}

func getToken(ctx context.Context, domain string) (string, error) {
	return authenticator.GetAccessToken(ctx, domain)
}
