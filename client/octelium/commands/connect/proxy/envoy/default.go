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

//go:build !serveenvoy

package envoy

/*
import (
	pb "github.com/octelium/octelium/apis/main/userv1"
)

const IsEnabled = false

type Server struct{}

func NewServer(ipv4Supported bool, ipv6Supported bool) (*Server, error) {
	return &Server{}, nil
}

func (s *Server) Run() error {
	return nil
}

func (s *Server) Close() {

}

func (s *Server) AddService(svc *pb.HostedService) error {

	return nil
}

func (s *Server) UpdateService(svc *pb.HostedService) error {

	return nil
}

func (s *Server) DeleteService(svcName string, svcNamespace string) error {

	return nil
}
*/
