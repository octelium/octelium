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

package connect

import (
	"os"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/pkg/errors"
)

type Opts struct {
	L3Mode             string
	IgnoreDNS          bool
	ServeServices      []string
	ServeAll           bool
	PublishServices    []*PublishedService
	ImplementationMode string

	UseESSH    bool
	ESSHUser   string
	UseESOCKS5 bool

	UseLocalDNS        bool
	LocalDNSListenAddr string
	UseFullDNS         bool

	UserHome string

	TunnelMode string

	MTU int32

	OnEvent func(ev *Event)
}

type PublishedService struct {
	Name    string
	Address string
	Port    int
}

type EventType int

const (
	EventTypeConnecting EventType = iota + 1
	EventTypeConnected
	EventTypeReconnecting
	EventTypeDisconnected
)

type Event struct {
	Type       EventType
	Connection *cliconfigv1.Connection
	Err        error
}

type Connector struct {
	domain string
	opts   *Opts
}

func NewConnector(domain string, opts *Opts) (*Connector, error) {
	if domain == "" {
		return nil, errors.Errorf("The Cluster domain is not set")
	}

	if opts == nil {
		opts = &Opts{}
	}

	return &Connector{
		domain: domain,
		opts:   opts,
	}, nil
}

func (c *Connector) setEvent(ev *Event) {
	if c.opts.OnEvent == nil {
		return
	}

	c.opts.OnEvent(ev)
}

func (c *Connector) isQUICV0() bool {
	return c.opts.TunnelMode == "quicv0" || os.Getenv("OCTELIUM_QUIC") == "true"
}

func (c *Connector) isFullDNS() bool {
	return c.opts.UseFullDNS || os.Getenv("OCTELIUM_FULL_DNS") == "true"
}
