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

package liboctelium

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/cliutils/deviceinfo"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/tun"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	apiMajorVersion = 1
	apiMinorVersion = 0
)

const (
	stateKeyLen        = 32
	operationRetention = 10 * time.Minute
)

type Host interface {
	SendEvent(ev *mobilev1.Event)
	SendPlatformRequest(id uint64, req *mobilev1.PlatformRequest)
}

type Client struct {
	cfg        *mobilev1.Config
	host       Host
	instanceID string
	dbC        *db.DB
	svc        *service

	ctx      context.Context
	cancelFn context.CancelFunc
	wg       sync.WaitGroup

	eventsCancelFn context.CancelFunc

	mu           sync.Mutex
	revision     uint64
	domains      map[string]*domainCtl
	ops          map[string]*operation
	tunnelDomain string
	isClosed     bool

	events           *eventDispatcher
	requests         *requestMap
	network          *network
	openTUN          func(fd int) (tun.Device, error)
	unregisterLogger func()
	closeOnce        sync.Once
}

func New(cfg *mobilev1.Config, host Host) (*Client, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	if host == nil {
		return nil, status.Error(codes.InvalidArgument, "The host is not set")
	}

	dbC, err := db.OpenWithOpts(&db.Opts{
		Path:          cfg.StateDir,
		EncryptionKey: cfg.StateKey,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not open the state: %s", err)
	}

	if err := dbC.Migrate(); err != nil {
		return nil, status.Errorf(codes.Internal, "Could not migrate the state: %s", err)
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	eventsCtx, eventsCancelFn := context.WithCancel(context.Background())

	ret := &Client{
		cfg:            pbutils.Clone(cfg).(*mobilev1.Config),
		host:           host,
		instanceID:     uuid.NewString(),
		dbC:            dbC,
		ctx:            ctx,
		cancelFn:       cancelFn,
		eventsCancelFn: eventsCancelFn,
		domains:        make(map[string]*domainCtl),
		ops:            make(map[string]*operation),
		requests:       newRequestMap(),
		network:        newNetwork(),
		openTUN:        newTUNFromFD,
	}

	ret.svc = &service{
		c: ret,
	}
	ret.events = newEventDispatcher(host, ret.getStatus)

	if err := ret.loadDomains(); err != nil {
		cancelFn()
		eventsCancelFn()
		dbC.Close()
		return nil, status.Errorf(codes.Internal, "Could not load the state: %s", err)
	}

	ret.unregisterLogger = registerLogCore(newLogCore(cfg.LogLevel, ret.events.sendLog))

	go ret.events.run(eventsCtx)

	return ret, nil
}

func validateConfig(cfg *mobilev1.Config) error {
	if cfg == nil {
		return status.Error(codes.InvalidArgument, "The config is not set")
	}

	switch cfg.Platform {
	case mobilev1.Config_ANDROID, mobilev1.Config_IOS:
	default:
		return status.Errorf(codes.InvalidArgument, "Unsupported platform: %d", cfg.Platform)
	}

	if cfg.StateDir == "" {
		return status.Error(codes.InvalidArgument, "The state directory is not set")
	}

	if len(cfg.StateKey) != stateKeyLen {
		return status.Errorf(codes.InvalidArgument, "The state key must be %d bytes", stateKeyLen)
	}

	if cfg.GetDevice().GetId() == "" {
		return status.Error(codes.InvalidArgument, "The device ID is not set")
	}

	if _, ok := mobilev1.Log_Level_name[int32(cfg.LogLevel)]; !ok {
		return status.Errorf(codes.InvalidArgument, "Unsupported log level: %d", cfg.LogLevel)
	}

	return nil
}

func (c *Client) Call(ctx context.Context, method string, req []byte) ([]byte, error) {
	if !c.beginWork() {
		return nil, status.Error(codes.Unavailable, "The client is closed")
	}
	defer c.wg.Done()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()

	for _, m := range mobilev1.MainService_ServiceDesc.Methods {
		if m.MethodName != method {
			continue
		}

		resp, err := m.Handler(c.svc, ctx, func(in any) error {
			if err := pbutils.Unmarshal(req, in.(pbutils.Message)); err != nil {
				return status.Errorf(codes.InvalidArgument, "Could not unmarshal the request: %s", err)
			}
			return nil
		}, nil)
		if err != nil {
			return nil, err
		}

		return pbutils.Marshal(resp.(pbutils.Message))
	}

	return nil, status.Errorf(codes.Unimplemented, "Unknown method: %s", method)
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.isClosed = true
		var domains []*domainCtl
		for _, d := range c.domains {
			domains = append(domains, d)
		}
		c.mu.Unlock()

		for _, d := range domains {
			d.close()
		}

		c.cancelFn()
		c.wg.Wait()

		c.eventsCancelFn()
		c.events.wait()
		c.unregisterLogger()

		if err := c.dbC.Close(); err != nil {
			zap.L().Debug("Could not close the state", zap.Error(err))
		}
	})

	return nil
}

func (c *Client) beginWork() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return false
	}

	c.wg.Add(1)

	return true
}

func (c *Client) goWork(fn func()) {
	c.wg.Add(1)

	go func() {
		defer c.wg.Done()
		fn()
	}()
}

func (c *Client) withCtx(ctx context.Context) context.Context {
	ctx = authenticator.WithNonInteractive(cliutils.WithDB(ctx, c.dbC))

	return deviceinfo.WithDeviceInfo(ctx, &deviceinfo.DeviceInfo{
		ID:           c.cfg.GetDevice().GetId(),
		Hostname:     c.cfg.GetDevice().GetName(),
		SerialNumber: c.cfg.GetDevice().GetSerialNumber(),
	})
}

func (c *Client) opCtx() context.Context {
	return c.withCtx(c.ctx)
}

func (c *Client) update(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fn()

	c.notify()
}

func (c *Client) updateIf(fn func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if fn() {
		c.notify()
	}
}

func (c *Client) notify() {
	c.revision++
	c.events.notifyStatus()
}

func (c *Client) getStatus() *daemonv1.GetStatusResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneOperations()

	ret := &daemonv1.GetStatusResponse{
		InstanceID: c.instanceID,
		Revision:   c.revision,
		UpdatedAt:  pbutils.Now(),
	}

	for _, d := range c.domains {
		ret.Domains = append(ret.Domains, d.toPB())
	}

	slices.SortFunc(ret.Domains, func(a, b *daemonv1.DomainState) int {
		return strings.Compare(a.Domain, b.Domain)
	})

	return ret
}

func (c *Client) loadDomains() error {
	domainMap, err := c.dbC.List()
	if err != nil {
		return err
	}

	for domain, itm := range domainMap {
		canonical, err := canonicalizeDomain(domain)
		if err != nil {
			zap.L().Warn("Skipping an invalid stored domain", zap.String("domain", domain))
			continue
		}

		if _, ok := c.domains[canonical]; ok {
			zap.L().Warn("Skipping a duplicate stored domain", zap.String("domain", domain))
			continue
		}

		d := c.newDomainCtl(canonical)
		d.settings = itm.GetSettings()
		d.setAuthenticationFromState(itm)

		c.domains[canonical] = d
	}

	return nil
}

func (c *Client) reconcile() {
	domainMap, err := c.dbC.List()
	if err != nil {
		zap.L().Debug("Could not read the state to reconcile it", zap.Error(err))
		return
	}

	canonicalMap := make(map[string]*cliconfigv1.State_Domain)
	for domain, itm := range domainMap {
		canonical, err := canonicalizeDomain(domain)
		if err != nil {
			continue
		}
		canonicalMap[canonical] = itm
	}

	c.updateIf(func() bool {
		var isChanged bool

		for domain, itm := range canonicalMap {
			d, ok := c.domains[domain]
			if !ok {
				d = c.newDomainCtl(domain)
				d.settings = itm.GetSettings()
				d.setAuthenticationFromState(itm)
				c.domains[domain] = d
				isChanged = true
				continue
			}

			if !d.canReconcile() {
				continue
			}

			if itm.GetSettings() != nil && !pbutils.IsEqual(d.settings, itm.GetSettings()) {
				d.settings = itm.GetSettings()
				isChanged = true
			}

			if d.setAuthenticationFromState(itm) {
				isChanged = true
			}
		}

		for domain, d := range c.domains {
			if _, ok := canonicalMap[domain]; ok {
				continue
			}

			if !d.canReconcile() {
				continue
			}

			if d.setAuthenticationFromState(nil) {
				isChanged = true
			}
		}

		return isChanged
	})
}

func (c *Client) getDomain(domain string) (*domainCtl, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ret, ok := c.domains[domain]; ok {
		if ret.isDeleting {
			return nil, status.Errorf(codes.FailedPrecondition,
				"The domain %s is being deleted", domain)
		}
		return ret, nil
	}

	ret := c.newDomainCtl(domain)

	if itm, err := c.dbC.Get(domain); err == nil {
		ret.settings = itm.GetSettings()
		ret.setAuthenticationFromState(itm)
	} else if !c.dbC.ErrorIsNotFound(err) {
		return nil, status.Errorf(codes.Internal, "Could not read the local state: %s", err.Error())
	}

	c.domains[domain] = ret

	return ret, nil
}

func (c *Client) findDomain(domain string) (*domainCtl, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ret, ok := c.domains[domain]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Unknown Cluster domain: %s", domain)
	}

	if ret.isDeleting {
		return nil, status.Errorf(codes.FailedPrecondition,
			"The domain %s is being deleted", domain)
	}

	return ret, nil
}

func (c *Client) getOperation(id string) (*daemonv1.Operation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneOperations()

	op, ok := c.ops[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Unknown Operation: %s", id)
	}

	return op.toPB(), nil
}

func (c *Client) cancelOperation(id string) (*daemonv1.Operation, error) {
	c.mu.Lock()

	op, ok := c.ops[id]
	if !ok {
		c.mu.Unlock()
		return nil, status.Errorf(codes.NotFound, "Unknown Operation: %s", id)
	}

	if op.isDone() {
		ret := op.toPB()
		c.mu.Unlock()
		return ret, nil
	}

	if !op.isCancellable() {
		typ := op.typ
		c.mu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition,
			"The %s Operation cannot be canceled", typ.String())
	}

	cancelFn := op.cancelFn
	op.setCanceled("The Operation was canceled")
	c.notify()
	ret := op.toPB()

	c.mu.Unlock()

	cancelFn()

	return ret, nil
}

func (c *Client) completeAuthentication(opID, callbackURL string) (*daemonv1.Operation, error) {
	c.mu.Lock()
	op, ok := c.ops[opID]
	if !ok {
		c.mu.Unlock()
		return nil, status.Errorf(codes.NotFound, "Unknown Operation: %s", opID)
	}
	d := c.domains[op.domain]
	c.mu.Unlock()

	if d == nil {
		return nil, status.Errorf(codes.NotFound, "Unknown Cluster domain: %s", op.domain)
	}

	return d.completeAuthentication(op, callbackURL)
}

func (c *Client) pruneOperations() {
	now := time.Now()
	for id, op := range c.ops {
		if !op.isDone() || op.completedAt == nil {
			continue
		}
		if now.Sub(op.completedAt.AsTime()) > operationRetention {
			delete(c.ops, id)
		}
	}
}

func (c *Client) acquireTunnel(domain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return status.Error(codes.Unavailable, "The client is closed")
	}

	if c.tunnelDomain != "" {
		return status.Errorf(codes.FailedPrecondition,
			"The domain %s is already connected. Only a single domain can be connected at a time",
			c.tunnelDomain)
	}

	c.tunnelDomain = domain

	return nil
}

func (c *Client) releaseTunnel(domain string) {
	if c.tunnelDomain == domain {
		c.tunnelDomain = ""
	}
}
