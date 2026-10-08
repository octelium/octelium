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
	"sync"
	"sync/atomic"
	"time"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	AuthHeader = "x-octelium-auth"

	VClientInitBudget      = 60 * time.Second
	vclientDisconnectGrace = 15 * time.Second

	reconnectBackoffMin = 2 * time.Second
	reconnectBackoffMax = 5 * time.Second
)

const (
	EventState         = "State"
	EventAddGateway    = "AddGateway"
	EventUpdateGateway = "UpdateGateway"
	EventDeleteGateway = "DeleteGateway"
	EventUpdateDNS     = "UpdateDNS"
	EventDisconnect    = "Disconnect"
	EventAddService    = "AddService"
	EventUpdateService = "UpdateService"
	EventDeleteService = "DeleteService"
	EventMessage       = "Message"
)

var errServerDisconnect = errors.New("the Cluster disconnected the stream")

type VClientOpts struct {
	L3Mode     userv1.ConnectRequest_Initialize_L3Mode
	Tunnel     userv1.ConnectRequest_Initialize_ConnectionType
	KeepAlive  time.Duration
	InitBudget time.Duration
	IgnoreDNS  bool
}

type eventRecord struct {
	count int
	last  time.Time
	msg   *userv1.ConnectResponse
}

type VClient struct {
	Session *FleetSession

	pool *VConnPool
	opts VClientOpts

	connectMu sync.Mutex

	mu                   sync.Mutex
	conn                 *VConn
	cancel               context.CancelFunc
	stream               userv1.MainService_ConnectClient
	state                *userv1.ConnectionState
	gateways             map[string]*userv1.Gateway
	connected            bool
	done                 chan struct{}
	streamErr            error
	disconnectedByServer bool
	connectedAt          time.Time
	droppedAt            time.Time
	connects             int
	failedConnects       int
	initAt               time.Time
	staleEvents          int
	events               map[string]*eventRecord
	gatewayHooks         []func(gws []*userv1.Gateway)

	readGate *gate
}

func NewVClient(sess *FleetSession, pool *VConnPool, opts VClientOpts) *VClient {
	if opts.InitBudget == 0 {
		opts.InitBudget = VClientInitBudget
	}

	ret := &VClient{
		Session:  sess,
		pool:     pool,
		opts:     opts,
		gateways: map[string]*userv1.Gateway{},
		events:   map[string]*eventRecord{},
		readGate: newGate(),
		done:     make(chan struct{}),
	}
	close(ret.done)

	return ret
}

func (c *VClient) Opts() VClientOpts { return c.opts }

func (c *VClient) authCtx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, AuthHeader, c.Session.AccessToken)
}

func (c *VClient) initRequest() *userv1.ConnectRequest {
	return &userv1.ConnectRequest{
		Type: &userv1.ConnectRequest_Initialize_{
			Initialize: &userv1.ConnectRequest_Initialize{
				L3Mode:         c.opts.L3Mode,
				ConnectionType: c.opts.Tunnel,
				IgnoreDNS:      c.opts.IgnoreDNS,
			},
		},
	}
}

func (c *VClient) Connect(ctx context.Context) error {
	c.connectMu.Lock()
	defer c.connectMu.Unlock()

	if c.IsConnected() {
		return nil
	}

	err := c.doConnect(ctx)

	c.mu.Lock()
	if err != nil {
		c.failedConnects++
	}
	c.mu.Unlock()

	return err
}

func (c *VClient) doConnect(ctx context.Context) error {
	conn, err := c.pool.Acquire()
	if err != nil {
		return err
	}

	streamCtx, cancel := context.WithCancel(context.Background())

	var timedOut atomic.Bool
	initTimer := time.AfterFunc(c.opts.InitBudget, func() {
		timedOut.Store(true)
		cancel()
	})
	stopInit := context.AfterFunc(ctx, cancel)

	fail := func(err error) error {
		initTimer.Stop()
		stopInit()
		cancel()
		conn.Release()

		switch {
		case timedOut.Load():
			return errors.Wrapf(err, "timed out after %s waiting for the Connection state",
				c.opts.InitBudget)
		case ctx.Err() != nil:
			return errors.Wrap(ctx.Err(), "the Connect initialization was interrupted")
		default:
			return err
		}
	}

	stream, err := userv1.NewMainServiceClient(conn.cc).Connect(c.authCtx(streamCtx))
	if err != nil {
		return fail(err)
	}

	if err := stream.Send(c.initRequest()); err != nil {
		return fail(err)
	}

	var state *userv1.ConnectionState
	var initAt time.Time
	for state == nil {
		msg, err := stream.Recv()
		if err != nil {
			return fail(err)
		}

		if msg.GetState() != nil {
			state = msg.GetState()
			if msg.CreatedAt.IsValid() {
				initAt = msg.CreatedAt.AsTime()
			}
		}
	}

	if !initTimer.Stop() || !stopInit() {
		return fail(errors.Errorf("the Connect initialization was interrupted"))
	}

	done := make(chan struct{})

	c.mu.Lock()
	c.conn = conn
	c.cancel = cancel
	c.stream = stream
	c.state = state
	c.gateways = map[string]*userv1.Gateway{}
	for _, gw := range state.Gateways {
		c.gateways[gw.Id] = gw
	}
	c.connected = true
	c.done = done
	c.streamErr = nil
	c.disconnectedByServer = false
	c.connectedAt = time.Now()
	c.initAt = initAt
	c.connects++
	c.recordEventLocked(EventState, &userv1.ConnectResponse{
		CreatedAt: pbutils.Now(),
		Event:     &userv1.ConnectResponse_State{State: state},
	})
	hooks := c.gatewayHooks
	gws := c.gatewayListLocked()
	c.mu.Unlock()

	for _, hook := range hooks {
		hook(gws)
	}

	go c.recvLoop(streamCtx, stream, done)

	if c.opts.KeepAlive > 0 {
		go c.keepAliveLoop(streamCtx, stream, done)
	}

	return nil
}

func (c *VClient) recvLoop(ctx context.Context, stream userv1.MainService_ConnectClient,
	done chan struct{}) {
	var streamErr error

	for {
		if err := c.readGate.wait(ctx); err != nil {
			streamErr = err
			break
		}

		msg, err := stream.Recv()
		if err != nil {
			streamErr = err
			break
		}

		if c.handleEvent(msg) {
			streamErr = errServerDisconnect
			break
		}
	}

	c.finish(done, streamErr)
}

func (c *VClient) keepAliveLoop(ctx context.Context, stream userv1.MainService_ConnectClient,
	done chan struct{}) {
	ticker := time.NewTicker(Jitter(c.opts.KeepAlive, c.opts.KeepAlive/4))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			c.mu.Lock()
			isCurrent := c.stream == stream && c.connected
			c.mu.Unlock()
			if !isCurrent {
				return
			}

			if err := stream.Send(&userv1.ConnectRequest{
				Type: &userv1.ConnectRequest_KeepAlive_{
					KeepAlive: &userv1.ConnectRequest_KeepAlive{SetAt: pbutils.Now()},
				},
			}); err != nil {
				return
			}
		}
	}
}

func eventName(msg *userv1.ConnectResponse) string {
	switch msg.Event.(type) {
	case *userv1.ConnectResponse_State:
		return EventState
	case *userv1.ConnectResponse_AddGateway_:
		return EventAddGateway
	case *userv1.ConnectResponse_UpdateGateway_:
		return EventUpdateGateway
	case *userv1.ConnectResponse_DeleteGateway_:
		return EventDeleteGateway
	case *userv1.ConnectResponse_UpdateDNS_:
		return EventUpdateDNS
	case *userv1.ConnectResponse_Disconnect_:
		return EventDisconnect
	case *userv1.ConnectResponse_AddService_:
		return EventAddService
	case *userv1.ConnectResponse_UpdateService_:
		return EventUpdateService
	case *userv1.ConnectResponse_DeleteService_:
		return EventDeleteService
	case *userv1.ConnectResponse_Message_:
		return EventMessage
	default:
		return "Unknown"
	}
}

func (c *VClient) recordEventLocked(name string, msg *userv1.ConnectResponse) {
	rec, ok := c.events[name]
	if !ok {
		rec = &eventRecord{}
		c.events[name] = rec
	}
	rec.count++
	rec.last = time.Now()
	rec.msg = msg
}

func (c *VClient) handleEvent(msg *userv1.ConnectResponse) bool {
	if msg == nil || msg.Event == nil {
		return false
	}

	name := eventName(msg)

	c.mu.Lock()
	if !c.initAt.IsZero() && msg.CreatedAt.IsValid() && msg.CreatedAt.AsTime().Before(c.initAt) {
		c.staleEvents++
		c.mu.Unlock()
		return false
	}

	c.recordEventLocked(name, msg)

	var gwChanged bool
	switch ev := msg.Event.(type) {
	case *userv1.ConnectResponse_State:
		c.state = ev.State
		c.gateways = map[string]*userv1.Gateway{}
		for _, gw := range ev.State.Gateways {
			c.gateways[gw.Id] = gw
		}
		gwChanged = true
	case *userv1.ConnectResponse_AddGateway_:
		if gw := ev.AddGateway.GetGateway(); gw != nil {
			c.gateways[gw.Id] = gw
			gwChanged = true
		}
	case *userv1.ConnectResponse_UpdateGateway_:
		if gw := ev.UpdateGateway.GetGateway(); gw != nil {
			c.gateways[gw.Id] = gw
			gwChanged = true
		}
	case *userv1.ConnectResponse_DeleteGateway_:
		delete(c.gateways, ev.DeleteGateway.GetId())
		gwChanged = true
	case *userv1.ConnectResponse_UpdateDNS_:
		if c.state != nil && ev.UpdateDNS.GetDns() != nil {
			c.state.Dns = ev.UpdateDNS.GetDns()
		}
	case *userv1.ConnectResponse_Disconnect_:
		c.disconnectedByServer = true
	}

	hooks := c.gatewayHooks
	gws := c.gatewayListLocked()
	isDisconnect := name == EventDisconnect
	c.mu.Unlock()

	if gwChanged {
		for _, hook := range hooks {
			hook(gws)
		}
	}

	return isDisconnect
}

func (c *VClient) finish(done chan struct{}, streamErr error) {
	c.mu.Lock()
	if c.done != done {
		c.mu.Unlock()
		return
	}

	conn := c.conn
	cancel := c.cancel

	c.connected = false
	c.streamErr = streamErr
	c.droppedAt = time.Now()
	c.conn = nil
	c.stream = nil
	close(done)
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		conn.Release()
	}
}

func (c *VClient) gatewayListLocked() []*userv1.Gateway {
	ret := make([]*userv1.Gateway, 0, len(c.gateways))
	for _, gw := range c.gateways {
		ret = append(ret, proto.Clone(gw).(*userv1.Gateway))
	}
	return ret
}

func (c *VClient) OnGateways(hook func(gws []*userv1.Gateway)) {
	c.mu.Lock()
	c.gatewayHooks = append(c.gatewayHooks, hook)
	c.mu.Unlock()
}

func (c *VClient) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	conn := c.conn
	done := c.done
	connected := c.connected
	c.mu.Unlock()

	if !connected || conn == nil || !conn.retain() {
		return nil
	}
	defer conn.Release()

	ctx, cancel := context.WithTimeout(ctx, vclientDisconnectGrace)
	defer cancel()

	_, err := userv1.NewMainServiceClient(conn.cc).Disconnect(c.authCtx(ctx), &userv1.DisconnectRequest{})

	select {
	case <-done:
	case <-ctx.Done():
		c.Drop()
	}

	return err
}

func (c *VClient) Drop() {
	c.mu.Lock()
	cancel := c.cancel
	connected := c.connected
	c.mu.Unlock()

	if connected && cancel != nil {
		cancel()
	}
}

func (c *VClient) WaitDone(ctx context.Context) error {
	select {
	case <-c.Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *VClient) Freeze() {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn != nil {
		conn.Freeze()
	}
}

func (c *VClient) Thaw() {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn != nil {
		conn.Thaw()
	}
}

func (c *VClient) PauseReading() { c.readGate.close() }

func (c *VClient) ResumeReading() { c.readGate.open() }

func (c *VClient) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.done
}

func (c *VClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *VClient) StreamErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streamErr
}

func (c *VClient) DisconnectedByServer() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disconnectedByServer
}

func (c *VClient) State() *userv1.ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == nil {
		return nil
	}
	return proto.Clone(c.state).(*userv1.ConnectionState)
}

func (c *VClient) Gateways() []*userv1.Gateway {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gatewayListLocked()
}

func (c *VClient) Connects() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connects
}

func (c *VClient) FailedConnects() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failedConnects
}

func (c *VClient) ConnectedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectedAt
}

func (c *VClient) DroppedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.droppedAt
}

func (c *VClient) StaleEvents() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.staleEvents
}

func (c *VClient) EventCount(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if rec, ok := c.events[name]; ok {
		return rec.count
	}
	return 0
}

func (c *VClient) LastEvent(name string) (time.Time, *userv1.ConnectResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if rec, ok := c.events[name]; ok {
		return rec.last, rec.msg
	}
	return time.Time{}, nil
}

func (c *VClient) X25519PublicKey() ([]byte, error) {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()

	if state == nil {
		return nil, errors.Errorf("the client has no Connection state")
	}

	key, err := wgtypes.NewKey(state.X25519Key)
	if err != nil {
		return nil, err
	}

	pub := key.PublicKey()
	return pub[:], nil
}

type SuperviseOpts struct {
	ReconnectAfterServerDisconnect bool
	BackoffMin                     time.Duration
	BackoffMax                     time.Duration
}

func ReconnectBackoff(attempt int, lo, hi time.Duration) time.Duration {
	if lo <= 0 {
		lo = reconnectBackoffMin
	}
	if hi < lo {
		hi = max(lo, reconnectBackoffMax)
	}

	ret := lo << min(max(attempt-1, 0), 6)
	if ret > hi || ret <= 0 {
		ret = hi
	}

	return Jitter(ret, min(ret/2, hi-ret+1))
}

func (c *VClient) Supervise(ctx context.Context, o SuperviseOpts) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.Done():
		}

		if c.DisconnectedByServer() && !o.ReconnectAfterServerDisconnect {
			return
		}

		for attempt := 1; ; attempt++ {
			if err := Sleep(ctx, ReconnectBackoff(attempt, o.BackoffMin, o.BackoffMax)); err != nil {
				return
			}

			attemptCtx, cancel := context.WithTimeout(ctx, c.opts.InitBudget+10*time.Second)
			err := c.Connect(attemptCtx)
			cancel()
			if err == nil {
				break
			}
		}
	}
}
