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

package server

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	operationRetention     = 10 * time.Minute
	stateReconcileInterval = 5 * time.Second
)

type principal struct {
	srv     *Server
	id      string
	name    string
	homeDir string

	dbC *db.DB

	mu       sync.Mutex
	revision uint64
	domains  map[string]*domainCtl
	ops      map[string]*operation
	watchers map[*watcher]struct{}
}

type watcher struct {
	ch chan struct{}
}

func newPrincipal(srv *Server, pr *ipc.Principal) (*principal, error) {
	dbDir, err := srv.getPrincipalDBDir(pr)
	if err != nil {
		return nil, err
	}

	dbC, err := db.OpenWithOpts(&db.Opts{
		Path:  dbDir,
		Owner: getDBOwner(pr),
	})
	if err != nil {
		return nil, err
	}

	if err := dbC.Migrate(); err != nil {
		return nil, err
	}

	ret := &principal{
		srv:      srv,
		id:       pr.ID,
		name:     pr.Name,
		homeDir:  pr.HomeDir,
		dbC:      dbC,
		domains:  make(map[string]*domainCtl),
		ops:      make(map[string]*operation),
		watchers: make(map[*watcher]struct{}),
	}

	if err := ret.loadDomains(); err != nil {
		return nil, err
	}

	zap.L().Debug("Loaded the state of the OS principal",
		zap.String("principal", ret.id), zap.String("dbDir", dbDir),
		zap.Int("domains", len(ret.domains)))

	return ret, nil
}

func getDBOwner(pr *ipc.Principal) *db.Owner {
	if os.Geteuid() == 0 {
		uid, err := strconv.Atoi(pr.ID)
		if err != nil {
			return nil
		}

		gid, err := strconv.Atoi(pr.GID)
		if err != nil {
			return nil
		}

		return &db.Owner{
			UID: uid,
			GID: gid,
		}
	}

	return nil
}

func (p *principal) startReconcileLoop() {
	go func() {
		tickerCh := time.NewTicker(stateReconcileInterval)
		defer tickerCh.Stop()

		for {
			select {
			case <-p.srv.ctx.Done():
				return
			case <-tickerCh.C:
				p.reconcile()
			}
		}
	}()
}

func (p *principal) reconcile() {
	domainMap, err := p.dbC.List()
	if err != nil {
		zap.L().Debug("Could not read the local state to reconcile it", zap.Error(err))
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

	p.updateIf(func() bool {
		var isChanged bool

		for domain, itm := range canonicalMap {
			d, ok := p.domains[domain]
			if !ok {
				d = p.newDomainCtl(domain)
				d.settings = itm.GetSettings()
				d.setAuthenticationFromState(itm)
				p.domains[domain] = d
				isChanged = true
				continue
			}

			if !d.canReconcile() {
				continue
			}

			if d.setAuthenticationFromState(itm) {
				isChanged = true
			}
		}

		for domain, d := range p.domains {
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

func (p *principal) displayName() string {
	if p.name != "" {
		return p.name
	}

	return p.id
}

func (p *principal) loadDomains() error {
	domainMap, err := p.dbC.List()
	if err != nil {
		return err
	}

	for domain, itm := range domainMap {
		canonical, err := canonicalizeDomain(domain)
		if err != nil {
			zap.L().Warn("Skipping an invalid stored domain", zap.String("domain", domain))
			continue
		}

		if _, ok := p.domains[canonical]; ok {
			zap.L().Warn("Skipping a duplicate stored domain", zap.String("domain", domain))
			continue
		}

		d := p.newDomainCtl(canonical)
		d.settings = itm.GetSettings()
		d.setAuthenticationFromState(itm)

		p.domains[canonical] = d
	}

	return nil
}

func (p *principal) ctx(ctx context.Context) context.Context {
	return authenticator.WithNonInteractive(cliutils.WithDB(ctx, p.dbC))
}

func (p *principal) opCtx() context.Context {
	return p.ctx(p.srv.ctx)
}

func (p *principal) update(fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()

	fn()

	p.notify()
}

func (p *principal) updateIf(fn func() bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if fn() {
		p.notify()
	}
}

func (p *principal) notify() {
	p.revision++

	for w := range p.watchers {
		select {
		case w.ch <- struct{}{}:
		default:
		}
	}
}

func (p *principal) addWatcher() *watcher {
	ret := &watcher{
		ch: make(chan struct{}, 1),
	}

	p.mu.Lock()
	p.watchers[ret] = struct{}{}
	p.mu.Unlock()

	return ret
}

func (p *principal) deleteWatcher(w *watcher) {
	p.mu.Lock()
	delete(p.watchers, w)
	p.mu.Unlock()
}

func (p *principal) getStatus() *daemonv1.GetStatusResponse {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pruneOperations()

	ret := &daemonv1.GetStatusResponse{
		InstanceID: p.srv.instanceID,
		Revision:   p.revision,
		UpdatedAt:  pbutils.Now(),
	}

	for _, d := range p.domains {
		ret.Domains = append(ret.Domains, d.toPB())
	}

	slices.SortFunc(ret.Domains, func(a, b *daemonv1.DomainState) int {
		return strings.Compare(a.Domain, b.Domain)
	})

	return ret
}

func (p *principal) getDomain(domain string) (*domainCtl, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ret, ok := p.domains[domain]; ok {
		if ret.isDeleting {
			return nil, status.Errorf(codes.FailedPrecondition,
				"The domain %s is being deleted", domain)
		}
		return ret, nil
	}

	ret := p.newDomainCtl(domain)

	if itm, err := p.dbC.Get(domain); err == nil {
		ret.settings = itm.GetSettings()
		ret.setAuthenticationFromState(itm)
	} else if !p.dbC.ErrorIsNotFound(err) {
		return nil, status.Errorf(codes.Internal, "Could not read the local state: %s", err.Error())
	}

	p.domains[domain] = ret

	return ret, nil
}

func (p *principal) findDomain(domain string) (*domainCtl, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ret, ok := p.domains[domain]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Unknown Cluster domain: %s", domain)
	}

	if ret.isDeleting {
		return nil, status.Errorf(codes.FailedPrecondition,
			"The domain %s is being deleted", domain)
	}

	return ret, nil
}

func (p *principal) getOperation(id string) (*daemonv1.Operation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pruneOperations()

	op, ok := p.ops[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Unknown Operation: %s", id)
	}

	return op.toPB(), nil
}

func (p *principal) cancelOperation(id string) (*daemonv1.Operation, error) {
	p.mu.Lock()

	op, ok := p.ops[id]
	if !ok {
		p.mu.Unlock()
		return nil, status.Errorf(codes.NotFound, "Unknown Operation: %s", id)
	}

	if op.isDone() {
		ret := op.toPB()
		p.mu.Unlock()
		return ret, nil
	}

	if !op.isCancellable() {
		typ := op.typ
		p.mu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition,
			"The %s Operation cannot be canceled", typ.String())
	}

	cancelFn := op.cancelFn
	op.setCanceled("The Operation was canceled")
	p.notify()
	ret := op.toPB()

	p.mu.Unlock()

	cancelFn()

	return ret, nil
}

func (p *principal) pruneOperations() {
	now := time.Now()
	for id, op := range p.ops {
		if !op.isDone() || op.completedAt == nil {
			continue
		}
		if now.Sub(op.completedAt.AsTime()) > operationRetention {
			delete(p.ops, id)
		}
	}
}

func (p *principal) doAutoConnect() {
	p.mu.Lock()
	var domains []*domainCtl
	for _, d := range p.domains {
		if !d.isDeleting && d.settings.GetAutoConnect() &&
			d.authState == daemonv1.AuthenticationStatus_AUTHENTICATED {
			domains = append(domains, d)
		}
	}
	p.mu.Unlock()

	for _, d := range domains {
		zap.L().Debug("Auto-connecting the domain",
			zap.String("principal", p.id), zap.String("domain", d.domain))
		if _, err := d.startConnect(nil); err != nil {
			zap.L().Warn("Could not auto-connect the domain",
				zap.String("domain", d.domain), zap.Error(err))
		}
	}
}

func (p *principal) close() {
	p.mu.Lock()
	var domains []*domainCtl
	for _, d := range p.domains {
		domains = append(domains, d)
	}
	p.mu.Unlock()

	for _, d := range domains {
		d.close()
	}

	if err := p.dbC.Close(); err != nil {
		zap.L().Debug("Could not close the local state of the OS principal", zap.Error(err))
	}
}
