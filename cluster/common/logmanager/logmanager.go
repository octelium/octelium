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

package logmanager

/*
import (
	"context"
	"sync"
	"time"

	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

type LogManager struct {
	logCh  chan umetav1.LogResourceObjectI
	client plogotlp.GRPCClient

	fullCh chan plog.Logs

	readyLogs readyLogs

	cancelFn context.CancelFunc

	readyCh chan struct{}

	isClosed bool
	mu       sync.Mutex
	isDummy  bool
}

type readyLogs struct {
	mu         sync.Mutex
	plogsSlice []plog.Logs
}

const tstAddr = "localhost:34567"

type LogManagerOpts struct {
	Address string
	IsTLS   bool
}

func NewLogManager(ctx context.Context, opts *LogManagerOpts) (*LogManager, error) {

	addr := func() string {
		if opts.Address != "" {
			return opts.Address
		}
		if ldflags.IsTest() {
			return tstAddr
		} else {
			return ""
		}
	}()

	if addr == "" {
		return &LogManager{
			isDummy: true,
		}, nil
	}

	grpcOpts := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.DefaultConfig,
		}),
	}

	if !opts.IsTLS {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(addr, grpcOpts...)
	if err != nil {
		return nil, err
	}

	return &LogManager{
		logCh:   make(chan umetav1.LogResourceObjectI, 1000),
		client:  plogotlp.NewGRPCClient(conn),
		fullCh:  make(chan plog.Logs, 100),
		readyCh: make(chan struct{}, 1),
	}, nil
}

func (l *LogManager) Run(ctx context.Context) error {
	if l.isDummy {
		return nil
	}

	ctx, cancelFn := context.WithCancel(ctx)
	l.cancelFn = cancelFn

	go l.runInLoop(ctx)
	go l.runOutLoop(ctx)
	go l.runExportLoop(ctx)

	zap.S().Debugf("Log manager is now running")

	return nil
}

func (l *LogManager) Close() error {
	if l.isDummy {
		return nil
	}
	zap.S().Debugf("Closing log manager")
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return nil
	}
	l.isClosed = true
	l.cancelFn()
	zap.S().Debugf("Log manager closed")
	return nil
}

func (l *LogManager) Set(logEntry umetav1.LogResourceObjectI) {
	if logEntry == nil || l.isDummy {
		return
	}

	l.logCh <- logEntry
}

func (l *LogManager) export(ctx context.Context) error {

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	l.readyLogs.mu.Lock()
	defer l.readyLogs.mu.Unlock()

	sliceLen := len(l.readyLogs.plogsSlice)
	if sliceLen == 0 {
		return nil
	}

	cur := l.readyLogs.plogsSlice[0]


	_, err := l.client.Export(ctx, plogotlp.NewExportRequestFromLogs(cur))
	if err != nil {
		return err
	}

	if sliceLen == 1 {
		l.readyLogs.plogsSlice = nil
	} else {
		l.readyLogs.plogsSlice = l.readyLogs.plogsSlice[1:]
	}

	return nil
}

func (l *LogManager) runExportLoop(ctx context.Context) {

	tickerCh := time.NewTicker(2 * time.Second)
	defer tickerCh.Stop()
	for {
		select {
		case <-ctx.Done():
			return

		case <-l.readyCh:
			if err := l.export(ctx); err != nil {
				// zap.S().Warnf("Could not export: %+v", err)
			}
		case <-tickerCh.C:
			if err := l.export(ctx); err != nil {
				// zap.S().Warnf("Could not export: %+v", err)
			}
		}
	}
}

func (l *LogManager) runOutLoop(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case plog, ok := <-l.fullCh:
			if !ok {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			l.readyLogs.mu.Lock()
			l.readyLogs.plogsSlice = append(l.readyLogs.plogsSlice, plog)
			l.readyLogs.mu.Unlock()
			l.readyCh <- struct{}{}
		}
	}
}

func (l *LogManager) runInLoop(ctx context.Context) {
	tickerCh := time.NewTicker(2 * time.Second)
	defer tickerCh.Stop()

	curLogs := plog.NewLogs()
	curLogs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			logRecords := curLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
			if logRecords.Len() > 0 {
				l.fullCh <- curLogs
				curLogs = plog.NewLogs()
				curLogs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
			}
		case logEntry, ok := <-l.logCh:
			if !ok {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			logRecords := curLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
			lr := logRecords.AppendEmpty()

			convertLogRecord(logEntry, lr)

			if logRecords.Len() >= 512 {
				l.fullCh <- curLogs
				curLogs = plog.NewLogs()
				curLogs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
			}
		}
	}
}

func convertLogRecord(in umetav1.LogResourceObjectI, ret plog.LogRecord) {
	inMap := pbutils.MustConvertToMap(in)

	ret.SetTimestamp(pcommon.NewTimestampFromTime(in.GetMetadata().CreatedAt.AsTime()))
	ret.SetObservedTimestamp(pcommon.NewTimestampFromTime(in.GetMetadata().CreatedAt.AsTime()))
	ret.SetSeverityNumber(plog.SeverityNumberInfo)
	ret.SetSeverityText(plog.SeverityNumberInfo.String())
	ret.Body().SetEmptyMap().FromRaw(inMap)
}

func (l *LogManager) Export(ctx context.Context, logEntry umetav1.LogResourceObjectI) error {
	if l.isDummy {
		return nil
	}
	curLogs := plog.NewLogs()
	curLogs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()

	logRecords := curLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	lr := logRecords.AppendEmpty()

	convertLogRecord(logEntry, lr)

	_, err := l.client.Export(ctx, plogotlp.NewExportRequestFromLogs(curLogs))
	if err != nil {
		return err
	}

	return nil
}
*/
