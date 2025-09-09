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

package ssh

import (
	"context"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"go.uber.org/zap"
)

type recordingChunk struct {
	createdAt time.Time
	data      []byte
}

type recorder struct {
	stdinCh   chan *recordingChunk
	stdoutCh  chan *recordingChunk
	createdAt time.Time

	dctx *dctx

	sessionID string

	sequence struct {
		sync.Mutex
		val int64
	}
}

type recordOpts struct {
	skipRecording bool
	recordStdin   bool
}

func newRecorder(dctx *dctx, sessionID string) *recorder {
	return &recorder{
		createdAt: time.Now(),
		stdinCh:   make(chan *recordingChunk, 10000),
		stdoutCh:  make(chan *recordingChunk, 10000),
		dctx:      dctx,
		sessionID: sessionID,
	}
}

func (t *recorder) run(ctx context.Context) {
	if t.dctx.recordOpts.skipRecording {
		zap.L().Debug("SSH Recoding is disabled", zap.String("id", t.dctx.id))
		return
	}
	go t.doRun(ctx)
}

func (t *recorder) doRun(ctx context.Context) {

	defer func() {
		zap.L().Debug("Exiting recorder loop", zap.String("id", t.dctx.id))
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case record, ok := <-t.stdinCh:
			if !ok {
				return
			}
			if !t.dctx.recordOpts.recordStdin {
				continue
			}

			t.setRecordLog(record,
				corev1.AccessLog_Entry_Info_SSH_SessionRecording_STDIN)
		case record, ok := <-t.stdoutCh:
			if !ok {
				return
			}
			t.setRecordLog(record,
				corev1.AccessLog_Entry_Info_SSH_SessionRecording_STDOUT)
		}
	}
}

func (t *recorder) setRecordLog(record *recordingChunk, typ corev1.AccessLog_Entry_Info_SSH_SessionRecording_Type) {
	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       t.createdAt,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          t.dctx.i,
		ConnectionID:    t.dctx.id,
		SessionID:       t.sessionID,
		Sequence:        t.sequence.val,
	})

	t.sequence.Lock()
	t.sequence.val = t.sequence.val + 1
	t.sequence.Unlock()

	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
		Ssh: &corev1.AccessLog_Entry_Info_SSH{
			Type: corev1.AccessLog_Entry_Info_SSH_SESSION_RECORDING,
			Details: &corev1.AccessLog_Entry_Info_SSH_SessionRecording_{
				SessionRecording: &corev1.AccessLog_Entry_Info_SSH_SessionRecording{
					Data: record.data,
					Type: typ,
				},
			},
		},
	}

	otelutils.EmitAccessLog(logE)
}

func (t *recorder) getStdinWriter() *recordWriter {
	return &recordWriter{
		chunkChan:     t.stdinCh,
		skipRecording: t.dctx.recordOpts.skipRecording,
		isStdin:       true,
	}
}

func (t *recorder) getStdoutWriter() *recordWriter {
	return &recordWriter{
		chunkChan:     t.stdoutCh,
		skipRecording: t.dctx.recordOpts.skipRecording,
	}
}

type recordWriter struct {
	chunkChan     chan<- *recordingChunk
	skipRecording bool
	isStdin       bool
}

func (r *recordWriter) Write(b []byte) (int, error) {
	if !r.skipRecording {
		r.chunkChan <- &recordingChunk{
			createdAt: time.Now(),
			data:      b,
		}
	}

	return len(b), nil
}
