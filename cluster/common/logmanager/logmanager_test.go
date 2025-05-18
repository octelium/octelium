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
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func TestConvertLogRecord(t *testing.T) {
	in := &corev1.AccessLog{
		Metadata: &metav1.LogMetadata{
			CreatedAt: pbutils.Now(),
		},
		Entry: &corev1.AccessLog_Entry{},
	}

	lr := plog.NewLogRecord()

	convertLogRecord(in, lr)

}

type tstSrv struct {
	plogotlp.UnimplementedGRPCServer
}

func (s *tstSrv) Export(ctx context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {

	reqMap := req.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Map().AsRaw()

	accessLog := &corev1.AccessLog{}
	if err := pbutils.UnmarshalFromMap(reqMap, accessLog); err != nil {
		return plogotlp.NewExportResponse(), grpcutils.InvalidArgWithErr(err)
	}

	if accessLog.Metadata.ActorRef.Name != "octelium" {
		return plogotlp.NewExportResponse(), grpcutils.InvalidArg("")
	}

	zap.L().Debug("SUCCESS NEW REQ", zap.Any("req", accessLog))

	return plogotlp.NewExportResponse(), nil
}

func TestServer(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	grpcSrv := grpc.NewServer()
	srv := &tstSrv{}

	plogotlp.RegisterGRPCServer(grpcSrv, srv)

	go func() {

		lis, err := net.Listen("tcp", tstAddr)
		if err != nil {
			return
		}
		grpcSrv.Serve(lis)
	}()

	time.Sleep(1 * time.Second)

	logman, err := NewLogManager(ctx, &LogManagerOpts{})
	assert.Nil(t, err)

	err = logman.Run(ctx)
	assert.Nil(t, err)

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	cc.Spec.Observability = &corev1.ClusterConfig_Spec_Observability{
		Receiver: &corev1.ClusterConfig_Spec_Observability_Receiver{
			Endpoint: tstAddr,
		},
	}

	cc, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err)

	for i := 0; i < 5; i++ {
		logEntry := &corev1.AccessLog{
			Metadata: &metav1.LogMetadata{
				CreatedAt: pbutils.Now(),
				ActorRef: &metav1.ObjectReference{
					Name: "octelium",
				},
			},
			Entry: &corev1.AccessLog_Entry{
				Common: &corev1.AccessLog_Entry_Common{
					Status:    corev1.AccessLog_Entry_Common_ALLOWED,
					StartedAt: pbutils.Now(),
				},
			},
		}

		logman.Set(logEntry)
	}

	time.Sleep(5 * time.Second)

}
*/
