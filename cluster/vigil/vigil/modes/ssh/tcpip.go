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
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type reqDirectTCPIP struct {
	Host string
	Port uint32

	Orig     string
	OrigPort uint32
}

func parseDirectTCPIPReq(data []byte) (*reqDirectTCPIP, error) {
	var r reqDirectTCPIP
	if err := ssh.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	return &r, nil
}

func (c *dctx) handleDirectTCPIP(ctx context.Context, nch ssh.NewChannel) {
	svcCfg := c.svcConfig

	if svcCfg == nil || svcCfg.GetSsh() == nil || !svcCfg.GetSsh().EnableLocalPortForwarding {
		zap.L().Debug("Handling TCPIP rejected since local port forwarding is not enabled", zap.String("id", c.id))
		nch.Reject(ssh.UnknownChannelType,
			fmt.Sprintf("Channel type: %s is unsupported", nch.ChannelType()))

		return
	}

	zap.L().Debug("Starting handleDirectTCPIP", zap.String("id", c.id))

	startTime := time.Now()

	tcpIPReq := &reqDirectTCPIP{}
	if err := ssh.Unmarshal(nch.ExtraData(), tcpIPReq); err != nil {
		zap.L().Debug("Could not parse Direct TCP_IP request",
			zap.String("id", c.id), zap.Error(err))
		return
	}

	ch, _, err := nch.Accept()
	if err != nil {
		zap.L().Debug("Could not accept the new channel",
			zap.String("id", c.id), zap.Error(err))
		return
	}
	defer ch.Close()

	remoteAddr := net.JoinHostPort(tcpIPReq.Host, fmt.Sprintf("%d", tcpIPReq.Port))

	zap.L().Debug("Connecting to remote addr",
		zap.String("id", c.id), zap.String("addr", remoteAddr))

	conn, err := c.remoteConn.sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		zap.L().Debug("Could not connect to remote addr",
			zap.String("id", c.id), zap.String("addr", remoteAddr))
		return
	}
	defer conn.Close()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err = io.Copy(ch, conn)
	}()

	go func() {
		defer wg.Done()
		_, err = io.Copy(conn, ch)
	}()

	{
		logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
			StartTime:       startTime,
			IsAuthenticated: true,
			IsAuthorized:    true,
			ReqCtx:          c.i,
			ConnectionID:    c.id,
			Reason:          c.reasonInit,
		})
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
			Ssh: &corev1.AccessLog_Entry_Info_SSH{
				Type: corev1.AccessLog_Entry_Info_SSH_DIRECT_TCPIP_START,
				Details: &corev1.AccessLog_Entry_Info_SSH_DirectTCPIPStart_{
					DirectTCPIPStart: &corev1.AccessLog_Entry_Info_SSH_DirectTCPIPStart{
						Host: tcpIPReq.Host,
						Port: int32(tcpIPReq.Port),
					},
				},
			},
		}
		otelutils.EmitAccessLog(logE)
	}

	zap.L().Debug("Waiting for port forwarding to close", zap.String("id", c.id))
	wg.Wait()

	{
		logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
			StartTime:       startTime,
			IsAuthenticated: true,
			IsAuthorized:    true,
			ReqCtx:          c.i,
			ConnectionID:    c.id,
			Reason:          c.reasonInit,
		})
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
			Ssh: &corev1.AccessLog_Entry_Info_SSH{
				Type: corev1.AccessLog_Entry_Info_SSH_DIRECT_TCPIP_END,
			},
		}
		otelutils.EmitAccessLog(logE)
	}

	zap.L().Debug("handleDirectTCPIP ended", zap.String("id", c.id))
}
