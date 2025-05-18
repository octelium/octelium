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
		zap.L().Debug("Handling TCPIP rejected since local port forwarding is not enabled")
		nch.Reject(ssh.UnknownChannelType,
			fmt.Sprintf("Channel type: %s is unsupported", nch.ChannelType()))

		return
	}

	zap.L().Debug("Starting handling TCPIP")

	startTime := time.Now()

	tcpIPReq := &reqDirectTCPIP{}
	if err := ssh.Unmarshal(nch.ExtraData(), tcpIPReq); err != nil {
		zap.S().Debugf("Could not parse Direct TCP_IP request: %+v", err)
		return
	}

	ch, _, err := nch.Accept()
	if err != nil {
		zap.S().Debugf("Could not accept the new channel %+v", err)
		return
	}
	defer ch.Close()

	remoteAddr := net.JoinHostPort(tcpIPReq.Host, fmt.Sprintf("%d", tcpIPReq.Port))

	zap.S().Debugf("Connecting to remote addr: %s", remoteAddr)

	conn, err := c.remoteConn.sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		zap.S().Debugf("Could not connect to remote addr: %s", remoteAddr)
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

	zap.S().Debugf("Waiting for port forwarding to close for dctx: %s", c.id)
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

	zap.S().Debugf("Port forwarding ended for dctx: %s", c.id)
}
