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

package mysql

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func newTestFullPacket(seq byte, typ byte) []byte {
	ret := make([]byte, 4+mysql.MaxPayloadLen)
	ret[0] = 0xff
	ret[1] = 0xff
	ret[2] = 0xff
	ret[3] = seq
	ret[4] = typ
	return ret
}

func TestPacketPayloadLen(t *testing.T) {
	assert.Equal(t, 0, packetPayloadLen(newPacket(0, nil)))
	assert.Equal(t, 9, packetPayloadLen(newPacket(0, []byte("SELECT 1x"))))
	assert.Equal(t, mysql.MaxPayloadLen,
		packetPayloadLen(newTestFullPacket(0, mysql.COM_QUERY)))
}

func TestPacketReader(t *testing.T) {
	newQueryPacket := func(seq byte, query string) []byte {
		return newPacket(seq, append([]byte{mysql.COM_QUERY}, []byte(query)...))
	}

	{
		pkts := [][]byte{
			newQueryPacket(0, "SELECT 1"),
			newQueryPacket(0, "SELECT 2"),
			newPacket(0, []byte{mysql.COM_QUIT}),
		}

		p := newPacketReader(bytes.NewReader(bytes.Join(pkts, nil)))

		for _, pkt := range pkts {
			out, isCommand, err := p.read()
			assert.Nil(t, err, "%+v", err)
			assert.True(t, isCommand)
			assert.Equal(t, pkt, out)
		}

		_, _, err := p.read()
		assert.ErrorIs(t, err, io.EOF)
	}

	{
		pkts := [][]byte{
			newTestFullPacket(0, mysql.COM_QUERY),
			newPacket(1, []byte{mysql.COM_QUIT, 'a', 'b'}),
			newQueryPacket(0, "SELECT 1"),
		}

		p := newPacketReader(bytes.NewReader(bytes.Join(pkts, nil)))

		for _, arg := range []bool{true, false, true} {
			_, isCommand, err := p.read()
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, arg, isCommand)
		}
	}

	{
		pkts := [][]byte{
			newTestFullPacket(0, mysql.COM_QUERY),
			newPacket(1, nil),
			newPacket(0, []byte{mysql.COM_CHANGE_USER}),
		}

		p := newPacketReader(bytes.NewReader(bytes.Join(pkts, nil)))

		_, isCommand, err := p.read()
		assert.Nil(t, err, "%+v", err)
		assert.True(t, isCommand)

		out, isCommand, err := p.read()
		assert.Nil(t, err, "%+v", err)
		assert.False(t, isCommand)
		assert.Equal(t, pkts[1], out)

		out, isCommand, err = p.read()
		assert.Nil(t, err, "%+v", err)
		assert.True(t, isCommand)
		assert.Equal(t, pkts[2], out)
	}

	{
		pkts := [][]byte{
			newTestFullPacket(0, mysql.COM_QUERY),
			newTestFullPacket(1, mysql.COM_QUIT),
			newPacket(2, []byte{mysql.COM_CHANGE_USER}),
			newQueryPacket(0, "SELECT 1"),
		}

		p := newPacketReader(bytes.NewReader(bytes.Join(pkts, nil)))

		for _, arg := range []bool{true, false, false, true} {
			_, isCommand, err := p.read()
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, arg, isCommand)
		}
	}
}

func TestDownstreamLoopMultiPacket(t *testing.T) {
	ctx := context.Background()

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
			Uid:  vutils.UUIDv4(),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_MYSQL,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{},
			RegionRef:    &metav1.ObjectReference{},
		},
	}

	commonMetrics, err := metricutils.NewCommonMetrics(ctx, svc)
	assert.Nil(t, err, "%+v", err)
	dbMetrics, err := metricutils.NewDBMetrics(ctx, svc)
	assert.Nil(t, err, "%+v", err)

	downstreamConn, downstreamClient := net.Pipe()
	upstreamConn, upstreamServer := net.Pipe()
	defer downstreamClient.Close()

	c := &dctx{
		id:                vutils.GenerateLogID(),
		reqCtx:            &corev1.RequestContext{Service: svc},
		downstreamConnSQL: &server.Conn{Conn: packet.NewConn(downstreamConn)},
		upstreamConnSQL:   packet.NewConn(upstreamConn),
		downstreamCh:      make(chan error, 1),
		commonMetrics:     commonMetrics,
		dbMetrics:         dbMetrics,
	}

	go c.startDownstreamLoop(ctx)

	forwardedCh := make(chan []byte, 1)
	go func() {
		buf := &bytes.Buffer{}
		io.Copy(buf, upstreamServer)
		forwardedCh <- buf.Bytes()
	}()

	pkts := [][]byte{
		newTestFullPacket(0, mysql.COM_QUERY),
		newPacket(1, []byte{mysql.COM_QUIT, 'a', 'b'}),
		newPacket(0, []byte{mysql.COM_QUIT}),
	}

	assert.Nil(t, downstreamClient.SetDeadline(time.Now().Add(30*time.Second)))

	for _, pkt := range pkts {
		_, err := downstreamClient.Write(pkt)
		assert.Nil(t, err, "%+v", err)
	}

	select {
	case err := <-c.downstreamCh:
		assert.Nil(t, err, "%+v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the downstreamLoop never exited")
	}

	upstreamConn.Close()

	select {
	case forwarded := <-forwardedCh:
		expected := bytes.Join(pkts[:2], nil)
		assert.Equal(t, len(expected), len(forwarded))
		assert.True(t, bytes.Equal(expected, forwarded))
	case <-time.After(30 * time.Second):
		t.Fatal("the forwarded packets were never read")
	}
}

func TestNewErrPacket(t *testing.T) {
	pkt := newErrPacket(1, mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR, "42000", "Octelium: Unauthorized")

	assert.Equal(t, len(pkt)-4, packetPayloadLen(pkt))
	assert.Equal(t, byte(1), pkt[3])

	payload := pkt[4:]
	assert.Equal(t, mysql.ERR_HEADER, payload[0])
	assert.Equal(t, uint16(mysql.ER_SPECIFIC_ACCESS_DENIED_ERROR),
		uint16(payload[1])|uint16(payload[2])<<8)
	assert.Equal(t, byte('#'), payload[3])
	assert.Equal(t, "42000", string(payload[4:9]))
	assert.Equal(t, "Octelium: Unauthorized", string(payload[9:]))
}

func TestGetMySQLRequest(t *testing.T) {
	newTestMysqlPacket := func(t *testing.T, typ byte, content string) *mysqlPacket {
		t.Helper()

		pkt, err := decodePacket(append([]byte{typ}, []byte(content)...))
		assert.Nil(t, err, "%+v", err)
		return pkt
	}

	{
		req := getMySQLRequest(newTestMysqlPacket(t, mysql.COM_QUERY, "SELECT 1"))
		assert.NotNil(t, req.GetMysql().GetQuery())
		assert.Equal(t, "SELECT 1", req.GetMysql().GetQuery().Query)
	}

	{
		req := getMySQLRequest(newTestMysqlPacket(t, mysql.COM_STMT_PREPARE, "SELECT ?"))
		assert.NotNil(t, req.GetMysql().GetPrepareStatement())
		assert.Equal(t, "SELECT ?", req.GetMysql().GetPrepareStatement().Query)
	}

	{
		req := getMySQLRequest(newTestMysqlPacket(t, mysql.COM_INIT_DB, "mydb"))
		assert.NotNil(t, req.GetMysql().GetInitDB())
		assert.Equal(t, "mydb", req.GetMysql().GetInitDB().Database)
	}

	for _, arg := range []byte{
		mysql.COM_QUIT,
		mysql.COM_PING,
		mysql.COM_STMT_EXECUTE,
		mysql.COM_STMT_CLOSE,
		mysql.COM_CHANGE_USER,
		mysql.COM_DEBUG,
	} {
		assert.Nil(t, getMySQLRequest(newTestMysqlPacket(t, arg, "")),
			fmt.Sprintf("%#x", arg))
	}
}

func TestIsAuthorizingCommands(t *testing.T) {
	assert.False(t, newTestDctx(nil).isAuthorizingCommands())
	assert.False(t, newTestDctx(&corev1.Service_Spec_Config_MySQL{}).isAuthorizingCommands())

	assert.False(t, newTestDctx(&corev1.Service_Spec_Config_MySQL{
		Authorization: &corev1.Service_Spec_Config_MySQL_Authorization{},
	}).isAuthorizingCommands())

	assert.False(t, newTestDctx(&corev1.Service_Spec_Config_MySQL{
		Authorization: &corev1.Service_Spec_Config_MySQL_Authorization{
			Mode: corev1.Service_Spec_Config_MySQL_Authorization_NONE,
		},
	}).isAuthorizingCommands())

	assert.True(t, newTestDctx(&corev1.Service_Spec_Config_MySQL{
		Authorization: &corev1.Service_Spec_Config_MySQL_Authorization{
			Mode: corev1.Service_Spec_Config_MySQL_Authorization_ALL,
		},
	}).isAuthorizingCommands())
}
