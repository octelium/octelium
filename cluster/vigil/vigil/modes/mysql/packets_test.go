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

func newTestPacket(seq byte, payload []byte) []byte {
	ret := make([]byte, 4+len(payload))
	ret[0] = byte(len(payload))
	ret[1] = byte(len(payload) >> 8)
	ret[2] = byte(len(payload) >> 16)
	ret[3] = seq
	copy(ret[4:], payload)
	return ret
}

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
	assert.Equal(t, 0, packetPayloadLen(newTestPacket(0, nil)))
	assert.Equal(t, 9, packetPayloadLen(newTestPacket(0, []byte("SELECT 1x"))))
	assert.Equal(t, mysql.MaxPayloadLen,
		packetPayloadLen(newTestFullPacket(0, mysql.COM_QUERY)))
}

func TestPacketReader(t *testing.T) {
	newQueryPacket := func(seq byte, query string) []byte {
		return newTestPacket(seq, append([]byte{mysql.COM_QUERY}, []byte(query)...))
	}

	{
		pkts := [][]byte{
			newQueryPacket(0, "SELECT 1"),
			newQueryPacket(0, "SELECT 2"),
			newTestPacket(0, []byte{mysql.COM_QUIT}),
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
			newTestPacket(1, []byte{mysql.COM_QUIT, 'a', 'b'}),
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
			newTestPacket(1, nil),
			newTestPacket(0, []byte{mysql.COM_CHANGE_USER}),
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
			newTestPacket(2, []byte{mysql.COM_CHANGE_USER}),
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
		newTestPacket(1, []byte{mysql.COM_QUIT, 'a', 'b'}),
		newTestPacket(0, []byte{mysql.COM_QUIT}),
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
