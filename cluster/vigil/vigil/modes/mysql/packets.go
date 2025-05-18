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
	"io"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pkg/errors"
)

const serverVersion = "8.0.0-Octelium"

type mysqlPacket struct {
	typ     byte
	raw     []byte
	len     int
	content []byte
}

func decodePacket(packetBytes []byte) (*mysqlPacket, error) {
	packetLen := len(packetBytes)

	if len(packetBytes) < 1 {
		return nil, errors.Errorf("Empty packet")
	}

	ret := &mysqlPacket{
		raw: packetBytes,
		typ: packetBytes[0],
		len: packetLen,
	}

	if packetLen > 1 {
		ret.content = packetBytes[1:]
	}

	return ret, nil
}

func (p *mysqlPacket) isQuit() bool {
	return p.typ == mysql.COM_QUIT
}

func (p *mysqlPacket) isQuery() bool {
	return p.typ == mysql.COM_QUERY
}

func (p *mysqlPacket) isPreparedStatement() bool {
	return p.typ == mysql.COM_STMT_PREPARE
}

func (p *mysqlPacket) isExecuteStatement() bool {
	return p.typ == mysql.COM_STMT_EXECUTE
}

func (p *mysqlPacket) isCloseStatement() bool {
	return p.typ == mysql.COM_STMT_CLOSE
}

func (p *mysqlPacket) isResetStatement() bool {
	return p.typ == mysql.COM_STMT_RESET
}

func (p *mysqlPacket) isFetchStatement() bool {
	return p.typ == mysql.COM_STMT_FETCH
}

func (p *mysqlPacket) isChangeUser() bool {
	return p.typ == mysql.COM_CHANGE_USER
}

func (p *mysqlPacket) isInitDB() bool {
	return p.typ == mysql.COM_INIT_DB
}

func (p *mysqlPacket) isCreateDB() bool {
	return p.typ == mysql.COM_CREATE_DB
}

func (p *mysqlPacket) isDropDB() bool {
	return p.typ == mysql.COM_DROP_DB
}

func (p *mysqlPacket) isDebug() bool {
	return p.typ == mysql.COM_DEBUG
}

type packetQuery struct {
	query string
}

type packetPreparedStatement struct {
	query string
}

type packetExecuteStatement struct {
}

type packetInitDB struct {
	db string
}

type packetCreateDB struct {
	db string
}

type packetDropDB struct {
	db string
}

type packetQuit struct{}

func (p *mysqlPacket) toQuery() *packetQuery {
	return &packetQuery{
		query: string(p.content),
	}
}

func (p *mysqlPacket) toPreparedStatement() *packetPreparedStatement {
	return &packetPreparedStatement{
		query: string(p.content),
	}
}

func (p *mysqlPacket) toInitDB() *packetInitDB {
	return &packetInitDB{
		db: string(p.content),
	}
}

func (p *mysqlPacket) toCreateDB() *packetCreateDB {
	return &packetCreateDB{
		db: string(p.content),
	}
}

func (p *mysqlPacket) toDropDB() *packetDropDB {
	return &packetDropDB{
		db: string(p.content),
	}
}

func (p *mysqlPacket) toQuit() *packetQuit {
	return &packetQuit{}
}

func readPacket(conn io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}

	payloadLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if payloadLen == 0 {
		return header[:], nil
	}

	payload := make([]byte, payloadLen)
	n, err := io.ReadFull(conn, payload)
	if err != nil {
		return nil, err
	}

	return append(header[:], payload[0:n]...), nil
}

func writePacket(pkt []byte, conn io.Writer) error {
	_, err := conn.Write(pkt)
	if err != nil {
		return err
	}
	return nil
}
