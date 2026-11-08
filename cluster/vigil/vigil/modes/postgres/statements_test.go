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

package postgres

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
)

func TestUpdateStatements(t *testing.T) {
	newStatementsDctx := func() *dctx {
		return &dctx{
			stmts:             newStatements(),
			unauthorizedQuery: "octelium_unauthorized_abcd",
		}
	}

	send := func(c *dctx, msgs ...pgproto3.FrontendMessage) {
		t.Helper()
		for _, msg := range msgs {
			assert.Nil(t, c.updateStatements(msg))
		}
	}

	answer := func(c *dctx) {
		c.rfqReceived.Store(c.rfqExpected)
	}

	assertStatement := func(c *dctx, name, query string) {
		t.Helper()
		ret, ok := c.stmts.get(name)
		assert.True(t, ok, name)
		assert.Equal(t, query, ret, name)
	}

	assertNoStatement := func(c *dctx, name string) {
		t.Helper()
		_, ok := c.stmts.get(name)
		assert.False(t, ok, name)
	}

	prepare := func(c *dctx, name, query string) {
		t.Helper()
		send(c, &pgproto3.Parse{Name: name, Query: query}, &pgproto3.Sync{})
		answer(c)
		assertStatement(c, name, query)
	}

	{
		c := newStatementsDctx()
		assertNoStatement(c, "s1")

		send(c, &pgproto3.Parse{Name: "s1", Query: "SELECT 1"})
		assertStatement(c, "s1", "SELECT 1")
		send(c, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Execute{})
		assertStatement(c, "s1", "SELECT 1")
		send(c, &pgproto3.Sync{})
		assertStatement(c, "s1", "SELECT 1")

		answer(c)
		send(c, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Execute{}, &pgproto3.Sync{})
		assertStatement(c, "s1", "SELECT 1")
	}

	{
		c := newStatementsDctx()
		prepare(c, "s1", "SELECT 1")

		send(c, &pgproto3.Parse{Name: "s1", Query: "SELECT 2"})
		assertStatement(c, "s1", "SELECT 2")
		send(c, &pgproto3.Sync{})
		answer(c)
		assertNoStatement(c, "s1")

		send(c, &pgproto3.Parse{Name: "s1", Query: "SELECT 1"}, &pgproto3.Sync{})
		answer(c)
		assertNoStatement(c, "s1")

		send(c, &pgproto3.Close{ObjectType: 'S', Name: "s1"}, &pgproto3.Sync{})
		answer(c)
		assertNoStatement(c, "s1")

		prepare(c, "s1", "SELECT 3")
	}

	{
		c := newStatementsDctx()
		prepare(c, "s1", "SELECT 1")
		prepare(c, "s2", "SELECT 2")

		send(c,
			&pgproto3.Close{ObjectType: 'S', Name: "s1"},
			&pgproto3.Close{ObjectType: 'P', Name: "s2"},
			&pgproto3.Flush{},
			&pgproto3.Close{ObjectType: 'S', Name: "s2"})
		assertNoStatement(c, "s1")
		assertNoStatement(c, "s2")
		send(c, &pgproto3.Sync{})
		answer(c)
		assertNoStatement(c, "s1")
		assertNoStatement(c, "s2")
		assert.Empty(t, c.stmts.committed)
		assert.Zero(t, c.stmts.size)

		prepare(c, "s1", "SELECT 3")
	}

	for _, failing := range []pgproto3.FrontendMessage{
		&pgproto3.Parse{Query: "SELECT"},
		&pgproto3.Bind{PreparedStatement: "s1"},
		&pgproto3.Describe{ObjectType: 'S', Name: "s1"},
		&pgproto3.Execute{},
		&pgproto3.Close{ObjectType: 'X', Name: "s1"},
		&pgproto3.Parse{Name: "s2", Query: "octelium_unauthorized_abcd"},
		&pgproto3.CopyFail{},
	} {
		c := newStatementsDctx()
		prepare(c, "s1", "SELECT 1")

		send(c, failing, &pgproto3.Close{ObjectType: 'S', Name: "s1"})
		assertNoStatement(c, "s1")
		send(c, &pgproto3.Sync{})
		answer(c)
		assertStatement(c, "s1", "SELECT 1")

		send(c, &pgproto3.Parse{Name: "s1", Query: "SELECT 2"}, &pgproto3.Sync{})
		answer(c)
		assertNoStatement(c, "s1")
	}

	{
		c := newStatementsDctx()
		prepare(c, "s1", "SELECT 1")

		send(c, &pgproto3.Parse{Query: "SELECT 2"}, &pgproto3.Sync{})
		send(c, &pgproto3.Close{ObjectType: 'S', Name: "s1"}, &pgproto3.Sync{})
		answer(c)
		assertStatement(c, "s1", "SELECT 1")
		assertStatement(c, "", "SELECT 2")
	}

	{
		c := newStatementsDctx()
		prepare(c, "", "SELECT 1")

		send(c, &pgproto3.Parse{Query: "SELECT 2"})
		assertStatement(c, "", "SELECT 2")
		send(c, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Parse{Query: "SELECT 3"})
		assertStatement(c, "", "SELECT 3")
		send(c, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
		answer(c)
		assertNoStatement(c, "")

		prepare(c, "", "SELECT 4")

		send(c, &pgproto3.Query{String: "SELECT 5"})
		assertNoStatement(c, "")
		answer(c)
		assertNoStatement(c, "")

		prepare(c, "", "SELECT 6")

		send(c, &pgproto3.Parse{Query: "octelium_unauthorized_abcd"})
		assertNoStatement(c, "")
		send(c, &pgproto3.Sync{})
		answer(c)
		assertNoStatement(c, "")
	}

	{
		c := newStatementsDctx()
		prepare(c, "", "SELECT 1")

		send(c, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
		send(c, &pgproto3.Query{String: "SELECT 2"})
		answer(c)
		assertStatement(c, "", "SELECT 1")
	}

	{
		c := newStatementsDctx()
		prepare(c, "s1", "SELECT 1")
		prepare(c, "s2", "SELECT 2")

		send(c, &pgproto3.Query{String: "COPY users FROM STDIN"})

		send(c, &pgproto3.Parse{Name: "s1", Query: "SELECT 3"})
		assertNoStatement(c, "s1")
		send(c, &pgproto3.Parse{Name: "s3", Query: "SELECT 4"})
		assertStatement(c, "s3", "SELECT 4")
		send(c, &pgproto3.Close{ObjectType: 'S', Name: "s2"})
		assertStatement(c, "s2", "SELECT 2")
		send(c, &pgproto3.Sync{})
		answer(c)

		assertNoStatement(c, "s1")
		assertStatement(c, "s2", "SELECT 2")
		assertStatement(c, "s3", "SELECT 4")
	}

	{
		c := newStatementsDctx()
		prepare(c, "s1", "SELECT 1")

		send(c, &pgproto3.Parse{Name: "s1", Query: "octelium_unauthorized_abcd"}, &pgproto3.Sync{})
		answer(c)
		assertStatement(c, "s1", "SELECT 1")
	}

	{
		c := newStatementsDctx()
		prefix := strings.Repeat("a", maxStatementNameLen)
		prepare(c, prefix+"1", "SELECT 1")
		assertStatement(c, prefix+"2", "SELECT 1")
		assertNoStatement(c, prefix[1:])

		send(c, &pgproto3.Close{ObjectType: 'S', Name: prefix + "2"}, &pgproto3.Sync{})
		answer(c)
		assertNoStatement(c, prefix+"1")
	}

	{
		c := newStatementsDctx()
		for i := range maxStatements {
			prepare(c, fmt.Sprintf("s%d", i), "SELECT 1")
		}

		assert.NotNil(t, c.updateStatements(&pgproto3.Parse{Name: "s", Query: "SELECT 1"}))
	}

	{
		c := newStatementsDctx()
		query := strings.Repeat("a", maxStatementsSize/2)
		prepare(c, "s1", query)
		prepare(c, "s2", query)
		assert.Equal(t, maxStatementsSize, c.stmts.size)

		assert.NotNil(t, c.updateStatements(&pgproto3.Parse{Name: "s3", Query: "SELECT 1"}))
	}
}
