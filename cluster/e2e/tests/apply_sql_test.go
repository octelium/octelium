//go:build e2e

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

package tests

import (
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func applyPostgresMain(t *testing.T, a *applyCtx) {
	a.h.MustWaitService(t, "postgres-main")

	db := a.h.OpenSQL(t, "postgres", postgresutils.GetPostgresURLFromArgs(
		&postgresutils.PostgresDBArgs{
			Host:  "localhost",
			NoSSL: true,
			Port:  a.port("postgres-main"),
		}))

	_, err := db.Exec("SELECT current_database();")
	assert.Nil(t, err)
}

func applyPostgresContainer(t *testing.T, a *applyCtx) {
	h := a.h
	port := a.port("pg.production")

	h.MustWaitService(t, "pg.production")
	h.MustWaitServiceUpstream(t, "pg.production")

	t.Run("WrongPasswordRejected", func(t *testing.T) {
		db, err := sql.Open("postgres", postgresutils.GetPostgresURLFromArgs(
			&postgresutils.PostgresDBArgs{
				Host:     "localhost",
				NoSSL:    true,
				Username: "postgres",
				Password: "wrong-password",
				Port:     port,
			}))
		require.Nil(t, err)
		defer db.Close()

		_, err = db.Exec("SELECT current_database();")
		assert.NotNil(t, err)
	})

	t.Run("CRUD", func(t *testing.T) {
		db := h.OpenSQL(t, "postgres", postgresutils.GetPostgresURLFromArgs(
			&postgresutils.PostgresDBArgs{
				Host:     "localhost",
				NoSSL:    true,
				Username: "postgres",
				Password: "password",
				Port:     port,
			}))

		_, err := db.Exec("SELECT current_database();")
		require.Nil(t, err)

		_, err = db.Exec(`
CREATE TABLE users (
	id SERIAL PRIMARY KEY,
	name VARCHAR(100) NOT NULL,
	status VARCHAR(50) NOT NULL
);`)
		require.Nil(t, err)

		var insertedID int
		err = db.QueryRow(
			"INSERT INTO users (name, status) VALUES ($1, $2) RETURNING id",
			"john doe", "active").Scan(&insertedID)
		require.Nil(t, err)
		assert.True(t, insertedID > 0)

		const querySQL = "SELECT name, status FROM users WHERE id = $1"

		var name, status string
		err = db.QueryRow(querySQL, insertedID).Scan(&name, &status)
		require.Nil(t, err)
		assert.Equal(t, "john doe", name)
		assert.Equal(t, "active", status)

		res, err := db.Exec("UPDATE users SET status = $1 WHERE id = $2", "inactive", insertedID)
		require.Nil(t, err)

		rowsAffected, err := res.RowsAffected()
		require.Nil(t, err)
		assert.Equal(t, int64(1), rowsAffected)

		res, err = db.Exec("DELETE FROM users WHERE id = $1", insertedID)
		require.Nil(t, err)

		rowsAffected, err = res.RowsAffected()
		require.Nil(t, err)
		assert.Equal(t, int64(1), rowsAffected)

		err = db.QueryRow(querySQL, insertedID).Scan(&name, &status)
		assert.ErrorIs(t, err, sql.ErrNoRows)

		assert.Nil(t, postgresutils.Migrate(t.Context(), db))
	})
}

func applyMySQL(t *testing.T, a *applyCtx) {
	for _, svc := range []string{"mariadb", "mysql8", "mysql9"} {
		t.Run(svc, func(t *testing.T) {
			applyOneMySQL(t, a, svc)
		})
	}
}

func applyOneMySQL(t *testing.T, a *applyCtx, svc string) {
	h := a.h

	h.MustWaitServiceUpstream(t, svc)
	h.MustWaitService(t, svc)

	db := h.OpenSQL(t, "mysql", fmt.Sprintf("root:@tcp(%s)/mysql", a.addr(svc)))

	_, err := db.Exec("CREATE DATABASE IF NOT EXISTS mydb")
	require.Nil(t, err)

	rows, err := db.Query("SHOW DATABASES")
	require.Nil(t, err)
	rows.Close()

	_, err = db.Exec(`
CREATE TABLE users (
	id INT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(100) NOT NULL,
	status VARCHAR(50) NOT NULL
);`)
	require.Nil(t, err)

	res, err := db.Exec("INSERT INTO users (name, status) VALUES (?, ?)", "john doe", "active")
	require.Nil(t, err)

	insertedID, err := res.LastInsertId()
	require.Nil(t, err)

	var name, status string
	err = db.QueryRow("SELECT name, status FROM users WHERE id = ?", insertedID).
		Scan(&name, &status)
	require.Nil(t, err)
	assert.Equal(t, "john doe", name)

	res, err = db.Exec("UPDATE users SET status = ? WHERE id = ?", "inactive", insertedID)
	require.Nil(t, err)

	rowsAffected, err := res.RowsAffected()
	require.Nil(t, err)
	assert.Equal(t, int64(1), rowsAffected)

	_, err = db.Exec("DELETE FROM users WHERE id = ?", insertedID)
	assert.Nil(t, err)

	h.MustRun(t, fmt.Sprintf("octeliumctl del svc %s", svc))
}
