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

package suite

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pgErrInsufficientPrivilege = "42501"
	pgErrUndefinedTable        = "42P01"

	mysqlConnectBudget = 3 * time.Minute

	unauthorizedMySQLError = "Octelium: Unauthorized"
)

type postgresConn struct {
	net.Conn
	deadline time.Time
}

func (c *postgresConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() || deadline.After(c.deadline) {
		deadline = c.deadline
	}
	return c.Conn.SetDeadline(deadline)
}

type postgresDialer struct{}

func (d *postgresDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialTimeout(network, address, 10*time.Second)
}

func (d *postgresDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return nil, err
	}
	ret := &postgresConn{Conn: conn, deadline: time.Now().Add(2 * harness.SQLConnectBudget)}
	if err := ret.SetDeadline(ret.deadline); err != nil {
		conn.Close()
		return nil, err
	}
	return ret, nil
}

func denySQLUpdateRules(queryAttr, prepareAttr string) []*corev1.InlinePolicy {
	return []*corev1.InlinePolicy{
		{
			Name: "deny-update",
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					harness.MatchRule("deny-query", 0, corev1.Policy_Spec_Rule_DENY,
						fmt.Sprintf(`%s.startsWith("UPDATE")`, queryAttr)),
					harness.MatchRule("deny-prepared", 0, corev1.Policy_Spec_Rule_DENY,
						fmt.Sprintf(`%s.startsWith("UPDATE")`, prepareAttr)),
				},
			},
		},
	}
}

func pgErrorCode(err error) string {
	if err == nil {
		return ""
	}

	var pgErr *pq.Error
	if errors.As(err, &pgErr) {
		return string(pgErr.Code)
	}

	return ""
}

func testVigilPostgres(t *testing.T, h *harness.H) {
	pg := h.Scenario.Storage.Postgres
	if h.State.PostgresPassword == "" || pg.Host == "" {
		t.Skip("this scenario does not expose a PostgreSQL upstream")
	}

	secret := h.CreateSecret(t, "", h.State.PostgresPassword)

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_POSTGRES,
			Port: uint32(pg.Port),
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("postgres://%s:%d", pg.Host, pg.Port),
					},
				},
				Type: &corev1.Service_Spec_Config_Postgres_{
					Postgres: &corev1.Service_Spec_Config_Postgres{
						User:     pg.Username,
						Database: pg.Database,
						Auth: &corev1.Service_Spec_Config_Postgres_Auth{
							Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_{
								Password: &corev1.Service_Spec_Config_Postgres_Auth_Password{
									Type: &corev1.Service_Spec_Config_Postgres_Auth_Password_FromSecret{
										FromSecret: secret.Metadata.Name,
									},
								},
							},
						},
						Authorization: &corev1.Service_Spec_Config_Postgres_Authorization{
							Mode: corev1.Service_Spec_Config_Postgres_Authorization_ALL,
						},
					},
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	port := h.Port()
	h.Connect(t, harness.ConnectOpts{Publish: map[string]int{svc.Metadata.Name: port}})

	openDB := func(t *testing.T, username string) *sql.DB {
		t.Helper()

		connector, err := pq.NewConnector(postgresutils.GetPostgresURLFromArgs(
			&postgresutils.PostgresDBArgs{
				Host:     "localhost",
				Port:     port,
				NoSSL:    true,
				Username: username,
			}) + "&connect_timeout=10")
		if err != nil {
			t.Fatalf("%+v", err)
		}

		connector.Dialer(&postgresDialer{})
		db := sql.OpenDB(connector)
		t.Cleanup(func() { db.Close() })
		h.Eventually(t, "the PostgreSQL upstream to accept connections",
			harness.SQLConnectBudget, db.PingContext)
		return db
	}

	table := fmt.Sprintf("octelium_e2e_%s", utilrand.GetRandomStringCanonical(8))
	update := fmt.Sprintf("UPDATE %s SET status = 'inactive'", table)

	t.Run("QueryReachesUpstream", func(t *testing.T) {
		db := openDB(t, "")

		_, err := db.Exec(update)
		require.NotNil(t, err, "the query must be refused by the upstream database")
		assert.Equal(t, pgErrUndefinedTable, pgErrorCode(err),
			"the query did not reach the upstream database: %+v", err)
	})

	t.Run("CopyAndRollback", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), harness.SQLConnectBudget)
		defer cancel()

		db := openDB(t, "")
		conn, err := db.Conn(ctx)
		require.Nil(t, err)
		defer conn.Close()

		_, err = conn.ExecContext(ctx, fmt.Sprintf(
			"CREATE TEMP TABLE %s (id INT PRIMARY KEY, payload TEXT NOT NULL)", table))
		require.Nil(t, err)

		tx, err := conn.BeginTx(ctx, nil)
		require.Nil(t, err)
		defer tx.Rollback()

		stmt, err := tx.PrepareContext(ctx, pq.CopyIn(table, "id", "payload"))
		require.Nil(t, err)
		defer stmt.Close()

		const total = 128
		payload := strings.Repeat("octelium\tcopy\n"+h.Name(), 256)
		for i := range total {
			_, err = stmt.ExecContext(ctx, i, payload)
			require.Nil(t, err)
		}
		_, err = stmt.ExecContext(ctx)
		require.Nil(t, err)
		require.Nil(t, stmt.Close())
		require.Nil(t, tx.Commit())

		tx, err = conn.BeginTx(ctx, nil)
		require.Nil(t, err)
		defer tx.Rollback()
		_, err = tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE id = $1", table), 0)
		require.Nil(t, err)
		require.Nil(t, tx.Rollback())

		rows, err := conn.QueryContext(ctx, fmt.Sprintf("SELECT id, payload FROM %s ORDER BY id", table))
		require.Nil(t, err)
		defer rows.Close()

		var count int
		for rows.Next() {
			var id int
			var got string
			require.Nil(t, rows.Scan(&id, &got))
			assert.Equal(t, count, id)
			assert.Equal(t, payload, got)
			count++
		}
		require.Nil(t, rows.Err())
		assert.Equal(t, total, count,
			"the bulk COPY and rolled back DELETE must preserve every row")
	})

	t.Run("ExistingConnectionPolicy", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*harness.SQLConnectBudget)
		defer cancel()

		db := openDB(t, "")
		conn, err := db.Conn(ctx)
		require.Nil(t, err)
		defer conn.Close()

		var before int
		require.Nil(t, conn.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&before))
		_, err = conn.ExecContext(ctx, fmt.Sprintf(
			"CREATE TEMP TABLE %s (status TEXT NOT NULL)", table))
		require.Nil(t, err)
		_, err = conn.ExecContext(ctx, fmt.Sprintf("INSERT INTO %s VALUES ('active')", table))
		require.Nil(t, err)

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: denySQLUpdateRules(
				"ctx.request.postgres.query.query", "ctx.request.postgres.parse.query"),
		}
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the existing connection to enforce the updated policy",
			harness.DecisionBudget, func(ctx context.Context) error {
				_, err := conn.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET status = status", table))
				if code := pgErrorCode(err); code != pgErrInsufficientPrivilege {
					return errors.Errorf("got the error code %q, want %q: %+v",
						code, pgErrInsufficientPrivilege, err)
				}
				return nil
			})

		tx, err := conn.BeginTx(ctx, nil)
		require.Nil(t, err)
		defer tx.Rollback()
		_, err = tx.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET status = $1", table), "inactive")
		require.NotNil(t, err)
		assert.Equal(t, pgErrInsufficientPrivilege, pgErrorCode(err), "%+v", err)

		var status string
		require.Nil(t, tx.QueryRowContext(ctx, fmt.Sprintf("SELECT status FROM %s", table)).Scan(&status))
		assert.Equal(t, "active", status,
			"the denied prepared UPDATE must not change or abort the upstream transaction")
		require.Nil(t, tx.Rollback())

		svc.Spec.Authorization = nil
		svc = h.UpdateService(t, svc)
		h.Eventually(t, "the existing connection to regain UPDATE access",
			harness.DecisionBudget, func(ctx context.Context) error {
				_, err := conn.ExecContext(ctx, update)
				return err
			})

		require.Nil(t, conn.QueryRowContext(ctx, fmt.Sprintf("SELECT status FROM %s", table)).Scan(&status))
		assert.Equal(t, "inactive", status)
		var after int
		require.Nil(t, conn.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&after))
		assert.Equal(t, before, after,
			"policy changes must be enforced without replacing the upstream connection")
	})

	svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
		InlinePolicies: denySQLUpdateRules(
			"ctx.request.postgres.query.query", "ctx.request.postgres.parse.query"),
	}
	svc = h.UpdateService(t, svc)

	t.Run("QueryDenied", func(t *testing.T) {
		db := openDB(t, "")

		h.Eventually(t, "the Service policy to deny the UPDATE query",
			harness.DecisionBudget, func(ctx context.Context) error {
				_, err := db.ExecContext(ctx, update)
				if code := pgErrorCode(err); code != pgErrInsufficientPrivilege {
					return errors.Errorf("got the error code %q, want %q: %+v",
						code, pgErrInsufficientPrivilege, err)
				}
				return nil
			})

		var got int
		require.Nil(t, db.QueryRow("SELECT 1").Scan(&got),
			"the connection must survive a denied query")
		assert.Equal(t, 1, got)
	})

	t.Run("PreparedStatementDenied", func(t *testing.T) {
		db := openDB(t, "")

		_, err := db.Exec(fmt.Sprintf("UPDATE %s SET status = $1", table), "inactive")
		require.NotNil(t, err)
		assert.Equal(t, pgErrInsufficientPrivilege, pgErrorCode(err), "%+v", err)

		var got int
		require.Nil(t, db.QueryRow("SELECT 1").Scan(&got))
		assert.Equal(t, 1, got)
	})

	t.Run("ConnectDenied", func(t *testing.T) {
		blocked := utilrand.GetRandomStringCanonical(8)

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Name: "deny-connect-user",
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							harness.MatchRule("deny-user", 0, corev1.Policy_Spec_Rule_DENY,
								fmt.Sprintf(`ctx.request.postgres.connect.user == %q`, blocked)),
						},
					},
				},
			},
		}
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the Service policy to deny the blocked database user",
			harness.DecisionBudget, func(ctx context.Context) error {
				db, err := sql.Open("postgres", postgresutils.GetPostgresURLFromArgs(
					&postgresutils.PostgresDBArgs{
						Host:     "localhost",
						Port:     port,
						NoSSL:    true,
						Username: blocked,
					}))
				if err != nil {
					return err
				}
				defer db.Close()

				if err := db.PingContext(ctx); err == nil {
					return errors.Errorf("the blocked database user is still allowed")
				}
				return nil
			})

		db := openDB(t, pg.Username)

		var got int
		require.Nil(t, db.QueryRow("SELECT 1").Scan(&got),
			"the other database users must still be allowed")
		assert.Equal(t, 1, got)
	})
}

func testVigilMySQL(t *testing.T, h *harness.H) {
	h.Require(t, capHeavyUpstreams)

	password := utilrand.GetRandomStringCanonical(16)
	secret := h.CreateSecret(t, "", password)

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_MYSQL,
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: denySQLUpdateRules(
					"ctx.request.mysql.query.query",
					"ctx.request.mysql.prepareStatement.query"),
			},
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Container_{
						Container: &corev1.Service_Spec_Config_Upstream_Container{
							Image: "mysql:8",
							Port:  3306,
							Env: []*corev1.Service_Spec_Config_Upstream_Container_Env{
								{
									Name: "MYSQL_ROOT_PASSWORD",
									Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{
										Value: password,
									},
								},
							},
						},
					},
				},
				Type: &corev1.Service_Spec_Config_Mysql{
					Mysql: &corev1.Service_Spec_Config_MySQL{
						User:     "root",
						Database: "mysql",
						Auth: &corev1.Service_Spec_Config_MySQL_Auth{
							Type: &corev1.Service_Spec_Config_MySQL_Auth_Password_{
								Password: &corev1.Service_Spec_Config_MySQL_Auth_Password{
									Type: &corev1.Service_Spec_Config_MySQL_Auth_Password_FromSecret{
										FromSecret: secret.Metadata.Name,
									},
								},
							},
						},
						Authorization: &corev1.Service_Spec_Config_MySQL_Authorization{
							Mode: corev1.Service_Spec_Config_MySQL_Authorization_ALL,
						},
					},
				},
			},
		},
	})

	h.MustWaitServiceUpstream(t, svc.Metadata.Name)
	h.MustWaitService(t, svc.Metadata.Name)

	port := h.Port()
	h.Connect(t, harness.ConnectOpts{Publish: map[string]int{svc.Metadata.Name: port}})

	db, err := harness.ConnectSQL("mysql",
		fmt.Sprintf("root:@tcp(localhost:%d)/mysql", port), mysqlConnectBudget)
	require.Nil(t, err, "could not reach the MySQL upstream")
	t.Cleanup(func() { db.Close() })

	table := fmt.Sprintf("octelium_e2e_%s", utilrand.GetRandomStringCanonical(8))

	_, err = db.Exec(fmt.Sprintf(
		"CREATE TABLE %s (id INT PRIMARY KEY, status VARCHAR(50) NOT NULL);", table))
	require.Nil(t, err, "the allowed DDL query must reach the upstream")

	t.Cleanup(func() {
		db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s;", table))
	})

	_, err = db.Exec(fmt.Sprintf("INSERT INTO %s (id, status) VALUES (1, 'active');", table))
	require.Nil(t, err)

	t.Run("QueryDenied", func(t *testing.T) {
		_, err := db.Exec(fmt.Sprintf("UPDATE %s SET status = 'inactive' WHERE id = 1;", table))
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), unauthorizedMySQLError)
	})

	t.Run("PreparedStatementDenied", func(t *testing.T) {
		_, err := db.Exec(
			fmt.Sprintf("UPDATE %s SET status = ? WHERE id = ?", table), "inactive", 1)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), unauthorizedMySQLError)
	})

	t.Run("DeniedQueriesNeverRun", func(t *testing.T) {
		var status string
		require.Nil(t, db.QueryRow(
			fmt.Sprintf("SELECT status FROM %s WHERE id = ?", table), 1).Scan(&status))
		assert.Equal(t, "active", status,
			"a denied UPDATE must never reach the upstream database")
	})

	t.Run("ConnectionSurvives", func(t *testing.T) {
		assert.Nil(t, db.Ping())

		var got int
		require.Nil(t, db.QueryRow("SELECT 1").Scan(&got))
		assert.Equal(t, 1, got)
	})
}
