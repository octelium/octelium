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

package postgresutils

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"text/template"

	"github.com/lib/pq"
	"github.com/lib/pq/pqerror"
	"go.uber.org/zap"
)

const migrationTmpl = `

{{ range $val := .Tables }}
CREATE TABLE IF NOT EXISTS {{$val}} (
    id BIGSERIAL PRIMARY KEY,
		uid TEXT UNIQUE NOT NULL,
		created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
		api TEXT,
		version TEXT,
		kind TEXT,
    resource JSONB
);

CREATE INDEX IF NOT EXISTS idx_{{$val}}_name ON {{$val}}((resource->'metadata'->>'name'));
CREATE INDEX IF NOT EXISTS idx_{{$val}}_uid ON {{$val}}((resource->'metadata'->>'uid'));
CREATE INDEX IF NOT EXISTS idx_{{$val}}_created_at_ts ON {{$val}}(created_at);
{{ end }}
`

const uniqueNameIndexTmpl = `CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s
	(api COLLATE "C", version COLLATE "C", kind COLLATE "C", ((resource->'metadata'->>'name')) COLLATE "C")`

type migrationTmplArgs struct {
	Tables []string
}

var Tables = []string{
	"octelium_resources",
}

func Migrate(ctx context.Context, db *sql.DB) error {
	t, err := template.New("migration-tmpl").Parse(migrationTmpl)
	if err != nil {
		return err
	}

	var tpl bytes.Buffer

	args := migrationTmplArgs{
		Tables: Tables,
	}

	if err := t.Execute(&tpl, args); err != nil {
		panic(err)
	}

	tmpl := tpl.String()

	_, err = db.ExecContext(ctx, tmpl)
	if err != nil {
		return err
	}

	for _, table := range Tables {
		if err := migrateUniqueNameIndex(ctx, db, table); err != nil {
			return err
		}
	}

	return nil
}

func migrateUniqueNameIndex(ctx context.Context, db *sql.DB, table string) error {
	idxName := fmt.Sprintf("idx_%s_api_version_kind_name", table)

	_, err := db.ExecContext(ctx, fmt.Sprintf(uniqueNameIndexTmpl, idxName, table))
	pqErr := pq.As(err, pqerror.UniqueViolation)
	if pqErr == nil {
		return err
	}

	if pqErr.Constraint == idxName {
		zap.L().Error("Could not enforce unique resource names. Duplicate resource names must be removed",
			zap.String("table", table), zap.String("detail", pqErr.Detail))
	}

	return nil
}

func IsUniqueViolation(err error) bool {
	return pq.As(err, pqerror.UniqueViolation) != nil
}

func getPostgresURL(noDB bool) string {

	return GetPostgresURLFromArgs(&PostgresDBArgs{
		Username: func() string {
			ev := os.Getenv("OCTELIUM_POSTGRES_USERNAME")
			if ev != "" {
				return ev
			}

			return "postgres"
		}(),
		Password: os.Getenv("OCTELIUM_POSTGRES_PASSWORD"),
		Host: func() string {
			ev := os.Getenv("OCTELIUM_POSTGRES_HOST")
			if ev != "" {
				return ev
			}

			return "octelium-deps-postgresql.octelium.svc"
		}(),
		NoSSL: func() bool {
			return os.Getenv("OCTELIUM_POSTGRES_NOSSL") == "true"
		}(),
		DB: func() string {
			if noDB {
				return ""
			}
			return os.Getenv("OCTELIUM_POSTGRES_DATABASE")
		}(),
		Port: func() int {
			ev := os.Getenv("OCTELIUM_POSTGRES_PORT")
			if ev == "" || ev == "0" {
				return 5432
			}

			port, _ := strconv.Atoi(ev)
			if port == 0 {
				return 5432
			}

			return port
		}(),
	})
}

type PostgresDBArgs struct {
	Username string
	Password string
	Port     int
	Host     string
	DB       string
	NoSSL    bool
}

func GetPostgresURLFromArgs(a *PostgresDBArgs) string {
	if a == nil {
		return ""
	}

	if a.Username == "" {
		a.Username = "postgres"
	}

	if a.Port == 0 {
		a.Port = 5432
	}

	ret := url.URL{
		Scheme: "postgres",
		Path:   a.DB,
		Host:   net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port)),
		User: func() *url.Userinfo {
			if a.Password == "" {
				return url.User(a.Username)
			} else {
				return url.UserPassword(a.Username, a.Password)
			}
		}(),
	}

	if a.NoSSL {
		q := ret.Query()
		q.Set("sslmode", "disable")
		ret.RawQuery = q.Encode()
	} else {
		q := ret.Query()
		q.Set("sslmode", "require")
		ret.RawQuery = q.Encode()
	}

	return ret.String()
}

func NewDBWithURL(url string) (*sql.DB, error) {
	return sql.Open("postgres", url)
}

func NewDB() (*sql.DB, error) {
	return sql.Open("postgres", getPostgresURL(false))
}

func NewDBWithNODB() (*sql.DB, error) {
	return sql.Open("postgres", getPostgresURL(true))
}
