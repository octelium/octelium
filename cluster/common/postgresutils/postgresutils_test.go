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
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPostgresURL(t *testing.T) {
	assert.Empty(t, GetPostgresURLFromArgs(nil))
	for _, host := range []string{"db.example.com", "2001:db8::1"} {
		for _, noSSL := range []bool{true, false} {
			args := &PostgresDBArgs{Host: host, Username: "user:@/?#", Password: "password:@/?#", DB: "database?sslmode=disable", NoSSL: noSSL}
			u, err := url.Parse(GetPostgresURLFromArgs(args))
			assert.Nil(t, err)
			assert.Equal(t, "postgres", u.Scheme)
			assert.Equal(t, host, u.Hostname())
			assert.Equal(t, "5432", u.Port())
			assert.Equal(t, args.Username, u.User.Username())
			password, ok := u.User.Password()
			assert.True(t, ok)
			assert.Equal(t, args.Password, password)
			assert.Equal(t, "/"+args.DB, u.Path)
			wantSSL := "require"
			if noSSL {
				wantSSL = "disable"
			}
			assert.Equal(t, wantSSL, u.Query().Get("sslmode"))
		}
	}
	u, err := url.Parse(GetPostgresURLFromArgs(&PostgresDBArgs{Host: "localhost"}))
	assert.Nil(t, err)
	assert.Equal(t, "postgres", u.User.Username())
	_, ok := u.User.Password()
	assert.False(t, ok)
}

func TestPostgresEnvironment(t *testing.T) {
	for _, name := range []string{"USERNAME", "PASSWORD", "HOST", "NOSSL", "DATABASE", "PORT"} {
		t.Setenv("OCTELIUM_POSTGRES_"+name, "")
	}
	u, err := url.Parse(getPostgresURL(false))
	assert.Nil(t, err)
	assert.Equal(t, "octelium-deps-postgresql.octelium.svc", u.Hostname())
	assert.Equal(t, "5432", u.Port())
	t.Setenv("OCTELIUM_POSTGRES_DATABASE", "database")
	t.Setenv("OCTELIUM_POSTGRES_HOST", "localhost")
	t.Setenv("OCTELIUM_POSTGRES_USERNAME", "user")
	t.Setenv("OCTELIUM_POSTGRES_NOSSL", "true")
	for _, tc := range []struct{ input, want string }{{"", "5432"}, {"0", "5432"}, {"invalid", "5432"}, {"5433", "5433"}} {
		t.Setenv("OCTELIUM_POSTGRES_PORT", tc.input)
		u, err := url.Parse(getPostgresURL(false))
		assert.Nil(t, err)
		assert.Equal(t, tc.want, u.Port())
		assert.Equal(t, "/database", u.Path)
		assert.Equal(t, "disable", u.Query().Get("sslmode"))
		u, err = url.Parse(getPostgresURL(true))
		assert.Nil(t, err)
		assert.Empty(t, u.Path)
	}
	db, err := NewDB()
	assert.Nil(t, err)
	assert.Nil(t, db.Close())
	db, err = NewDBWithNODB()
	assert.Nil(t, err)
	assert.Nil(t, db.Close())
	db, err = NewDBWithURL("postgres://%")
	assert.Nil(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	assert.NotNil(t, db.PingContext(ctx))
	assert.Nil(t, db.Close())
}
