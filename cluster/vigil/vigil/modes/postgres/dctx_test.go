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
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/stretchr/testify/assert"
)

func newTestDctx(pgCfg *corev1.Service_Spec_Config_Postgres, params map[string]string) *dctx {
	return &dctx{
		svcConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Postgres_{
				Postgres: pgCfg,
			},
		},
		startupMessage: &pgproto3.StartupMessage{
			Parameters: params,
		},
	}
}

func TestGetUpstreamConfig(t *testing.T) {
	upstream := &loadbalancer.Upstream{
		Host: "10.0.0.5",
		Port: 5432,
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
			User:     "postgres",
			Database: "postgres",
		}, nil)
		c.dbUser = c.getEffectiveUser()
		c.dbName = c.getEffectiveDB()

		pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
		assert.Nil(t, err, "%+v", err)

		assert.Equal(t, "10.0.0.5", pgCfg.Host)
		assert.Equal(t, uint16(5432), pgCfg.Port)
		assert.Equal(t, "postgres", pgCfg.User)
		assert.Equal(t, "postgres", pgCfg.Database)
		assert.Equal(t, "mypassword", pgCfg.Password)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{}, map[string]string{
			"user":     "linus",
			"database": "linusdb",
		})
		c.dbUser = c.getEffectiveUser()
		c.dbName = c.getEffectiveDB()

		pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
		assert.Nil(t, err, "%+v", err)

		assert.Equal(t, "linus", pgCfg.User)
		assert.Equal(t, "linusdb", pgCfg.Database)
	}

	{
		for _, arg := range []struct {
			sslMode corev1.Service_Spec_Config_Postgres_SSLMode
			isTLS   bool
		}{
			{corev1.Service_Spec_Config_Postgres_SSL_MODE_UNSET, true},
			{corev1.Service_Spec_Config_Postgres_DISABLE, false},
			{corev1.Service_Spec_Config_Postgres_REQUIRE, true},
		} {
			c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
				User:    "postgres",
				SslMode: arg.sslMode,
			}, nil)
			c.dbUser = c.getEffectiveUser()
			c.dbName = c.getEffectiveDB()

			pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, arg.isTLS, pgCfg.TLSConfig != nil, arg.sslMode.String())
		}
	}
}

func TestGetUpstreamConfigDownstreamInjection(t *testing.T) {
	upstream := &loadbalancer.Upstream{
		Host: "10.0.0.5",
		Port: 5432,
	}

	for _, arg := range []string{
		"postgres host=attacker.example.com port=5432",
		`postgres' host=attacker.example.com '`,
		`postgres\' host=attacker.example.com`,
		`postgres\\ host=attacker.example.com`,
		"postgres sslmode=disable",
		"postgres'",
		`postgres\`,
		"postgres passfile=/etc/passwd",
		"postgres host=/var/run/postgresql",
	} {
		{
			c := newTestDctx(&corev1.Service_Spec_Config_Postgres{}, map[string]string{
				"user":     "postgres",
				"database": arg,
			})
			c.dbUser = c.getEffectiveUser()
			c.dbName = c.getEffectiveDB()

			pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
			assert.Nil(t, err, "%+v", err)

			assert.Equal(t, "10.0.0.5", pgCfg.Host, arg)
			assert.Equal(t, uint16(5432), pgCfg.Port, arg)
			assert.Equal(t, arg, pgCfg.Database, arg)
			assert.Equal(t, "mypassword", pgCfg.Password, arg)
			assert.NotNil(t, pgCfg.TLSConfig, arg)
			for _, fallback := range pgCfg.Fallbacks {
				assert.Equal(t, "10.0.0.5", fallback.Host, arg)
				assert.Equal(t, uint16(5432), fallback.Port, arg)
			}
		}

		{
			c := newTestDctx(&corev1.Service_Spec_Config_Postgres{}, map[string]string{
				"user":     arg,
				"database": "postgres",
			})
			c.dbUser = c.getEffectiveUser()
			c.dbName = c.getEffectiveDB()

			pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
			assert.Nil(t, err, "%+v", err)

			assert.Equal(t, "10.0.0.5", pgCfg.Host, arg)
			assert.Equal(t, uint16(5432), pgCfg.Port, arg)
			assert.Equal(t, arg, pgCfg.User, arg)
			assert.Equal(t, "mypassword", pgCfg.Password, arg)
			assert.NotNil(t, pgCfg.TLSConfig, arg)
			for _, fallback := range pgCfg.Fallbacks {
				assert.Equal(t, "10.0.0.5", fallback.Host, arg)
				assert.Equal(t, uint16(5432), fallback.Port, arg)
			}
		}
	}
}

func TestGetUpstreamConfigSecretValue(t *testing.T) {
	upstream := &loadbalancer.Upstream{
		Host: "10.0.0.5",
		Port: 5432,
	}

	for _, arg := range []string{
		"my password",
		`my'password`,
		`my\password`,
		`my\\'password`,
		"",
	} {
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
			User:     "postgres",
			Database: "postgres",
		}, nil)
		c.dbUser = c.getEffectiveUser()
		c.dbName = c.getEffectiveDB()

		pgCfg, err := c.getUpstreamConfig(upstream, arg)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, arg, pgCfg.Password, arg)
	}
}

func TestIsExtendedProtocolMessage(t *testing.T) {
	for _, arg := range []struct {
		msg        pgproto3.FrontendMessage
		isExtended bool
	}{
		{&pgproto3.Query{}, false},
		{&pgproto3.FunctionCall{}, false},
		{&pgproto3.CopyData{}, false},
		{&pgproto3.CopyDone{}, false},
		{&pgproto3.CopyFail{}, false},
		{&pgproto3.Parse{}, true},
		{&pgproto3.Bind{}, true},
		{&pgproto3.Execute{}, true},
		{&pgproto3.Describe{}, true},
		{&pgproto3.Close{}, true},
		{&pgproto3.Flush{}, true},
	} {
		assert.Equal(t, arg.isExtended, isExtendedProtocolMessage(arg.msg),
			fmt.Sprintf("%T", arg.msg))
	}
}

func TestGetMessageLogInfo(t *testing.T) {
	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{}, nil)

		for _, arg := range []struct {
			msg pgproto3.FrontendMessage
			typ corev1.AccessLog_Entry_Info_Postgres_Type
		}{
			{&pgproto3.Query{String: "SELECT 1"}, corev1.AccessLog_Entry_Info_Postgres_QUERY},
			{&pgproto3.Parse{Query: "SELECT 1"}, corev1.AccessLog_Entry_Info_Postgres_PARSE},
			{&pgproto3.Bind{}, corev1.AccessLog_Entry_Info_Postgres_BIND},
			{&pgproto3.Execute{}, corev1.AccessLog_Entry_Info_Postgres_EXECUTE},
			{&pgproto3.Close{}, corev1.AccessLog_Entry_Info_Postgres_CLOSE},
			{&pgproto3.FunctionCall{}, corev1.AccessLog_Entry_Info_Postgres_FUNCTION_CALL},
		} {
			info := c.getMessageLogInfo(arg.msg)
			assert.NotNil(t, info, fmt.Sprintf("%T", arg.msg))
			assert.Equal(t, arg.typ, info.Type, fmt.Sprintf("%T", arg.msg))
			assert.False(t, info.IsTruncated, fmt.Sprintf("%T", arg.msg))
		}

		for _, arg := range []pgproto3.FrontendMessage{
			&pgproto3.Describe{},
			&pgproto3.Flush{},
			&pgproto3.CopyData{},
			&pgproto3.CopyDone{},
			&pgproto3.CopyFail{},
			&pgproto3.Sync{},
			&pgproto3.Terminate{},
		} {
			assert.Nil(t, c.getMessageLogInfo(arg), fmt.Sprintf("%T", arg))
		}
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{}, nil)

		info := c.getMessageLogInfo(&pgproto3.Query{String: "SELECT 1"})
		assert.Equal(t, "SELECT 1", info.GetQuery().Query)

		info = c.getMessageLogInfo(&pgproto3.Parse{Name: "stmt", Query: "SELECT 1"})
		assert.Equal(t, "SELECT 1", info.GetParse().Query)
		assert.Equal(t, "stmt", info.GetParse().Name)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
			Visibility: &corev1.Service_Spec_Config_Postgres_Visibility{
				DisableQuery: true,
			},
		}, nil)

		info := c.getMessageLogInfo(&pgproto3.Query{String: "SELECT 1"})
		assert.Equal(t, corev1.AccessLog_Entry_Info_Postgres_QUERY, info.Type)
		assert.Equal(t, "", info.GetQuery().Query)
		assert.False(t, info.IsTruncated)

		info = c.getMessageLogInfo(&pgproto3.Parse{Name: "stmt", Query: "SELECT 1"})
		assert.Equal(t, corev1.AccessLog_Entry_Info_Postgres_PARSE, info.Type)
		assert.Equal(t, "", info.GetParse().Query)
		assert.Equal(t, "stmt", info.GetParse().Name)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{}, nil)

		query := strings.Repeat("a", maxLoggedQueryLen+100)

		info := c.getMessageLogInfo(&pgproto3.Query{String: query})
		assert.Len(t, info.GetQuery().Query, maxLoggedQueryLen)
		assert.True(t, info.IsTruncated)

		info = c.getMessageLogInfo(&pgproto3.Parse{Query: query})
		assert.Len(t, info.GetParse().Query, maxLoggedQueryLen)
		assert.True(t, info.IsTruncated)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
			Visibility: &corev1.Service_Spec_Config_Postgres_Visibility{
				DisableQuery: true,
			},
		}, nil)

		info := c.getMessageLogInfo(&pgproto3.Query{
			String: strings.Repeat("a", maxLoggedQueryLen+100)})
		assert.Equal(t, "", info.GetQuery().Query)
		assert.False(t, info.IsTruncated)
	}
}

func TestTruncateQuery(t *testing.T) {
	for _, arg := range []struct {
		query string
		out   string
	}{
		{"", ""},
		{"SELECT 1", "SELECT 1"},
		{strings.Repeat("a", maxLoggedQueryLen), strings.Repeat("a", maxLoggedQueryLen)},
		{strings.Repeat("a", maxLoggedQueryLen+1), strings.Repeat("a", maxLoggedQueryLen)},
	} {
		assert.Equal(t, arg.out, truncateQuery(arg.query))
	}

	{
		query := strings.Repeat("a", maxLoggedQueryLen-1) + "€"
		out := truncateQuery(query)
		assert.True(t, utf8.ValidString(out))
		assert.Equal(t, strings.Repeat("a", maxLoggedQueryLen-1), out)
	}
}
