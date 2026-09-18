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
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
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

func hasPlaintextFallback(pgCfg *pgconn.Config) bool {
	for _, fallback := range pgCfg.Fallbacks {
		if fallback.TLSConfig == nil {
			return true
		}
	}
	return false
}

func TestGetUpstreamConfigSSLMode(t *testing.T) {
	upstream := &loadbalancer.Upstream{
		Host: "10.0.0.5",
		Port: 5432,
	}

	newCfg := func(t *testing.T,
		sslMode corev1.Service_Spec_Config_Postgres_SSLMode) *pgconn.Config {
		t.Helper()

		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
			User:    "postgres",
			SslMode: sslMode,
		}, nil)
		c.dbUser = c.getEffectiveUser()

		pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
		assert.Nil(t, err, "%+v", err)
		return pgCfg
	}

	for _, arg := range []struct {
		sslMode              corev1.Service_Spec_Config_Postgres_SSLMode
		isTLS                bool
		canFallbackPlaintext bool
	}{
		{corev1.Service_Spec_Config_Postgres_SSL_MODE_UNSET, true, true},
		{corev1.Service_Spec_Config_Postgres_DISABLE, false, false},
		{corev1.Service_Spec_Config_Postgres_REQUIRE, true, false},
		{corev1.Service_Spec_Config_Postgres_VERIFY_CA, true, false},
		{corev1.Service_Spec_Config_Postgres_VERIFY_FULL, true, false},
	} {
		pgCfg := newCfg(t, arg.sslMode)
		assert.Equal(t, arg.isTLS, pgCfg.TLSConfig != nil, arg.sslMode.String())
		assert.Equal(t, arg.canFallbackPlaintext, hasPlaintextFallback(pgCfg),
			arg.sslMode.String())
	}

	{
		pgCfg := newCfg(t, corev1.Service_Spec_Config_Postgres_REQUIRE)
		assert.True(t, pgCfg.TLSConfig.InsecureSkipVerify)
		assert.Nil(t, pgCfg.TLSConfig.VerifyPeerCertificate)
	}

	{
		pgCfg := newCfg(t, corev1.Service_Spec_Config_Postgres_VERIFY_CA)
		assert.True(t, pgCfg.TLSConfig.InsecureSkipVerify)
		assert.NotNil(t, pgCfg.TLSConfig.VerifyPeerCertificate)
	}

	{
		pgCfg := newCfg(t, corev1.Service_Spec_Config_Postgres_VERIFY_FULL)
		assert.False(t, pgCfg.TLSConfig.InsecureSkipVerify)
		assert.Nil(t, pgCfg.TLSConfig.VerifyPeerCertificate)
		assert.Equal(t, upstream.Host, pgCfg.TLSConfig.ServerName)
	}
}

func TestSetUpstreamTLSConfig(t *testing.T) {
	ctx := context.Background()

	upstream := &loadbalancer.Upstream{
		Host: "10.0.0.5",
		Port: 5432,
	}

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "svc",
		},
		Spec:   &corev1.Service_Spec{},
		Status: &corev1.Service_Status{},
	}

	ca, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err, "%+v", err)

	caPEM, err := utils_cert.GetCertificatePEMStr(ca.Certificate)
	assert.Nil(t, err, "%+v", err)

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
			SslMode: corev1.Service_Spec_Config_Postgres_VERIFY_FULL,
		}, nil)

		pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
		assert.Nil(t, err, "%+v", err)

		assert.Nil(t, c.setUpstreamTLSConfig(ctx, svc, pgCfg, upstream))
		assert.Nil(t, pgCfg.TLSConfig.RootCAs)
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
			SslMode: corev1.Service_Spec_Config_Postgres_VERIFY_FULL,
		}, nil)
		c.svcConfig.Tls = &corev1.Service_Spec_Config_TLS{
			TrustedCAs: []string{caPEM},
		}

		pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
		assert.Nil(t, err, "%+v", err)

		assert.Nil(t, c.setUpstreamTLSConfig(ctx, svc, pgCfg, upstream))
		assert.NotNil(t, pgCfg.TLSConfig.RootCAs)
		assert.True(t, pgCfg.TLSConfig.RootCAs.Equal(caPool(t, ca.Certificate)))
	}

	{
		c := newTestDctx(&corev1.Service_Spec_Config_Postgres{
			SslMode: corev1.Service_Spec_Config_Postgres_SSL_MODE_UNSET,
		}, nil)
		c.svcConfig.Tls = &corev1.Service_Spec_Config_TLS{
			TrustedCAs: []string{caPEM},
		}

		pgCfg, err := c.getUpstreamConfig(upstream, "mypassword")
		assert.Nil(t, err, "%+v", err)

		assert.Nil(t, c.setUpstreamTLSConfig(ctx, svc, pgCfg, upstream))
		for _, cfg := range upstreamTLSConfigs(pgCfg) {
			assert.NotNil(t, cfg.RootCAs)
		}
	}
}

func caPool(t *testing.T, crt *x509.Certificate) *x509.CertPool {
	t.Helper()

	ret := x509.NewCertPool()
	ret.AddCert(crt)
	return ret
}

func TestCancelKeyStore(t *testing.T) {
	store := newCancelKeyStore()

	key := cancelKey{
		processID: 1234,
		secretKey: "abcd",
	}

	assert.Nil(t, store.get(key))

	target := &cancelTarget{
		addr:      "10.0.0.5:5432",
		processID: 4321,
		secretKey: []byte("dcba"),
	}
	store.set(key, target)

	assert.Equal(t, target, store.get(key))
	assert.Nil(t, store.get(cancelKey{processID: 1234, secretKey: "abce"}))
	assert.Nil(t, store.get(cancelKey{processID: 1235, secretKey: "abcd"}))

	store.delete(key)
	assert.Nil(t, store.get(key))
}
