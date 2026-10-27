package login

import (
	"context"
	"testing"

	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/db"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginModes(t *testing.T) {
	prev := cmdArgs
	t.Cleanup(func() { cmdArgs = prev })
	t.Setenv("OCTELIUM_DOMAIN", "example.invalid")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "static-token")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	for _, arg := range []args{{}, {Token: "token"}, {IsWeb: true}, {Assertion: "jwt:env=JWT"}} {
		cmdArgs = arg
		assert.NoError(t, Cmd.RunE(cmd, nil))
	}
	t.Setenv("OCTELIUM_DOMAIN", "")
	assert.ErrorContains(t, doCmd(cmd, nil), "Cluster domain is not set")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "proxy.sock")
	assert.ErrorContains(t, Cmd.PersistentPreRunE(cmd, nil), "proxy mode")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	assert.NoError(t, Cmd.PersistentPreRunE(cmd, nil))
}

func TestLoginRequiresInteractiveAuthentication(t *testing.T) {
	for _, key := range []string{"OCTELIUM_ACCESS_TOKEN", "OCTELIUM_AUTH_PROXY_SOCKET", "OCTELIUM_AUTH_TOKEN", "OCTELIUM_AUTH_ASSERTION"} {
		t.Setenv(key, "")
	}
	t.Setenv("OCTELIUM_DOMAIN", "example.invalid")
	d, err := db.Open("mem")
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	prev := cmdArgs
	t.Cleanup(func() { cmdArgs = prev })
	cmdArgs = args{IsWeb: true}
	cmd := &cobra.Command{}
	cmd.SetContext(authenticator.WithNonInteractive(cliutils.WithDB(context.Background(), d)))
	assert.ErrorIs(t, doCmd(cmd, nil), authenticator.ErrAuthenticationRequired)
}
