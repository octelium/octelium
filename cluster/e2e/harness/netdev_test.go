package harness

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type sessionAddressClient struct {
	corev1.MainServiceClient
	session *corev1.Session
}

func (c *sessionAddressClient) GetSession(context.Context, *metav1.GetOptions,
	...grpc.CallOption) (*corev1.Session, error) {
	return c.session, nil
}

func TestWaitLocalSessionAddrs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family string
		addr   string
	}{
		{name: "IPv4", family: "inet", addr: "100.65.0.7/32"},
		{name: "IPv6", family: "inet6", addr: "fdee::7/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

			require.NoError(t, os.WriteFile(filepath.Join(dir, "octelium"), []byte(`#!/bin/bash
printf '%s\n' '{"session":{"metadata":{"name":"test"},"status":{"isConnected":true}}}'
`), 0755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "ip"), []byte(fmt.Sprintf(`#!/bin/bash
printf '1: lo inet 127.0.0.1/8 scope host lo\n'
if [ ! -f "$0.seen" ]; then
  touch "$0.seen"
  exit 0
fi
printf '2: octelium %s %s scope global octelium\n'
`, tc.family, tc.addr)), 0755))

			h := &H{coreC: &sessionAddressClient{session: &corev1.Session{
				Metadata: &metav1.Metadata{Name: "test"},
				Status: &corev1.Session_Status{
					IsConnected: true,
					Connection: &corev1.Session_Status_Connection{
						Addresses: []*metav1.DualStackNetwork{{V4: "100.65.0.7/32", V6: "fdee::7/128"}},
					},
				},
			}}}

			assert.Equal(t, []netip.Addr{netip.MustParsePrefix(tc.addr).Addr()}, h.WaitLocalSessionAddrs(t))
		})
	}
}
