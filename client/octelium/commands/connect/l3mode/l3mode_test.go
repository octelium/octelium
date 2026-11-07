package l3mode

import (
	"testing"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetL3ModeExplicit(t *testing.T) {
	for _, tt := range []struct {
		mode string
		want userv1.ConnectRequest_Initialize_L3Mode
	}{
		{"v4", userv1.ConnectRequest_Initialize_V4},
		{"v6", userv1.ConnectRequest_Initialize_V6},
		{"both", userv1.ConnectRequest_Initialize_BOTH},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			mode, err := GetL3Mode(tt.mode)
			require.NoError(t, err)
			assert.Equal(t, tt.want, mode)
		})
	}
}
