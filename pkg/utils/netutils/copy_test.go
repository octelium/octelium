// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netutils

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tstCloseWriteBuffer struct {
	buf           bytes.Buffer
	writeErr      error
	closeWriteErr error
	closeWrites   int
}

func (b *tstCloseWriteBuffer) Write(p []byte) (int, error) {
	if b.writeErr != nil {
		return 0, b.writeErr
	}
	return b.buf.Write(p)
}

func (b *tstCloseWriteBuffer) CloseWrite() error {
	b.closeWrites++
	return b.closeWriteErr
}

func TestCopyAndCloseWrite(t *testing.T) {
	for _, tc := range []struct {
		name        string
		dst         io.Writer
		src         io.Reader
		wantN       int64
		wantErr     error
		wantClosed  bool
		closeWrites int
	}{
		{
			name:        "EOF",
			dst:         &tstCloseWriteBuffer{},
			src:         strings.NewReader("request"),
			wantN:       7,
			closeWrites: 1,
		},
		{
			name:       "ReadError",
			dst:        &tstCloseWriteBuffer{},
			src:        io.MultiReader(strings.NewReader("req"), iotest.ErrReader(io.ErrUnexpectedEOF)),
			wantN:      3,
			wantErr:    io.ErrUnexpectedEOF,
			wantClosed: true,
		},
		{
			name:       "WriteError",
			dst:        &tstCloseWriteBuffer{writeErr: io.ErrClosedPipe},
			src:        strings.NewReader("request"),
			wantErr:    io.ErrClosedPipe,
			wantClosed: true,
		},
		{
			name:        "CloseWriteError",
			dst:         &tstCloseWriteBuffer{closeWriteErr: io.ErrClosedPipe},
			src:         strings.NewReader("request"),
			wantN:       7,
			wantErr:     io.ErrClosedPipe,
			wantClosed:  true,
			closeWrites: 1,
		},
		{
			name:       "NoCloseWrite",
			dst:        &bytes.Buffer{},
			src:        strings.NewReader("request"),
			wantN:      7,
			wantClosed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := 0
			n, err := CopyAndCloseWrite(tc.dst, tc.src, func() { closed++ })
			assert.Equal(t, tc.wantN, n)
			if tc.wantClosed {
				assert.NotNil(t, err)
				assert.Equal(t, 1, closed)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, 0, closed)
			}
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			}
			if b, ok := tc.dst.(*tstCloseWriteBuffer); ok {
				assert.Equal(t, tc.closeWrites, b.closeWrites)
				assert.Equal(t, tc.wantN, int64(b.buf.Len()))
			}
		})
	}
}

func TestCopyAndCloseWriteKeepsReadSideOpen(t *testing.T) {
	lis, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.Nil(t, err)
	defer lis.Close()
	client, err := net.DialTCP("tcp4", nil, lis.Addr().(*net.TCPAddr))
	require.Nil(t, err)
	defer client.Close()
	require.Nil(t, lis.SetDeadline(time.Now().Add(5*time.Second)))
	server, err := lis.AcceptTCP()
	require.Nil(t, err)
	defer server.Close()
	require.Nil(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.Nil(t, server.SetDeadline(time.Now().Add(5*time.Second)))

	closed := false
	n, err := CopyAndCloseWrite(client, strings.NewReader("request"), func() { closed = true })
	require.Nil(t, err)
	assert.Equal(t, int64(7), n)
	assert.False(t, closed)

	body, err := io.ReadAll(server)
	require.Nil(t, err)
	assert.Equal(t, "request", string(body))

	_, err = server.Write([]byte("response"))
	require.Nil(t, err)
	require.Nil(t, server.CloseWrite())

	body, err = io.ReadAll(client)
	require.Nil(t, err)
	assert.Equal(t, "response", string(body))
}
