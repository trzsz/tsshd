/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tsshd

import (
	"encoding/json"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNextAttachClientID(t *testing.T) {
	const maxID = ^uint64(0)
	require.Equal(t, uint64(2), nextAttachClientID(1, 3))
	require.Equal(t, uint64(4), nextAttachClientID(2, 3))
	require.Equal(t, uint64(1), nextAttachClientID(maxID-1, maxID))
	require.Equal(t, uint64(2), nextAttachClientID(maxID, 1))
}

func readAttachResponseForTest(t *testing.T) *ServerInfo {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)

	go func() {
		err := handleAttachRequest(serverConn)
		_ = serverConn.Close()
		done <- err
	}()

	data, err := io.ReadAll(clientConn)
	_ = clientConn.Close()

	require.NoError(t, err)
	require.NoError(t, <-done)
	require.NotEmpty(t, data)
	require.Equal(t, byte('\a'), data[0])

	var info ServerInfo
	err = json.Unmarshal(data[1:], &info)
	require.NoError(t, err)

	return &info
}

func TestHandleAttachRequestAllocatesClientID(t *testing.T) {
	const maxID = ^uint64(0)

	previous := globalSocketInfo
	t.Cleanup(func() {
		globalSocketInfo = previous
	})

	tests := []struct {
		name     string
		clientID uint64
		serverID uint64
		expected []uint64
	}{
		{
			name:     "Sequential",
			clientID: 100,
			serverID: 200,
			expected: []uint64{101, 102, 103},
		},
		{
			name:     "SkipServerID",
			clientID: 100,
			serverID: 102,
			expected: []uint64{101, 103, 104},
		},
		{
			name:     "Wraparound",
			clientID: maxID,
			serverID: 200,
			expected: []uint64{1, 2, 3},
		},
		{
			name:     "WraparoundSkipServerID",
			clientID: maxID,
			serverID: 1,
			expected: []uint64{2, 3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverInfo := &ServerInfo{
				ClientID: tt.clientID,
				ServerID: tt.serverID,
			}
			globalSocketInfo = &socketInfo{
				serverInfo: serverInfo,
			}

			for _, expectedID := range tt.expected {
				info := readAttachResponseForTest(t)

				// Verify the global ServerInfo was updated.
				require.Equal(t, expectedID, serverInfo.ClientID)

				// Verify the attach response contains the allocated ID.
				require.Equal(t, expectedID, info.ClientID)
				require.Equal(t, tt.serverID, info.ServerID)
			}
		})
	}
}
