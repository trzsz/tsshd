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
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// closeTrackingConn records whether Close was called, without needing a real
// network connection. The embedded nil net.Conn is never exercised because the
// reaper only ever calls Close.
type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return nil
}

// TestReapAcceptConnUnclaimed verifies the core fix: an accept connection the
// client never claims must be closed once ConnectTimeout elapses. Without this,
// a dead or unresponsive client (e.g. agent forwarding whose upstream agent has
// gone away) leaves the connection parked forever, which surfaces to the user
// as `ssh-add` or `git` SSH signing hanging indefinitely.
func TestReapAcceptConnUnclaimed(t *testing.T) {
	server := &sshUdpServer{args: &tsshdArgs{ConnectTimeout: 20 * time.Millisecond}}

	conn := &closeTrackingConn{}
	id := server.addAcceptConn(conn)
	server.reapAcceptConnAfterTimeout(id)

	deadline := time.Now().Add(2 * time.Second)
	for !conn.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}

	if !conn.closed.Load() {
		t.Fatal("unclaimed accept conn was not closed after ConnectTimeout")
	}
	if c := server.takeAcceptConn(id); c != nil {
		t.Fatal("reaped accept conn should no longer be parked")
	}
}

// TestReapAcceptConnClaimed verifies the reaper never disturbs a connection the
// client claimed in time: closing a live forwarded connection out from under an
// in-flight request would itself be a regression.
func TestReapAcceptConnClaimed(t *testing.T) {
	server := &sshUdpServer{args: &tsshdArgs{ConnectTimeout: 20 * time.Millisecond}}

	conn := &closeTrackingConn{}
	id := server.addAcceptConn(conn)
	server.reapAcceptConnAfterTimeout(id)

	if c := server.takeAcceptConn(id); c != conn {
		t.Fatalf("claim failed, expected ptr %p, got %v", conn, c)
	}

	// Wait well past ConnectTimeout so the reaper has certainly fired.
	time.Sleep(100 * time.Millisecond)

	if conn.closed.Load() {
		t.Fatal("reaper closed an accept conn that was already claimed by the client")
	}
}
