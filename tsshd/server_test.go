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
	dbg "runtime/debug"
	"testing"
)

func TestServerLazyMap(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v\n%s", r, dbg.Stack())
		}
	}()

	server := &sshUdpServer{}

	if conn := server.takeAcceptConn(123); conn != nil {
		t.Fatalf("accept conn expected nil, got %v", conn)
	}

	if sess := server.takeUdpFwdPendingSession(789); sess != nil {
		t.Fatalf("pending session expected nil, got %v", sess)
	}

	server.releaseUdpForwardSession(&udpForwardSession{}) // should not panic

	dummyConn := &net.TCPConn{}
	id := server.addAcceptConn(dummyConn)
	if conn := server.takeAcceptConn(id); conn != dummyConn {
		t.Fatalf("accept conn mismatch, expected ptr %p, got %v", dummyConn, conn)
	}

	dummySess := &udpForwardSession{}
	server.addUdpFwdPendingSession(100, dummySess)
	if sess := server.takeUdpFwdPendingSession(100); sess != dummySess {
		t.Fatalf("pending session mismatch, expected ptr %p, got %v", dummySess, sess)
	}

	server.proto = &kcpServer{}
	sess, exists := server.acquireUdpForwardSession("key", "udp", "", nil, nil)
	if exists {
		t.Fatalf("expected new session, got exists=true")
	}
	if sess == nil {
		t.Fatalf("acquired session is nil")
	}
	if size := len(server.udpFwdSessionMap); size != 1 {
		t.Fatalf("expected session map size 1, got %d", size)
	}

	server.releaseUdpForwardSession(sess)
	if size := len(server.udpFwdSessionMap); size != 0 {
		t.Fatalf("expected session map size 0 after release, got %d", size)
	}
}
