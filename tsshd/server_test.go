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
	"fmt"
	"net"
	dbg "runtime/debug"
	"sync/atomic"
	"testing"
	"time"
)

// closeTrackingProto is a protocolServer that only records whether it was closed.
type closeTrackingProto struct {
	closed atomic.Bool
}

func (p *closeTrackingProto) reset() {}

func (p *closeTrackingProto) Close() error {
	p.closed.Store(true)
	return nil
}

func (p *closeTrackingProto) getUdpForwarder() *udpForwarder { return nil }

// newTestServerWithoutBus returns a server in the state newSshUdpServer leaves it in:
// the connection is established, but the client has not initialized the bus yet.
func newTestServerWithoutBus() (*sshUdpServer, *closeTrackingProto) {
	proto := &closeTrackingProto{}
	server := &sshUdpServer{args: &tsshdArgs{}, client: &clientState{}, proto: proto,
		streamMap: make(map[uint64]Stream),
	}
	return server, proto
}

// TestServerCloseBeforeBusInit verifies that a server can be closed even if the
// client never initialized the bus, which is what happens on connect timeout when
// a client completes the handshake and then stalls. The client checker does not
// exist yet at that point, and closing must not panic and take down tsshd.
func TestServerCloseBeforeBusInit(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v\n%s", r, dbg.Stack())
		}
	}()

	server, proto := newTestServerWithoutBus()

	server.Close()

	if !proto.closed.Load() {
		t.Fatal("transport was not closed")
	}
	if !server.client.closed.Load() {
		t.Fatal("client was not closed")
	}
	if server.streamMap != nil {
		t.Fatal("server should no longer accept new streams")
	}

	server.Close() // closing again should be a no-op
}

// TestServerHandleStreamBeforeBusInit verifies that the cleanup of a stream opened
// before the bus does not panic when the server is closed without a client checker.
func TestServerHandleStreamBeforeBusInit(t *testing.T) {
	server, _ := newTestServerWithoutBus()

	serverEnd, clientEnd := net.Pipe()
	defer func() { _ = clientEnd.Close() }()

	// The client opens a stream but never sends a command.
	done := make(chan any, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Sprintf("%v\n%s", r, dbg.Stack())
				return
			}
			done <- nil
		}()
		server.handleStream(&pipeStream{Conn: serverEnd})
	}()

	// Wait for the stream to be registered, so that closing the server closes it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		server.streamMutex.Lock()
		count := len(server.streamMap)
		server.streamMutex.Unlock()
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream was not registered")
		}
		time.Sleep(2 * time.Millisecond)
	}

	server.Close()

	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("panic: %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handle stream did not return after the server was closed")
	}
}

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
