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

// isolateActiveServer isolates the package-level active server pointer.
// These tests must not use t.Parallel().
func isolateActiveServer(t *testing.T) {
	t.Helper()

	previous := activeSshUdpServer.Swap(nil)

	t.Cleanup(func() {
		activeSshUdpServer.Store(previous)
	})
}

// TestServerInitClientCheckerAfterClose verifies that a client checker
// cannot be initialized after the server has been closed.
func TestServerInitClientCheckerAfterClose(t *testing.T) {
	server, _ := newTestServerWithoutBus()

	server.Close()

	err := server.initClientChecker(time.Hour)
	if err != errServerClosed {
		t.Fatalf("expected %v, got %v", errServerClosed, err)
	}

	if server.clientChecker != nil {
		t.Fatal("client checker should not be initialized")
	}

	if !server.closed.Load() {
		t.Fatal("server should remain closed")
	}
}

// TestServerActivateAfterClose verifies that a closed server cannot
// become the active server.
func TestServerActivateAfterClose(t *testing.T) {
	isolateActiveServer(t)

	server, _ := newTestServerWithoutBus()

	server.Close()

	err := server.activateServer("")
	if err != errServerClosed {
		t.Fatalf("expected %v, got %v", errServerClosed, err)
	}

	if server.serving.Load() {
		t.Fatal("closed server should not enter serving state")
	}

	if activeSshUdpServer.Load() != nil {
		t.Fatal("closed server should not become active")
	}
}

// TestServerCloseDuringClientCheckerInit verifies that closing the server
// concurrently with checker initialization has a consistent result.
func TestServerCloseDuringClientCheckerInit(t *testing.T) {
	const iterations = 32

	for i := range iterations {
		server, proto := newTestServerWithoutBus()

		start := make(chan struct{})
		initDone := make(chan error, 1)
		closeDone := make(chan struct{})

		go func() {
			<-start
			initDone <- server.initClientChecker(time.Hour)
		}()

		go func() {
			<-start
			server.Close()
			close(closeDone)
		}()

		close(start)

		initErr := <-initDone
		<-closeDone

		if !server.closed.Load() {
			t.Fatalf("[%d] server should be closed", i)
		}

		if !proto.closed.Load() {
			t.Fatalf("[%d] transport was not closed", i)
		}

		switch initErr {
		case nil:
			// Initialization completed before Close acquired activationMutex.
			if server.clientChecker == nil {
				t.Fatalf("[%d] successful initialization has no client checker", i)
			}

		case errServerClosed:
			// Close completed before initialization acquired activationMutex.
			if server.clientChecker != nil {
				t.Fatalf("[%d] client checker should not be initialized after Close", i)
			}

		default:
			t.Fatalf("[%d] unexpected initialization error: %v", i, initErr)
		}
	}
}

// TestServerCloseDuringActivation verifies that Close and activation
// are serialized by activationMutex.
func TestServerCloseDuringActivation(t *testing.T) {
	isolateActiveServer(t)

	const iterations = 32

	for i := range iterations {
		activeSshUdpServer.Store(nil)

		server, proto := newTestServerWithoutBus()

		if err := server.initClientChecker(time.Hour); err != nil {
			t.Fatalf("[%d] initialize client checker failed: %v", i, err)
		}

		start := make(chan struct{})
		activateDone := make(chan error, 1)
		closeDone := make(chan struct{})

		go func() {
			<-start
			activateDone <- server.activateServer("")
		}()

		go func() {
			<-start
			server.Close()
			close(closeDone)
		}()

		close(start)

		activateErr := <-activateDone
		<-closeDone

		if !server.closed.Load() {
			t.Fatalf("[%d] server should be closed", i)
		}

		if !proto.closed.Load() {
			t.Fatalf("[%d] transport was not closed", i)
		}

		switch activateErr {
		case nil:
			// Activation completed before Close acquired activationMutex.
			if !server.serving.Load() {
				t.Fatalf("[%d] successful activation did not set serving", i)
			}

		case errServerClosed:
			// Close completed before activation acquired activationMutex.
			if server.serving.Load() {
				t.Fatalf("[%d] closed server should not enter serving state", i)
			}

			if activeSshUdpServer.Load() != nil {
				t.Fatalf("[%d] closed server should not become active", i)
			}

		default:
			t.Fatalf("[%d] unexpected activation error: %v", i, activateErr)
		}
	}
}

// TestNonAttachableServerActivationIsExclusive verifies that only one
// non-attachable server can become active at a time.
func TestNonAttachableServerActivationIsExclusive(t *testing.T) {
	isolateActiveServer(t)

	first, _ := newTestServerWithoutBus()
	second, _ := newTestServerWithoutBus()

	if err := first.initClientChecker(time.Hour); err != nil {
		t.Fatalf("initialize first client checker failed: %v", err)
	}

	if err := second.initClientChecker(time.Hour); err != nil {
		t.Fatalf("initialize second client checker failed: %v", err)
	}

	if err := first.activateServer(""); err != nil {
		t.Fatalf("first server activation failed: %v", err)
	}

	if !first.serving.Load() {
		t.Fatal("first server should be serving")
	}

	err := second.activateServer("")
	if err == nil {
		t.Fatal("second server should not be activated")
	}

	if second.serving.Load() {
		t.Fatal("second server should not enter serving state")
	}

	if activeSshUdpServer.Load() != first {
		t.Fatal("active server should remain the first server")
	}

	second.Close()
	first.Close()
}

// TestServerConnectTimeoutDuringActivation verifies that a connect timeout
// cannot close a server that has already entered the serving state.
func TestServerConnectTimeoutDuringActivation(t *testing.T) {
	isolateActiveServer(t)

	const iterations = 32

	for i := range iterations {
		activeSshUdpServer.Store(nil)

		server, proto := newTestServerWithoutBus()

		if err := server.initClientChecker(time.Hour); err != nil {
			t.Fatalf("[%d] initialize client checker failed: %v", i, err)
		}

		start := make(chan struct{})
		activateDone := make(chan error, 1)
		timeoutDone := make(chan struct{})

		go func() {
			<-start
			activateDone <- server.activateServer("")
		}()

		go func() {
			<-start
			server.closeServer(true)
			close(timeoutDone)
		}()

		// Start activation and connect timeout concurrently.
		close(start)

		activateErr := <-activateDone
		<-timeoutDone

		switch activateErr {
		case nil:
			// Activation completed first. The connect timeout must not close
			// a server that has already entered the serving state.
			if !server.serving.Load() {
				t.Fatalf("[%d] server should be serving", i)
			}

			if server.closed.Load() {
				t.Fatalf("[%d] serving server was closed by connect timeout", i)
			}

			if proto.closed.Load() {
				// The transport must remain open.
				t.Fatalf("[%d] transport should remain open", i)
			}

			if activeSshUdpServer.Load() != server {
				t.Fatalf("[%d] server should remain active", i)
			}

			// Clean up the successfully activated server.
			server.Close()

		case errServerClosed:
			// Connect timeout completed first. Activation must be rejected.
			if !server.closed.Load() {
				t.Fatalf("[%d] server should be closed", i)
			}

			if server.serving.Load() {
				t.Fatalf("[%d] closed server should not enter serving state", i)
			}

			if !proto.closed.Load() {
				t.Fatalf("[%d] transport was not closed", i)
			}

			if activeSshUdpServer.Load() != nil {
				t.Fatalf("[%d] closed server should not become active", i)
			}

		default:
			t.Fatalf("[%d] unexpected activation error: %v", i, activateErr)
		}
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
