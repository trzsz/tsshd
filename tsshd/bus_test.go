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
	"io"
	"net"
	"testing"
	"time"
)

type noopStream struct{}

func (s *noopStream) Read([]byte) (int, error)         { return 0, io.EOF }
func (s *noopStream) Write(p []byte) (int, error)      { return len(p), nil }
func (s *noopStream) Close() error                     { return nil }
func (s *noopStream) CloseRead() error                 { return nil }
func (s *noopStream) CloseWrite() error                { return nil }
func (s *noopStream) LocalAddr() net.Addr              { return nil }
func (s *noopStream) RemoteAddr() net.Addr             { return nil }
func (s *noopStream) SetDeadline(time.Time) error      { return nil }
func (s *noopStream) SetReadDeadline(time.Time) error  { return nil }
func (s *noopStream) SetWriteDeadline(time.Time) error { return nil }

func TestStartBusKeepAliveReplacesPrevious(t *testing.T) {
	oldExitChan := exitChan
	exitChan = make(chan int, 1)
	defer func() { exitChan = oldExitChan }()

	stopBusKeepAlive()
	defer stopBusKeepAlive()

	clientAliveTime.addMilli(time.Now().UnixMilli())
	startBusKeepAlive(40*time.Millisecond, 5*time.Millisecond)

	time.Sleep(15 * time.Millisecond)
	clientAliveTime.addMilli(time.Now().UnixMilli())
	startBusKeepAlive(200*time.Millisecond, 5*time.Millisecond)

	select {
	case code := <-exitChan:
		t.Fatalf("old keepalive should be canceled, got exit code: %d", code)
	case <-time.After(90 * time.Millisecond):
	}

	select {
	case code := <-exitChan:
		if code != 2 {
			t.Fatalf("keepalive should exit with code 2, got: %d", code)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatalf("replacement keepalive did not trigger timeout")
	}
}

func TestActiveBusForwarderSwitch(t *testing.T) {
	busMu.Lock()
	savedStream := busStream
	savedForwarder := activeBusForwarder
	busStream = nil
	activeBusForwarder = nil
	busMu.Unlock()
	defer func() {
		busMu.Lock()
		busStream = savedStream
		activeBusForwarder = savedForwarder
		busMu.Unlock()
	}()

	stream1 := &noopStream{}
	forwarder1 := &udpForwarder{}
	if err := initBusStream(stream1, forwarder1); err != nil {
		t.Fatalf("init first bus failed: %v", err)
	}
	if !isActiveBusForwarder(forwarder1) {
		t.Fatalf("first forwarder should be active")
	}
	if !isStreamCommandAuthorized("bus", nil) {
		t.Fatalf("bus command should always be allowed")
	}
	if !isStreamCommandAuthorized("session", forwarder1) {
		t.Fatalf("session command should be allowed on the active forwarder")
	}

	stream2 := &noopStream{}
	forwarder2 := &udpForwarder{}
	if err := initBusStream(stream2, forwarder2); err != nil {
		t.Fatalf("init second bus failed: %v", err)
	}
	if isActiveBusForwarder(forwarder1) {
		t.Fatalf("old forwarder should not remain active")
	}
	if isStreamCommandAuthorized("session", forwarder1) {
		t.Fatalf("session command should not be allowed on stale forwarder")
	}
	if !isActiveBusForwarder(forwarder2) {
		t.Fatalf("new forwarder should be active")
	}

	resetBusStream(stream2)
	if isActiveBusForwarder(forwarder2) {
		t.Fatalf("forwarder should be reset with bus stream")
	}
}
