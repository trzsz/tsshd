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
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeDatagramConn records SendDatagram calls and enforces a fixed budget.
type fakeDatagramConn struct {
	mu      sync.Mutex
	maxSize uint16
	sent    [][]byte
	recvCh  chan []byte
}

func newFakeDatagramConn(maxSize uint16) *fakeDatagramConn {
	return &fakeDatagramConn{maxSize: maxSize, recvCh: make(chan []byte, 16)}
}

func (c *fakeDatagramConn) GetMaxDatagramSize() uint16 {
	return c.maxSize
}

func (c *fakeDatagramConn) SendDatagram(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), data...))
	return nil
}

func (c *fakeDatagramConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case buf := <-c.recvCh:
		return buf, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeDatagramConn) sentCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

// fakeStream is an in-memory Stream that records writes (the reliable
// stream fallback path). Read blocks until the read side is closed. A test
// can also make Write block until Close to exercise shutdown behavior.
type fakeStream struct {
	mu  sync.Mutex
	buf bytes.Buffer

	closedCh chan struct{}
	readEOF  chan struct{}

	closeOnce     sync.Once
	readEOFOnce   sync.Once
	blockWrite    bool
	writeStarted  chan struct{}
	writeReturned chan struct{}

	writeStartOnce  sync.Once
	writeReturnOnce sync.Once
}

func newFakeStream() *fakeStream {
	return &fakeStream{
		closedCh: make(chan struct{}),
		readEOF:  make(chan struct{}),
	}
}

func (s *fakeStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	readEOF := s.readEOF
	s.mu.Unlock()
	<-readEOF
	return 0, io.EOF
}

func (s *fakeStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	blockWrite := s.blockWrite
	closedCh := s.closedCh
	writeStarted := s.writeStarted
	writeReturned := s.writeReturned
	s.mu.Unlock()

	if writeReturned != nil {
		defer s.writeReturnOnce.Do(func() { close(writeReturned) })
	}

	if blockWrite {
		if writeStarted != nil {
			s.writeStartOnce.Do(func() { close(writeStarted) })
		}
		<-closedCh
		return 0, net.ErrClosed
	}

	select {
	case <-closedCh:
		return 0, net.ErrClosed
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *fakeStream) Close() error {
	s.mu.Lock()
	closedCh := s.closedCh
	readEOF := s.readEOF
	s.mu.Unlock()

	s.closeOnce.Do(func() { close(closedCh) })
	s.readEOFOnce.Do(func() { close(readEOF) })
	return nil
}

func (s *fakeStream) CloseRead() error {
	s.mu.Lock()
	readEOF := s.readEOF
	s.mu.Unlock()
	s.readEOFOnce.Do(func() { close(readEOF) })
	return nil
}

func (s *fakeStream) CloseWrite() error                  { return nil }
func (s *fakeStream) LocalAddr() net.Addr                { return nil }
func (s *fakeStream) RemoteAddr() net.Addr               { return nil }
func (s *fakeStream) SetDeadline(t time.Time) error      { return nil }
func (s *fakeStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *fakeStream) SetWriteDeadline(t time.Time) error { return nil }

func (s *fakeStream) written() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

func (s *fakeStream) writtenBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

func newTestPacketConn(t *testing.T, budget uint16, datagramOnly bool) (*packetConn, *fakeDatagramConn, *fakeStream) {
	t.Helper()
	dc := newFakeDatagramConn(budget)
	forwarder := &udpForwarder{conn: dc}
	t.Cleanup(forwarder.Close)

	stream := newFakeStream()
	checker := newTimeoutChecker(0)
	t.Cleanup(checker.Close)
	conn := newPacketConn(stream, 1, forwarder, checker)
	conn.datagramOnly = datagramOnly
	t.Cleanup(func() { _ = conn.Close() })
	return conn, dc, stream
}

func waitForTestSignal(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func waitForTestChannelClose(t *testing.T, ch <-chan []byte, name string) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s to close", name)
		}
	}
}

func taggedDatagram(id uint64, payload []byte) []byte {
	data := append([]byte(nil), payload...)
	var tag [kUdpForwardChannelIdSize]byte
	binary.BigEndian.PutUint64(tag[:], id)
	return append(data, tag[:]...)
}

func TestPacketConn_DatagramOnlyDropsOversize(t *testing.T) {
	conn, dc, stream := newTestPacketConn(t, 100, true)

	// Fits the budget (payload + 8-byte channel tag): sent as a datagram.
	if err := conn.Write(make([]byte, 92)); err != nil {
		t.Fatalf("in-budget write failed: %v", err)
	}
	if dc.sentCount() != 1 {
		t.Fatalf("expected 1 datagram sent, got %d", dc.sentCount())
	}

	// Oversize: dropped silently, never the reliable stream.
	if err := conn.Write(make([]byte, 500)); err != nil {
		t.Fatalf("oversize write should drop, got error: %v", err)
	}
	if dc.sentCount() != 1 {
		t.Fatalf("oversize payload must not be sent as a datagram")
	}
	if stream.written() != 0 {
		t.Fatalf("oversize payload must not fall back to the stream, wrote %d bytes", stream.written())
	}
}

func TestPacketConn_DefaultKeepsStreamFallback(t *testing.T) {
	conn, dc, stream := newTestPacketConn(t, 100, false)

	if err := conn.Write(make([]byte, 500)); err != nil {
		t.Fatalf("fallback write failed: %v", err)
	}
	if dc.sentCount() != 0 {
		t.Fatalf("oversize payload must not be sent as a datagram")
	}
	if stream.written() == 0 {
		t.Fatalf("oversize payload should have fallen back to the stream")
	}
}

func TestPacketConn_DatagramOnlyDropsDuringReconnect(t *testing.T) {
	conn, dc, stream := newTestPacketConn(t, 100, true)
	conn.peerCheck.timeoutFlag.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := conn.WriteWithContext(ctx, make([]byte, 50)); err != nil {
		t.Fatalf("write during reconnect should drop, got error: %v", err)
	}

	if dc.sentCount() != 0 || stream.written() != 0 {
		t.Fatalf("write during reconnect must be dropped")
	}
}

// -----------------------------------------------------------------------------
// udpForwarder
// -----------------------------------------------------------------------------

func TestUdpForwarder_RoutesDatagramsByChannelID(t *testing.T) {
	dc := newFakeDatagramConn(1500)
	forwarder := &udpForwarder{conn: dc}
	defer forwarder.Close()

	const (
		id1 = uint64(11)
		id2 = uint64(22)
	)
	ch1 := forwarder.addChannel(id1)
	ch2 := forwarder.addChannel(id2)
	if ch1 == nil || ch2 == nil {
		t.Fatal("addChannel returned nil")
	}

	// Short packets and packets for unknown channels must be ignored.
	dc.recvCh <- []byte{1, 2, 3}
	dc.recvCh <- taggedDatagram(999, []byte("unknown"))
	dc.recvCh <- taggedDatagram(id1, []byte("first"))
	dc.recvCh <- taggedDatagram(id2, []byte("second"))

	select {
	case got := <-ch1:
		if string(got) != "first" {
			t.Fatalf("channel 1 received %q, want %q", got, "first")
		}
	case <-time.After(time.Second):
		t.Fatal("channel 1 did not receive its datagram")
	}

	select {
	case got := <-ch2:
		if string(got) != "second" {
			t.Fatalf("channel 2 received %q, want %q", got, "second")
		}
	case <-time.After(time.Second):
		t.Fatal("channel 2 did not receive its datagram")
	}

	forwarder.removeChannel(id1)
	waitForTestChannelClose(t, ch1, "channel 1")

	forwarder.Close()
	waitForTestChannelClose(t, ch2, "channel 2")

	if ch := forwarder.addChannel(33); ch != nil {
		t.Fatal("addChannel succeeded after forwarder was closed")
	}
}

func TestUdpForwarder_SendDatagramAppendsChannelID(t *testing.T) {
	dc := newFakeDatagramConn(100)
	forwarder := &udpForwarder{conn: dc}
	defer forwarder.Close()

	const id = uint64(0x1234567890abcdef)
	payload := []byte("payload")
	if !forwarder.sendDatagram(id, payload) {
		t.Fatal("sendDatagram failed")
	}

	dc.mu.Lock()
	if len(dc.sent) != 1 {
		dc.mu.Unlock()
		t.Fatalf("sent %d datagrams, want 1", len(dc.sent))
	}
	got := append([]byte(nil), dc.sent[0]...)
	dc.mu.Unlock()

	if !bytes.Equal(got[:len(payload)], payload) {
		t.Fatalf("payload = %q, want %q", got[:len(payload)], payload)
	}
	if gotID := binary.BigEndian.Uint64(got[len(payload):]); gotID != id {
		t.Fatalf("channel ID = %#x, want %#x", gotID, id)
	}

	if forwarder.sendDatagram(id, make([]byte, 101)) {
		t.Fatal("sendDatagram accepted an oversized payload")
	}
}

// -----------------------------------------------------------------------------
// packetConn lifecycle
// -----------------------------------------------------------------------------

type doneNotifyingContext struct {
	context.Context
	doneCalled chan struct{}
	once       sync.Once
}

func (c *doneNotifyingContext) Done() <-chan struct{} {
	c.once.Do(func() {
		close(c.doneCalled)
	})
	return c.Context.Done()
}

func assertWriteCanceledWhileReconnecting(t *testing.T, conn *packetConn) {
	t.Helper()

	baseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx := &doneNotifyingContext{
		Context:    baseCtx,
		doneCalled: make(chan struct{}),
	}

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- conn.WriteWithContext(ctx, []byte("test"))
	}()

	// Done() is called when waitReconnect evaluates its cancellation case.
	// This confirms that the write has reached the reconnect wait.
	select {
	case <-ctx.doneCalled:
	case <-time.After(time.Second):
		t.Fatal("write did not enter reconnect wait")
	}

	cancel()

	select {
	case err := <-writeDone:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not return after context cancellation")
	}
}

func TestPacketConn_WriteWithContextCancelsReconnectWait(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*timeoutChecker)
	}{
		{
			name: "nil reconnect channel",
			setup: func(tc *timeoutChecker) {
				tc.timeoutFlag.Store(true)
			},
		},
		{
			name: "reconnect channel available",
			setup: func(tc *timeoutChecker) {
				tc.timeoutFlag.Store(true)
				ch := make(chan struct{})
				tc.reconnectedCh.Store(&ch)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, _, _ := newTestPacketConn(t, 100, false)
			tt.setup(conn.peerCheck)
			assertWriteCanceledWhileReconnecting(t, conn)
		})
	}
}

// -----------------------------------------------------------------------------
// udpForwardSession
// -----------------------------------------------------------------------------

func TestUdpForwardSession_PendingPacketsAreFlushedInOrder(t *testing.T) {
	stream := newFakeStream()
	checker := newTimeoutChecker(0)
	t.Cleanup(checker.Close)
	ctx, cancel := context.WithCancel(context.Background())

	session := &udpForwardSession{
		forwardConn: newPacketConn(nil, 101, nil, checker),
		pendingFlag: true,
		writeCtx:    ctx,
		cancelWrite: cancel,
	}
	t.Cleanup(session.Close)

	first := []byte("pending-first")
	session.writePacket(first)
	first[0] = 'X' // pendingBuf must own a copy of the packet
	session.writePacket([]byte("pending-second"))

	session.attachStream(stream)
	session.writePacket([]byte("after-attach"))

	written := stream.writtenBytes()
	positions := []int{
		bytes.Index(written, []byte("pending-first")),
		bytes.Index(written, []byte("pending-second")),
		bytes.Index(written, []byte("after-attach")),
	}
	for i, pos := range positions {
		if pos < 0 {
			t.Fatalf("packet %d was not written; stream data: %q", i, written)
		}
	}
	if positions[0] >= positions[1] || positions[1] >= positions[2] {
		t.Fatalf("packets were written out of order: positions %v", positions)
	}

	session.stateMu.Lock()
	pendingFlag := session.pendingFlag
	pendingCount := len(session.pendingBuf)
	session.stateMu.Unlock()
	if pendingFlag {
		t.Fatal("pendingFlag remained set after attachStream")
	}
	if pendingCount != 0 {
		t.Fatalf("pendingBuf length = %d, want 0", pendingCount)
	}
}

func TestUdpForwardSession_PendingBufferLimit(t *testing.T) {
	session := &udpForwardSession{
		pendingFlag: true,
		writeCtx:    context.Background(),
	}

	for i := 0; i < kMaxUdpForwardPendingPackets; i++ {
		session.writePacket([]byte{byte(i)})
	}
	session.writePacket([]byte("overflow"))

	session.stateMu.Lock()
	got := len(session.pendingBuf)
	session.stateMu.Unlock()
	if got != kMaxUdpForwardPendingPackets {
		t.Fatalf("pendingBuf length = %d, want %d", got, kMaxUdpForwardPendingPackets)
	}
}

func TestUdpForwardSession_CloseDoesNotWaitForBlockedWrite(t *testing.T) {
	stream := newFakeStream()
	stream.blockWrite = true
	stream.writeStarted = make(chan struct{})
	stream.writeReturned = make(chan struct{})

	checker := newTimeoutChecker(0)
	t.Cleanup(checker.Close)
	ctx, cancel := context.WithCancel(context.Background())

	session := &udpForwardSession{
		forwardConn: newPacketConn(stream, 102, nil, checker),
		writeCtx:    ctx,
		cancelWrite: cancel,
	}
	t.Cleanup(session.Close)

	writeDone := make(chan struct{})
	go func() {
		session.writePacket([]byte("blocked write"))
		close(writeDone)
	}()
	waitForTestSignal(t, stream.writeStarted, "underlying stream write")

	closeDone := make(chan struct{})
	go func() {
		session.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(time.Second):
		// Release the test writer before failing, so this test cannot leak it.
		cancel()
		_ = stream.Close()
		<-writeDone
		t.Fatal("session.Close blocked waiting for writeMu")
	}

	waitForTestSignal(t, writeDone, "writePacket return")
	waitForTestSignal(t, stream.writeReturned, "underlying stream Write return")

	session.stateMu.Lock()
	closed := session.closed
	session.stateMu.Unlock()
	if !closed {
		t.Fatal("session.closed was not set")
	}
}

func TestUdpForwardSession_AttachAfterCloseClosesStream(t *testing.T) {
	checker := newTimeoutChecker(0)
	t.Cleanup(checker.Close)
	ctx, cancel := context.WithCancel(context.Background())

	session := &udpForwardSession{
		forwardConn: newPacketConn(nil, 103, nil, checker),
		writeCtx:    ctx,
		cancelWrite: cancel,
	}
	session.Close()

	stream := newFakeStream()
	session.attachStream(stream)
	waitForTestSignal(t, stream.closedCh, "late attached stream close")
}

// -----------------------------------------------------------------------------
// Server-side session map cleanup
// -----------------------------------------------------------------------------

func TestReleaseUdpForwardSessions_OnlyReleasesMatchingListener(t *testing.T) {
	newSession := func(listenerID uint64, key string, channelID uint64) (*udpForwardSession, context.Context) {
		ctx, cancel := context.WithCancel(context.Background())
		return &udpForwardSession{
			listenerID:  listenerID,
			sessionKey:  key,
			forwardConn: newPacketConn(nil, channelID, nil, nil),
			writeCtx:    ctx,
			cancelWrite: cancel,
		}, ctx
	}

	target1, targetCtx1 := newSession(10, "10_peer1", 101)
	target2, targetCtx2 := newSession(10, "10_peer2", 102)
	other, otherCtx := newSession(20, "20_peer", 201)

	server := &sshUdpServer{
		udpFwdSessionMap: map[string]*udpForwardSession{
			"10_peer1": target1,
			"10_peer2": target2,
			"20_peer":  other,
		},
		udpFwdPendingMap: map[uint64]*udpForwardSession{
			101: target1,
			102: target2,
			201: other,
		},
	}

	server.releaseUdpForwardSessions(10)

	for name, ctx := range map[string]context.Context{
		"first target":  targetCtx1,
		"second target": targetCtx2,
	} {
		select {
		case <-ctx.Done():
		default:
			t.Errorf("%s session context was not cancelled", name)
		}
	}
	select {
	case <-otherCtx.Done():
		t.Fatal("session belonging to another listener was closed")
	default:
	}

	if len(server.udpFwdSessionMap) != 1 || server.udpFwdSessionMap["20_peer"] != other {
		t.Fatalf("unexpected active session map after release: %#v", server.udpFwdSessionMap)
	}
	if len(server.udpFwdPendingMap) != 1 || server.udpFwdPendingMap[201] != other {
		t.Fatalf("unexpected pending session map after release: %#v", server.udpFwdPendingMap)
	}
}

func TestReleaseUdpForwardSessionDoesNotDeleteReplacement(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	newCtx, newCancel := context.WithCancel(context.Background())
	oldSession := &udpForwardSession{
		sessionKey:  "same-key",
		forwardConn: newPacketConn(nil, 301, nil, nil),
		writeCtx:    oldCtx,
		cancelWrite: oldCancel,
	}
	newSession := &udpForwardSession{
		sessionKey:  "same-key",
		forwardConn: newPacketConn(nil, 302, nil, nil),
		writeCtx:    newCtx,
		cancelWrite: newCancel,
	}

	server := &sshUdpServer{
		udpFwdSessionMap: map[string]*udpForwardSession{
			"same-key": newSession,
		},
		udpFwdPendingMap: map[uint64]*udpForwardSession{
			301: oldSession,
			302: newSession,
		},
	}

	server.releaseUdpForwardSession(oldSession)

	if server.udpFwdSessionMap["same-key"] != newSession {
		t.Fatal("releasing the old session deleted its replacement")
	}
	if _, ok := server.udpFwdPendingMap[301]; ok {
		t.Fatal("old pending session was not removed")
	}
	if server.udpFwdPendingMap[302] != newSession {
		t.Fatal("replacement pending session was removed")
	}
	select {
	case <-oldCtx.Done():
	default:
		t.Fatal("old session context was not cancelled")
	}
	select {
	case <-newCtx.Done():
		t.Fatal("replacement session context was cancelled")
	default:
	}
}

func TestReapUdpFwdPendingSessionAfterTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &udpForwardSession{
		sessionKey:  "pending-peer",
		forwardConn: newPacketConn(nil, 401, nil, nil),
		writeCtx:    ctx,
		cancelWrite: cancel,
	}
	server := &sshUdpServer{
		args: &tsshdArgs{ConnectTimeout: 20 * time.Millisecond},
		udpFwdSessionMap: map[string]*udpForwardSession{
			"pending-peer": session,
		},
		udpFwdPendingMap: map[uint64]*udpForwardSession{
			401: session,
		},
	}

	server.reapUdpFwdPendingSessionAfterTimeout(401)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("pending session was not reaped")
	}

	if _, ok := server.udpFwdSessionMap["pending-peer"]; ok {
		t.Fatal("reaped session remained in active session map")
	}
	if _, ok := server.udpFwdPendingMap[401]; ok {
		t.Fatal("reaped session remained in pending session map")
	}
}

// -----------------------------------------------------------------------------
// handleListenUdpEvent integration test
// -----------------------------------------------------------------------------

type udpHandlerTestStream struct {
	reader *io.PipeReader
	writer *io.PipeWriter

	closeReadOnce  sync.Once
	closeWriteOnce sync.Once
	closeOnce      sync.Once
	closed         chan struct{}

	writeStarted  chan struct{}
	writeReturned chan struct{}
	writeGate     <-chan struct{}
}

func newUDPHandlerTestStreamPair() (*udpHandlerTestStream, *udpHandlerTestStream) {
	clientToServerReader, clientToServerWriter := io.Pipe()
	serverToClientReader, serverToClientWriter := io.Pipe()

	server := &udpHandlerTestStream{
		reader:        clientToServerReader,
		writer:        serverToClientWriter,
		closed:        make(chan struct{}),
		writeStarted:  make(chan struct{}, 32),
		writeReturned: make(chan struct{}, 32),
	}
	client := &udpHandlerTestStream{
		reader: serverToClientReader,
		writer: clientToServerWriter,
		closed: make(chan struct{}),
	}
	return server, client
}

func (s *udpHandlerTestStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *udpHandlerTestStream) Write(p []byte) (int, error) {
	if s.writeStarted != nil {
		select {
		case s.writeStarted <- struct{}{}:
		default:
		}
	}
	if s.writeGate != nil {
		<-s.writeGate
	}

	n, err := s.writer.Write(p)
	if s.writeReturned != nil {
		select {
		case s.writeReturned <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (s *udpHandlerTestStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.reader.Close()
		_ = s.writer.Close()
	})
	return nil
}

func (s *udpHandlerTestStream) CloseRead() error {
	var err error
	s.closeReadOnce.Do(func() { err = s.reader.Close() })
	return err
}

func (s *udpHandlerTestStream) CloseWrite() error {
	var err error
	s.closeWriteOnce.Do(func() { err = s.writer.Close() })
	return err
}

func (s *udpHandlerTestStream) LocalAddr() net.Addr              { return nil }
func (s *udpHandlerTestStream) RemoteAddr() net.Addr             { return nil }
func (s *udpHandlerTestStream) SetDeadline(time.Time) error      { return nil }
func (s *udpHandlerTestStream) SetReadDeadline(time.Time) error  { return nil }
func (s *udpHandlerTestStream) SetWriteDeadline(time.Time) error { return nil }

type udpHandlerTestProtocol struct{}

func (*udpHandlerTestProtocol) reset()                         {}
func (*udpHandlerTestProtocol) Close() error                   { return nil }
func (*udpHandlerTestProtocol) getUdpForwarder() *udpForwarder { return nil }

func waitForUDPListenerClosed(t *testing.T, listener net.PacketConn, peer net.Addr) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, err := listener.WriteTo([]byte("close-check"), peer)
		if err != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("listenerConn was not closed after control stream EOF")
}

func drainTestSignals(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func sendUnacceptedUDPTestPeer(t *testing.T, server *sshUdpServer, listenerStream Stream,
	listenerAddr netip.AddrPort) (*net.UDPConn, *udpForwardSession) {
	t.Helper()

	peer, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(listenerAddr))
	if err != nil {
		t.Fatalf("dial UDP listener failed: %v", err)
	}

	if _, err := peer.Write([]byte("pending peer")); err != nil {
		_ = peer.Close()
		t.Fatalf("send UDP packet from pending peer failed: %v", err)
	}

	// The listener handler sends an accept message after creating the session.
	var msg acceptUdpMessage
	if err := recvMessage(listenerStream, &msg); err != nil {
		_ = peer.Close()
		t.Fatalf("receive pending peer accept message failed: %v", err)
	}

	server.udpFwdPendingMutex.Lock()
	session := server.udpFwdPendingMap[msg.ID]
	server.udpFwdPendingMutex.Unlock()

	if session == nil {
		_ = peer.Close()
		t.Fatalf("pending session %d was not registered", msg.ID)
	}

	return peer, session
}

func TestHandleDialUdpEventCleansUpConnWhenResponseWriteFails(t *testing.T) {
	// Use a loopback UDP listener so the test works on Windows as well as Unix.
	listenAddr := netip.MustParseAddrPort("127.0.0.1:0")
	remote, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listenAddr))
	if err != nil {
		t.Fatalf("listen on loopback UDP failed: %v", err)
	}
	defer func() { _ = remote.Close() }()

	remoteAddr := remote.LocalAddr().(*net.UDPAddr).AddrPort()

	serverStream, clientStream := newUDPHandlerTestStreamPair()
	defer func() { _ = serverStream.Close() }()
	defer func() { _ = clientStream.Close() }()

	// Pause the response write so the test can verify that the dialed
	// connection's cleanup has been registered before the write fails.
	writeGate := make(chan struct{})
	serverStream.writeGate = writeGate
	var releaseWriteOnce sync.Once
	releaseWrite := func() { releaseWriteOnce.Do(func() { close(writeGate) }) }
	defer releaseWrite()

	// Keep the request direction open, but make the response write fail.
	if err := clientStream.CloseRead(); err != nil {
		t.Fatalf("close client read side failed: %v", err)
	}

	checker := newTimeoutChecker(0)
	t.Cleanup(checker.Close)
	server := &sshUdpServer{
		proto:         &udpHandlerTestProtocol{},
		clientChecker: checker,
	}

	handlerDone := make(chan struct{})
	go func() {
		server.handleDialUdpEvent(serverStream)
		close(handlerDone)
	}()

	if err := sendMessage(clientStream, &dialUdpMessage{
		Net:  "udp4",
		Addr: remoteAddr.String(),
	}); err != nil {
		t.Fatalf("send dial-udp request failed: %v", err)
	}

	// A channel ID is allocated only after dialUDP succeeds, so this also
	// ensures that the test reached the response-write path, not sendError.
	waitForTestSignal(t, serverStream.writeStarted, "dial-udp response write")
	if got := server.nextUdpFwdChannelID.Load(); got != 1 {
		t.Fatalf("dialed UDP connection was not established; channel ID = %d", got)
	}

	server.cleanupMutex.Lock()
	cleanupCount := len(server.cleanupFuncs)
	server.cleanupMutex.Unlock()
	if cleanupCount != 1 {
		t.Fatalf("registered cleanup functions = %d, want 1", cleanupCount)
	}

	releaseWrite()
	waitForTestSignal(t, handlerDone, "dial-udp handler exit")
	waitForTestSignal(t, serverStream.closed, "dial-udp stream close")

	// The handler's deferred cleanup must unregister and run the connection
	// cleanup before returning, even when sending the response fails.
	server.cleanupMutex.Lock()
	cleanupCount = len(server.cleanupFuncs)
	server.cleanupMutex.Unlock()
	if cleanupCount != 0 {
		t.Fatalf("dialed UDP connection cleanup was not run; %d cleanup functions remain", cleanupCount)
	}
}

func TestHandleListenUdpEvent_CleansUpSessionsAfterControlStreamEOF(t *testing.T) {
	checker := newTimeoutChecker(0)
	t.Cleanup(checker.Close)

	server := &sshUdpServer{
		args:          &tsshdArgs{ConnectTimeout: 5 * time.Second},
		proto:         &udpHandlerTestProtocol{},
		clientChecker: checker,
	}

	// Reserve an ephemeral UDP port, then let handleListenUdpEvent bind it.
	// The short close/rebind window is local to this test.
	loopback := netip.MustParseAddr("127.0.0.1")
	probe, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, 0)))
	if err != nil {
		t.Fatalf("reserve UDP port failed: %v", err)
	}

	listenAddr := probe.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := probe.Close(); err != nil {
		t.Fatalf("release reserved UDP port failed: %v", err)
	}

	listenServerStream, listenClientStream := newUDPHandlerTestStreamPair()
	defer func() { _ = listenServerStream.Close() }()
	defer func() { _ = listenClientStream.Close() }()

	listenDone := make(chan struct{})
	go func() {
		server.handleListenUdpEvent(listenServerStream)
		close(listenDone)
	}()

	if err := sendMessage(listenClientStream, &listenUdpMessage{
		Net:  "udp4",
		Addr: listenAddr.String(),
	}); err != nil {
		t.Fatalf("send listen-udp request failed: %v", err)
	}
	if err := recvError(listenClientStream); err != nil {
		t.Fatalf("listen-udp request failed: %v", err)
	}

	udpClient, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(listenAddr))
	if err != nil {
		t.Fatalf("dial UDP listener failed: %v", err)
	}
	defer func() { _ = udpClient.Close() }()

	// The first packet creates a pending server-side session.
	if _, err := udpClient.Write([]byte("first packet")); err != nil {
		t.Fatalf("send first UDP packet failed: %v", err)
	}

	var acceptMsg acceptUdpMessage
	if err := recvMessage(listenClientStream, &acceptMsg); err != nil {
		t.Fatalf("receive accept-udp request failed: %v", err)
	}

	server.udpFwdPendingMutex.Lock()
	session := server.udpFwdPendingMap[acceptMsg.ID]
	server.udpFwdPendingMutex.Unlock()
	if session == nil {
		t.Fatal("UDP forwarding session was not registered")
	}

	// Attach an accept-udp stream. Its peer will read the initial buffered
	// packet, then stop reading so the next server-side write blocks.
	acceptServerStream, acceptClientStream := newUDPHandlerTestStreamPair()
	defer func() { _ = acceptClientStream.Close() }()

	acceptDone := make(chan struct{})
	go func() {
		server.handleAcceptUdpEvent(acceptServerStream)
		close(acceptDone)
	}()

	if err := sendMessage(acceptClientStream, &acceptUdpMessage{ID: acceptMsg.ID}); err != nil {
		t.Fatalf("send accept-udp request failed: %v", err)
	}
	if err := recvError(acceptClientStream); err != nil {
		t.Fatalf("accept-udp request failed: %v", err)
	}

	buf := make([]byte, 0xffff)
	n, err := recvUdpPacket(acceptClientStream, buf)
	if err != nil {
		t.Fatalf("receive initial forwarded packet failed: %v", err)
	}
	if got, want := string(buf[:n]), "first packet"; got != want {
		t.Fatalf("initial forwarded packet = %q, want %q", got, want)
	}

	// Keep a second peer pending so EOF cleanup must remove an unaccepted session.
	pendingPeer, pendingSession := sendUnacceptedUDPTestPeer(t, server, listenClientStream, listenAddr)
	defer func() { _ = pendingPeer.Close() }()
	if pendingSession == session {
		t.Fatal("expected a separate pending session")
	}

	// All writes used for the handshake and first packet have completed.
	// The next Write call must block because the client stops reading.
	drainTestSignals(acceptServerStream.writeStarted)
	drainTestSignals(acceptServerStream.writeReturned)

	if _, err := udpClient.Write([]byte("blocking packet")); err != nil {
		t.Fatalf("send second UDP packet failed: %v", err)
	}
	waitForTestSignal(t, acceptServerStream.writeStarted, "blocked accept-udp stream write")

	// This half-closes only the client's sending direction. It allows the
	// server to observe EOF while keeping the receive direction available.
	if err := listenClientStream.CloseWrite(); err != nil {
		t.Fatalf("close listen control stream write side failed: %v", err)
	}

	// Verify that the actual UDP listener has been closed by the EOF watcher.
	waitForUDPListenerClosed(t, session.listenerConn, session.peerAddr)

	// The handler must leave its blocked packet write, observe the closed UDP
	// listener, run releaseUdpForwardSessions from its defer, and return.
	select {
	case <-listenDone:
	case <-time.After(time.Second):
		// Cleanup the session explicitly so the failing test does not leak the
		// blocked packet write or the accept-udp Consume goroutine.
		server.releaseUdpForwardSessions(session.listenerID)
		select {
		case <-listenDone:
		case <-time.After(time.Second):
			t.Fatal("handleListenUdpEvent remained blocked even after explicit session cleanup")
		}
		t.Fatal("handleListenUdpEvent did not return after its control stream reached EOF")
	}

	select {
	case <-acceptDone:
	case <-time.After(time.Second):
		t.Fatal("handleAcceptUdpEvent did not exit after listener cleanup")
	}
	waitForTestSignal(t, acceptServerStream.closed, "accept-udp stream close")
	waitForTestSignal(t, acceptServerStream.writeReturned, "blocked stream write return")

	session.stateMu.Lock()
	closed := session.closed
	session.stateMu.Unlock()
	if !closed {
		t.Fatal("UDP forwarding session was not closed by listener cleanup")
	}

	server.udpFwdSessionMutex.Lock()
	activeCount := len(server.udpFwdSessionMap)
	server.udpFwdSessionMutex.Unlock()
	if activeCount != 0 {
		t.Fatalf("active UDP forwarding sessions remain: %d", activeCount)
	}

	server.udpFwdPendingMutex.Lock()
	_, pendingStillRegistered := server.udpFwdPendingMap[pendingSession.forwardConn.channelID]
	pendingCount := len(server.udpFwdPendingMap)
	server.udpFwdPendingMutex.Unlock()
	if pendingStillRegistered || pendingCount != 0 {
		t.Fatalf("unaccepted session was not removed from pending map (registered=%t, count=%d)",
			pendingStillRegistered, pendingCount)
	}

	pendingSession.stateMu.Lock()
	pendingClosed := pendingSession.closed
	pendingSession.stateMu.Unlock()
	if !pendingClosed {
		t.Fatal("unaccepted UDP forwarding session was not closed")
	}
	select {
	case <-pendingSession.writeCtx.Done():
	default:
		t.Fatal("unaccepted session write context was not cancelled")
	}

	select {
	case <-session.writeCtx.Done():
	default:
		t.Fatal("session write context was not cancelled")
	}
}
