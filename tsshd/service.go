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
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/trzsz/smux"
	"github.com/xtaci/kcp-go/v5"
)

var smuxConfig = smux.Config{
	Version:           2,
	KeepAliveDisabled: true,
	MaxFrameSize:      48 * 1024,
	MaxStreamBuffer:   10 * 1024 * 1024,
	MaxReceiveBuffer:  20 * 1024 * 1024,
}

var transportConnMu sync.Mutex
var transportConnID atomic.Uint64
var transportConnMap = make(map[uint64]func())
var transportCleanupOnce sync.Once

func registerTransportConn(closeFn func()) uint64 {
	if closeFn == nil {
		return 0
	}
	transportCleanupOnce.Do(func() {
		addOnExitFunc(closeAllTransportConns)
	})
	id := transportConnID.Add(1)
	transportConnMu.Lock()
	transportConnMap[id] = closeFn
	transportConnMu.Unlock()
	return id
}

func unregisterTransportConn(id uint64) {
	if id == 0 {
		return
	}
	transportConnMu.Lock()
	delete(transportConnMap, id)
	transportConnMu.Unlock()
}

func closeAllTransportConns() {
	transportConnMu.Lock()
	closeFns := make([]func(), 0, len(transportConnMap))
	for id, closeFn := range transportConnMap {
		delete(transportConnMap, id)
		closeFns = append(closeFns, closeFn)
	}
	transportConnMu.Unlock()
	for _, closeFn := range closeFns {
		closeFn()
	}
}

// Only the connection that owns the active bus may open non-bus streams.
// This prevents unauthenticated replacement transports from hijacking sessions.
func isStreamCommandAuthorized(command string, forwarder *udpForwarder) bool {
	if command == "bus" {
		return true
	}
	return isActiveBusForwarder(forwarder)
}

// Stream extends net.Conn by adding support for half-close operations
type Stream interface {
	net.Conn
	// CloseRead shuts down the reading side of the stream gracefully
	CloseRead() error
	// CloseWrite shuts down the writing side of the stream gracefully
	CloseWrite() error
}

type smuxStream struct {
	*smux.Stream
}

type quicStream struct {
	*quic.Stream
	conn *quic.Conn
}

func (s *quicStream) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *quicStream) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *quicStream) CloseRead() error {
	s.CancelRead(0)
	return nil
}

func (s *quicStream) CloseWrite() error {
	// CancelWrite aborts sending on this stream.
	// Data already written, but not yet delivered to the peer is not guaranteed to be delivered reliably.

	// Close closes the send-direction of the stream.
	// It does not close the receive-direction of the stream.
	return s.Stream.Close()
}

func (s *quicStream) Close() error {
	_ = s.CloseRead()
	return s.CloseWrite()
}

type kcpDatagramConn struct {
	*kcp.UDPSession
	buf chan []byte
	mtu uint16
}

func newKcpDatagramConn(conn *kcp.UDPSession) datagramConn {
	dc := &kcpDatagramConn{
		conn,
		make(chan []byte, 1024),
		uint16(conn.GetOOBMaxSize()) - kUdpForwardChannelIdSize, // Reserve 8 bytes from the MTU for the channel ID
	}
	_ = conn.SetOOBHandler(dc.datagramHandler)
	return dc
}

func (c *kcpDatagramConn) datagramHandler(buf []byte) {
	select {
	case c.buf <- append([]byte(nil), buf...):
	default:
	}
}

func (c *kcpDatagramConn) SendDatagram(data []byte) error {
	return c.SendOOB(data)
}

func (c *kcpDatagramConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case buf, ok := <-c.buf:
		if !ok {
			return nil, io.EOF
		}
		return buf, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *kcpDatagramConn) GetMaxDatagramSize() uint16 {
	return c.mtu
}

type quicDatagramConn struct {
	*quic.Conn
	mtu uint16
}

func newQuicDatagramConn(conn *quic.Conn) datagramConn {
	return &quicDatagramConn{
		conn,
		// This depends on quicConfig.InitialPacketSize being properly clamped to the valid MTU range.
		// See TestQUIC_InitialPacketSize for the test that ensures this behavior.
		quicConfig.InitialPacketSize - kQuicShortHeaderSize - kUdpForwardChannelIdSize, // Reserve 8 bytes from the MTU for the channel ID
	}
}

func (c *quicDatagramConn) GetMaxDatagramSize() uint16 {
	return c.mtu
}

func serveKCP(listener *kcp.Listener, mtu uint16) {
	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			warning("kcp accept failed: %v", err)
			return
		}
		debug("kcp accepted new connection from %v", conn.RemoteAddr())
		if busClosing.Load() {
			_ = conn.Close()
			return
		}
		// Handle connections asynchronously so roaming reconnects don't block accept.
		// Bus ownership is still established by the bus stream handshake, not by accept.
		go handleKcpConn(conn, mtu)
	}
}

func handleKcpConn(conn *kcp.UDPSession, mtu uint16) {
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	connID := registerTransportConn(closeConn)
	defer unregisterTransportConn(connID)
	defer closeConn()

	conn.SetWindowSize(1024, 1024)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWriteDelay(false)
	if mtu > 0 {
		conn.SetMtu(int(mtu))
	} else {
		conn.SetMtu(kDefaultMTU)
	}

	forwarder := &udpForwarder{conn: newKcpDatagramConn(conn)}

	session, err := smux.Server(conn, &smuxConfig)
	if err != nil {
		warning("kcp smux server failed: %v", err)
		return
	}

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if !isClosedError(err) {
				warning("kcp smux accept stream failed: %v", err)
			}
			return
		}
		if busClosing.Load() {
			_ = stream.Close()
			return
		}
		go handleStream(&smuxStream{stream}, forwarder)
	}
}

func serveQUIC(listener *quic.Listener) {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			warning("quic accept conn failed: %v", err)
			return
		}
		debug("quic accepted new connection from %v", conn.RemoteAddr())
		if busClosing.Load() {
			_ = conn.CloseWithError(0, "")
			return
		}
		// Handle connections asynchronously so roaming reconnects don't block accept.
		// Bus ownership is still established by the bus stream handshake, not by accept.
		go handleQuicConn(conn)
	}
}

func handleQuicConn(conn *quic.Conn) {
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { _ = conn.CloseWithError(0, "") }) }
	connID := registerTransportConn(closeConn)
	defer unregisterTransportConn(connID)
	defer closeConn()

	forwarder := &udpForwarder{conn: newQuicDatagramConn(conn)}

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			if !isClosedError(err) {
				warning("quic accept stream failed: %v", err)
			}
			return
		}
		if busClosing.Load() {
			_ = stream.Close()
			return
		}
		go handleStream(&quicStream{stream, conn}, forwarder)
	}
}

func handleStream(stream Stream, forwarder *udpForwarder) {
	defer func() { _ = stream.Close() }()

	command, err := recvCommand(stream)
	if err != nil {
		sendError(stream, fmt.Errorf("recv stream command failed: %v", err))
		return
	}

	var handler func(Stream)

	switch command {
	case "bus":
		handler = func(stream Stream) { handleBusEvent(stream, forwarder) }
	case "session":
		handler = handleSessionEvent
	case "stderr":
		handler = handleStderrEvent
	case "dial":
		handler = handleDialEvent
	case "listen":
		handler = handleListenEvent
	case "accept":
		handler = handleAcceptEvent
	case "dial-udp":
		handler = func(stream Stream) { handleDialUdpEvent(stream, forwarder) }
	case "listen-udp":
		handler = handleListenUdpEvent
	case "accept-udp":
		handler = handleAcceptUdpEvent
	default:
		sendError(stream, fmt.Errorf("unknown stream command: %s", command))
		return
	}

	if !isStreamCommandAuthorized(command, forwarder) {
		sendError(stream, fmt.Errorf("command [%s] requires an active bus connection", command))
		return
	}

	if err := sendSuccess(stream); err != nil { // say hello
		warning("tsshd say hello failed: %v", err)
		return
	}

	handler(stream)
}
