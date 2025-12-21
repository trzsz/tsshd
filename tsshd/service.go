/*
MIT License

Copyright (c) 2024-2025 The Trzsz SSH Authors.

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
	"net"

	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

var smuxConfig = smux.Config{
	Version:           2,
	KeepAliveDisabled: true,
	MaxFrameSize:      48 * 1024,
	MaxStreamBuffer:   10 * 1024 * 1024,
	MaxReceiveBuffer:  20 * 1024 * 1024,
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

func (s *smuxStream) CloseRead() error {
	return fmt.Errorf("smux: half-close is not yet supported")
}

func (s *smuxStream) CloseWrite() error {
	return fmt.Errorf("smux: half-close is not yet supported")
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

func serveKCP(listener *kcp.Listener) {
	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			warning("kcp accept failed: %v", err)
			return
		}
		go handleKcpConn(conn)
	}
}

func handleKcpConn(conn *kcp.UDPSession) {
	onExitFuncs = append(onExitFuncs, func() { _ = conn.Close() })

	if serving.Load() {
		return
	}

	conn.SetWindowSize(1024, 1024)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWriteDelay(false)

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
		go handleStream(&smuxStream{stream})
	}
}

func serveQUIC(listener *quic.Listener) {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			warning("quic accept conn failed: %v", err)
			return
		}
		go handleQuicConn(conn)
	}
}

func handleQuicConn(conn *quic.Conn) {
	onExitFuncs = append(onExitFuncs, func() { _ = conn.CloseWithError(0, "") })

	if serving.Load() {
		return
	}

	globalUdpForwarder = &udpForwarder{conn: conn}

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			if !isClosedError(err) {
				warning("quic accept stream failed: %v", err)
			}
			return
		}
		go handleStream(&quicStream{stream, conn})
	}
}

func handleStream(stream Stream) {
	defer func() { _ = stream.Close() }()

	command, err := recvCommand(stream)
	if err != nil {
		sendError(stream, fmt.Errorf("recv stream command failed: %v", err))
		return
	}

	var handler func(Stream)

	switch command {
	case "bus":
		handler = handleBusEvent
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
		handler = handleDialUdpEvent
	default:
		sendError(stream, fmt.Errorf("unknown stream command: %s", command))
		return
	}

	if err := sendSuccess(stream); err != nil { // say hello
		warning("tsshd say hello failed: %v", err)
		return
	}

	handler(stream)
}
