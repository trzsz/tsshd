/*
MIT License

Copyright (c) 2024 The Trzsz SSH Authors.

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
	MaxFrameSize:      32 * 1024,
	MaxStreamBuffer:   64 * 1024,
	MaxReceiveBuffer:  4 * 1024 * 1024,
}

type quicStream struct {
	quic.Stream
	conn quic.Connection
}

func (s *quicStream) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *quicStream) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func serveKCP(listener *kcp.Listener) {
	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			trySendErrorMessage("kcp accept failed: %v", err)
			return
		}
		go handleKcpConn(conn)
	}
}

func handleKcpConn(conn *kcp.UDPSession) {
	defer conn.Close()

	if serving.Load() {
		return
	}

	conn.SetNoDelay(1, 10, 2, 1)

	session, err := smux.Server(conn, &smuxConfig)
	if err != nil {
		trySendErrorMessage("kcp smux server failed: %v", err)
		return
	}

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			trySendErrorMessage("kcp smux accept stream failed: %v", err)
			return
		}
		go handleStream(stream)
	}
}

func serveQUIC(listener *quic.Listener) {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			trySendErrorMessage("quic accept conn failed: %v", err)
			return
		}
		go handleQuicConn(conn)
	}
}

func handleQuicConn(conn quic.Connection) {
	defer func() {
		_ = conn.CloseWithError(0, "")
	}()

	if serving.Load() {
		return
	}

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			trySendErrorMessage("quic accept stream failed: %v", err)
			return
		}
		go handleStream(&quicStream{stream, conn})
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	command, err := RecvCommand(stream)
	if err != nil {
		SendError(stream, fmt.Errorf("recv stream command failed: %v", err))
		return
	}

	var handler func(net.Conn)

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
	default:
		SendError(stream, fmt.Errorf("unknown stream command: %s", command))
		return
	}

	if err := SendSuccess(stream); err != nil { // say hello
		trySendErrorMessage("tsshd say hello failed: %v", err)
		return
	}

	handler(stream)
}
