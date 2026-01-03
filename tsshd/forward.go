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
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

var acceptMutex sync.Mutex
var acceptID atomic.Uint64
var acceptMap = make(map[uint64]net.Conn)

func sendProhibited(stream Stream, option string) {
	sendErrorCode(stream, ErrProhibited, fmt.Sprintf("Check [%s] in [%s] on the server.", option, sshdConfigPath))
}

func handleDialEvent(stream Stream) {
	var msg dialMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv dial message failed: %v", err))
		return
	}

	if strings.HasPrefix(msg.Net, "udp") {
		sendError(stream, fmt.Errorf("use DialUDP for [%s]", msg.Net))
		return
	}

	if v := strings.ToLower(getSshdConfig("AllowTcpForwarding")); v == "no" || v == "remote" {
		sendProhibited(stream, "AllowTcpForwarding")
		return
	}

	if msg.Net == "unix" {
		if v := strings.ToLower(getSshdConfig("AllowStreamLocalForwarding")); v == "no" || v == "remote" {
			sendProhibited(stream, "AllowStreamLocalForwarding")
			return
		}
	}

	if v := strings.ToLower(getSshdConfig("DisableForwarding")); v == "yes" {
		sendProhibited(stream, "DisableForwarding")
		return
	}

	var err error
	var conn net.Conn
	if msg.Timeout > 0 {
		conn, err = net.DialTimeout(msg.Net, msg.Addr, msg.Timeout)
	} else {
		conn, err = net.Dial(msg.Net, msg.Addr)
	}
	if err != nil {
		sendError(stream, err)
		return
	}

	defer func() { _ = conn.Close() }()

	var resp dialResponse
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		resp.RemoteAddr = addr
	}
	if err := sendResponse(stream, &resp); err != nil { // ack ok
		warning("dial ack ok failed: %v", err)
		return
	}

	forwardConnection(stream, conn)
}

func handleListenEvent(stream Stream) {
	var msg listenMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv listen message failed: %v", err))
		return
	}

	if v := strings.ToLower(getSshdConfig("AllowTcpForwarding")); v == "no" || v == "local" {
		sendProhibited(stream, "AllowTcpForwarding")
		return
	}

	if msg.Net == "unix" {
		if v := strings.ToLower(getSshdConfig("AllowStreamLocalForwarding")); v == "no" || v == "local" {
			sendProhibited(stream, "AllowStreamLocalForwarding")
			return
		}
	}

	if v := strings.ToLower(getSshdConfig("DisableForwarding")); v == "yes" {
		sendProhibited(stream, "DisableForwarding")
		return
	}

	listener, err := net.Listen(msg.Net, msg.Addr)
	if err != nil {
		sendError(stream, err)
		return
	}

	onExitFuncs = append(onExitFuncs, func() {
		_ = listener.Close()
		if msg.Net == "unix" {
			_ = os.Remove(msg.Addr)
		}
	})
	defer func() { _ = listener.Close() }()

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("listen ack ok failed: %v", err)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedError(err) {
				break
			}
			warning("listener [%s] [%s] accept failed: %v", msg.Net, msg.Addr, err)
			break
		}
		id := addAcceptConn(conn)
		if err := sendMessage(stream, acceptMessage{id}); err != nil {
			if conn := getAcceptConn(id); conn != nil {
				_ = conn.Close()
			}
			warning("send accept message failed: %v", err)
			return
		}
	}
}

func handleAcceptEvent(stream Stream) {
	var msg acceptMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv accept message failed: %v", err))
		return
	}

	conn := getAcceptConn(msg.ID)
	if conn == nil {
		sendError(stream, fmt.Errorf("invalid accept id: %d", msg.ID))
		return
	}

	defer func() { _ = conn.Close() }()

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("accept ack ok failed: %v", err)
		return
	}

	forwardConnection(stream, conn)
}

func addAcceptConn(conn net.Conn) uint64 {
	acceptMutex.Lock()
	defer acceptMutex.Unlock()
	id := acceptID.Add(1) - 1
	acceptMap[id] = conn
	return id
}

func getAcceptConn(id uint64) net.Conn {
	acceptMutex.Lock()
	defer acceptMutex.Unlock()
	if conn, ok := acceptMap[id]; ok {
		delete(acceptMap, id)
		return conn
	}
	return nil
}

func forwardConnection(stream Stream, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Go(func() { forwardConnInput(stream, conn) })
	wg.Go(func() { forwardConnOutput(stream, conn) })
	wg.Wait()
}

func forwardConnInput(stream Stream, conn net.Conn) {
	buffer := make([]byte, 32*1024)
	for {
		n, err := stream.Read(buffer)
		if n > 0 {
			if err := writeAll(conn, buffer[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}

	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}

	_ = stream.CloseRead()
}

func forwardConnOutput(stream Stream, conn net.Conn) {
	buffer := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			if globalServerProxy.clientChecker.isTimeout() {
				if globalServerProxy.clientChecker.waitUntilReconnected() != nil {
					break
				}
			}
			if err := writeAll(stream, buffer[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}

	_ = stream.CloseWrite()

	if cr, ok := conn.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}
}
