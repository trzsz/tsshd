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
	"os"
	"strconv"
	"strings"
	"sync"
)

// streamLocalBindMask returns the StreamLocalBindMask from sshd_config.
// OpenSSH's default is 0177.
func streamLocalBindMask() int {
	v := getSshdConfig("StreamLocalBindMask")
	if v == "" {
		return 0177
	}
	mask, err := strconv.ParseInt(v, 8, 32)
	if err != nil || mask < 0 || mask > 0777 {
		warning("invalid StreamLocalBindMask [%s] in [%s], using default 0177", v, sshdConfigPath)
		return 0177
	}
	return int(mask)
}

// unlinkStaleUnixSocket honors StreamLocalBindUnlink from sshd_config. If the
// path exists and is a unix socket, it is removed. Non-socket files are
// refused. Missing paths are a no-op.
func unlinkStaleUnixSocket(path string) error {
	if strings.ToLower(getSshdConfig("StreamLocalBindUnlink")) != "yes" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to unlink non-socket path: %s", path)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	debug("unlinked existing unix socket [%s] per StreamLocalBindUnlink", path)
	return nil
}

func sendProhibited(stream Stream, option string) {
	sendErrorCode(stream, ErrProhibited, fmt.Sprintf("Check [%s] in [%s] on the server.", option, sshdConfigPath))
}

func (s *sshUdpServer) handleDialEvent(stream Stream) {
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
		warning("send dial response failed: %v", err)
		return
	}

	s.forwardConnection(stream, conn)
}

func (s *sshUdpServer) handleListenEvent(stream Stream) {
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

	if msg.Net == "unix" {
		if err := unlinkStaleUnixSocket(msg.Addr); err != nil {
			sendError(stream, err)
			return
		}
	}

	listener, err := net.Listen(msg.Net, msg.Addr)
	if err != nil {
		sendError(stream, err)
		return
	}

	if msg.Net == "unix" {
		mode := os.FileMode(0666) &^ os.FileMode(streamLocalBindMask())
		if err := os.Chmod(msg.Addr, mode); err != nil {
			warning("chmod unix socket [%s] to %#o failed: %v", msg.Addr, mode, err)
		}
	}

	addOnExitFunc(func() {
		_ = listener.Close()
		if msg.Net == "unix" {
			_ = os.Remove(msg.Addr)
		}
	})
	defer func() { _ = listener.Close() }()

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("listener [%s] [%s] ack ok failed: %v", msg.Net, msg.Addr, err)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedError(err) {
				debug("listener [%s] [%s] closed: %v", msg.Net, msg.Addr, err)
				break
			}
			warning("listener [%s] [%s] accept failed: %v", msg.Net, msg.Addr, err)
			break
		}
		id := s.addAcceptConn(conn)
		if err := sendMessage(stream, acceptMessage{id}); err != nil {
			if conn := s.takeAcceptConn(id); conn != nil {
				_ = conn.Close()
			}
			if isClosedError(err) {
				debug("listener [%s] [%s] send accept message closed: %v", msg.Net, msg.Addr, err)
				return
			}
			warning("listener [%s] [%s] send accept message failed: %v", msg.Net, msg.Addr, err)
			return
		}
	}
}

func (s *sshUdpServer) handleAcceptEvent(stream Stream) {
	var msg acceptMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv accept message failed: %v", err))
		return
	}

	conn := s.takeAcceptConn(msg.ID)
	if conn == nil {
		sendError(stream, fmt.Errorf("invalid accept id: %d", msg.ID))
		return
	}

	defer func() { _ = conn.Close() }()

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("accept ack ok failed: %v", err)
		return
	}

	s.forwardConnection(stream, conn)
}

func (s *sshUdpServer) addAcceptConn(conn net.Conn) uint64 {
	s.fwdAcceptMutex.Lock()
	defer s.fwdAcceptMutex.Unlock()

	if s.fwdAcceptMap == nil {
		s.fwdAcceptMap = make(map[uint64]net.Conn)
	}

	id := s.nextFwdAcceptID.Add(1) - 1
	s.fwdAcceptMap[id] = conn
	return id
}

func (s *sshUdpServer) takeAcceptConn(id uint64) net.Conn {
	s.fwdAcceptMutex.Lock()
	defer s.fwdAcceptMutex.Unlock()

	if conn, ok := s.fwdAcceptMap[id]; ok {
		delete(s.fwdAcceptMap, id)
		return conn
	}

	return nil
}

func (s *sshUdpServer) forwardConnection(stream Stream, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Go(func() { s.forwardConnInput(stream, conn) })
	wg.Go(func() { s.forwardConnOutput(stream, conn) })
	wg.Wait()
}

func (s *sshUdpServer) forwardConnInput(stream Stream, conn net.Conn) {
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

func (s *sshUdpServer) forwardConnOutput(stream Stream, conn net.Conn) {
	buffer := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			if s.clientChecker.isTimeout() {
				if s.clientChecker.waitUntilReconnected() != nil {
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
