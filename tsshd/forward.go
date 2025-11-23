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
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

var acceptMutex sync.Mutex
var acceptID atomic.Uint64
var acceptMap = make(map[uint64]net.Conn)

func sendProhibited(stream net.Conn, option string) {
	sendErrorCode(stream, ErrProhibited, fmt.Sprintf("Check [%s] in [%s] on the server.", option, sshdConfigPath))
}

func handleDialEvent(stream net.Conn) {
	var msg dialMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv dial message failed: %v", err))
		return
	}

	if v := strings.ToLower(getSshdConfig("AllowTcpForwarding")); v == "no" || v == "remote" {
		sendProhibited(stream, "AllowTcpForwarding")
		return
	}

	if msg.Network == "unix" {
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
		conn, err = net.DialTimeout(msg.Network, msg.Addr, msg.Timeout)
	} else {
		conn, err = net.Dial(msg.Network, msg.Addr)
	}
	if err != nil {
		sendError(stream, err)
		return
	}

	defer func() { _ = conn.Close() }()

	if err := sendSuccess(stream); err != nil { // ack ok
		trySendErrorMessage("dial ack ok failed: %v", err)
		return
	}

	forwardConnection(stream, conn)
}

func handleListenEvent(stream net.Conn) {
	var msg listenMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv listen message failed: %v", err))
		return
	}

	if v := strings.ToLower(getSshdConfig("AllowTcpForwarding")); v == "no" || v == "local" {
		sendProhibited(stream, "AllowTcpForwarding")
		return
	}

	if msg.Network == "unix" {
		if v := strings.ToLower(getSshdConfig("AllowStreamLocalForwarding")); v == "no" || v == "local" {
			sendProhibited(stream, "AllowStreamLocalForwarding")
			return
		}
	}

	if v := strings.ToLower(getSshdConfig("DisableForwarding")); v == "yes" {
		sendProhibited(stream, "DisableForwarding")
		return
	}

	listener, err := net.Listen(msg.Network, msg.Addr)
	if err != nil {
		sendError(stream, err)
		return
	}

	onExitFuncs = append(onExitFuncs, func() {
		_ = listener.Close()
		if msg.Network == "unix" {
			_ = os.Remove(msg.Addr)
		}
	})
	defer func() { _ = listener.Close() }()

	if err := sendSuccess(stream); err != nil { // ack ok
		trySendErrorMessage("listen ack ok failed: %v", err)
		return
	}

	for {
		conn, err := listener.Accept()
		if err == io.EOF {
			break
		}
		if err != nil {
			trySendErrorMessage("listener %s [%s] accept failed: %v", msg.Network, msg.Addr, err)
			continue
		}
		id := addAcceptConn(conn)
		if err := sendMessage(stream, acceptMessage{id}); err != nil {
			if conn := getAcceptConn(id); conn != nil {
				_ = conn.Close()
			}
			trySendErrorMessage("send accept message failed: %v", err)
			return
		}
	}
}

func handleAcceptEvent(stream net.Conn) {
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
		trySendErrorMessage("accept ack ok failed: %v", err)
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

func forwardConnection(stream net.Conn, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(conn, stream)
		if cw, ok := conn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			// close the entire stream since there is no half-close
			time.Sleep(200 * time.Millisecond)
			_ = conn.Close()
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(stream, conn)
		if cw, ok := stream.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			// close the entire stream since there is no half-close
			time.Sleep(200 * time.Millisecond)
			_ = stream.Close()
		}
	})
	wg.Wait()
}

func handleUDPv1Event(stream net.Conn) {
	var msg udpv1Message
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv UDPv1 message failed: %v", err))
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", msg.Addr)
	if err != nil {
		sendError(stream, fmt.Errorf("resolve udp addr [%s] failed: %v", msg.Addr, err))
		return
	}
	testConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		sendError(stream, fmt.Errorf("dial udp [%s] failed: %v", msg.Addr, err))
		return
	}
	_ = testConn.Close()

	if err := sendSuccess(stream); err != nil { // ack ok
		trySendErrorMessage("UDPv1 ack ok failed: %v", err)
		return
	}

	connMgr := &udpv1ConnManager{
		stream:  stream,
		udpAddr: udpAddr,
		timeout: msg.Timeout,
		connMap: make(map[uint16]*udpv1ConnEntry),
	}
	go connMgr.cleanupInactiveConn()
	connMgr.frontendToBackend()
}

type udpv1ConnEntry struct {
	udpPort   uint16
	udpConn   *net.UDPConn
	closeChan chan struct{}
	aliveTime atomic.Pointer[time.Time]
}

type udpv1ConnManager struct {
	mutex     sync.Mutex
	stream    net.Conn
	udpAddr   *net.UDPAddr
	timeout   time.Duration
	connMap   map[uint16]*udpv1ConnEntry
	aliveTime atomic.Pointer[time.Time]
}

func (m *udpv1ConnManager) frontendToBackend() {
	for {
		port, data, err := recvUDPv1Packet(m.stream)
		if err != nil {
			trySendErrorMessage("UDPv1 forward recv packet failed: %v", err)
			return
		}
		now := time.Now()
		m.aliveTime.Store(&now)
		conn, err := m.getUdpConn(port)
		if err != nil {
			trySendErrorMessage("UDPv1 forward get udp conn failed: %v", err)
			continue
		}
		_, _ = conn.Write(data)
	}
}

func (m *udpv1ConnManager) backendToFrontend(entry *udpv1ConnEntry) {
	buffer := make([]byte, 0xffff)
	for {
		select {
		case <-entry.closeChan:
			return
		default:
			_ = entry.udpConn.SetReadDeadline(time.Now().Add(m.timeout))
			n, _, err := entry.udpConn.ReadFromUDP(buffer)
			if err != nil || n <= 0 {
				continue
			}
			now := time.Now()
			entry.aliveTime.Store(&now)
			if err := sendUDPv1Packet(m.stream, entry.udpPort, buffer[:n]); err != nil {
				trySendErrorMessage("UDPv1 forward send back to [%d] failed: %v", entry.udpPort, err)
			}
		}
	}
}
func (m *udpv1ConnManager) getUdpConn(port uint16) (*net.UDPConn, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if entry, ok := m.connMap[port]; ok {
		return entry.udpConn, nil
	}

	conn, err := net.DialUDP("udp", nil, m.udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial udp [%s] failed: %v", m.udpAddr.String(), err)
	}
	_ = conn.SetReadBuffer(kProxyBufferSize)
	_ = conn.SetWriteBuffer(kProxyBufferSize)

	entry := &udpv1ConnEntry{
		udpPort:   port,
		udpConn:   conn,
		closeChan: make(chan struct{}),
	}
	now := time.Now()
	entry.aliveTime.Store(&now)
	m.connMap[port] = entry

	go m.backendToFrontend(entry)
	return conn, nil
}

func (m *udpv1ConnManager) cleanupInactiveConn() {
	now := time.Now()
	m.aliveTime.Store(&now)
	for {
		time.Sleep(m.timeout)
		m.mutex.Lock()
		for port, entry := range m.connMap {
			if m.aliveTime.Load().Sub(*entry.aliveTime.Load()) > m.timeout {
				close(entry.closeChan)
				_ = entry.udpConn.Close()
				delete(m.connMap, port)
			}
		}
		m.mutex.Unlock()
	}
}
