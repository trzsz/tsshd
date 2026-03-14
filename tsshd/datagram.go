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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

const kMaxUdpForwardPendingPackets = 1024

const kUdpForwardChannelIdSize = 8

// PacketConn represents a connection capable of sending and receiving packet-based data.
type PacketConn interface {

	// Close closes the connection and releases any associated resources.
	Close() error

	// Write sends a single packet over the connection.
	// The implementation may append an additional 8-byte identifier or metadata to the payload.
	Write([]byte) error

	// Read reads a single packet from the connection into the provided buffer.
	Read([]byte) (int, error)

	// Consume repeatedly reads packets from the connection and passes each packet to the
	// provided consumeFn callback until an error occurs.
	Consume(consumeFn func([]byte) error) error
}

// PacketListener represents a remote UDP listening endpoint.
type PacketListener interface {

	// AcceptUDP waits for and returns the next incoming UDP forwarding session.
	AcceptUDP() (PacketConn, error)

	// Close closes the listener and releases any associated resources.
	Close() error
}

type datagramConn interface {
	GetMaxDatagramSize() uint16
	SendDatagram(data []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

type udpForwarder struct {
	conn       datagramConn
	channelMap sync.Map
	workerOnce sync.Once
	closingCh  chan uint64
	ctx        context.Context
	cancel     context.CancelFunc
	closed     atomic.Bool
	closeMutex sync.Mutex
}

func (f *udpForwarder) addChannel(id uint64) chan []byte {
	f.closeMutex.Lock()
	defer f.closeMutex.Unlock()
	if f.closed.Load() {
		return nil
	}

	f.workerOnce.Do(f.startWorker)

	ch := make(chan []byte, 1024)
	f.channelMap.Store(id, ch)
	return ch
}

func (f *udpForwarder) removeChannel(id uint64) {
	f.closeMutex.Lock()
	defer f.closeMutex.Unlock()
	if f.closed.Load() {
		return
	}

	// The worker goroutine is expected to keep processing f.closingCh quickly
	f.workerOnce.Do(f.startWorker)
	f.closingCh <- id
}

func (f *udpForwarder) startWorker() {
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.closingCh = make(chan uint64, 10)
	incomingBufferChan := make(chan []byte)

	go func() {
		defer close(incomingBufferChan)
		for {
			buf, err := f.conn.ReceiveDatagram(f.ctx)
			if err != nil {
				return
			}

			if len(buf) < kUdpForwardChannelIdSize {
				continue
			}

			incomingBufferChan <- buf
		}
	}()

	go func() {
		closeChannel := func(val any) {
			if ch, ok := val.(chan []byte); ok {
				close(ch)
			}
		}
		defer func() {
			// Before exiting, also ensure f.closingCh is processed quickly, until Close() closes f.closingCh
			for id := range f.closingCh {
				if val, ok := f.channelMap.LoadAndDelete(id); ok {
					closeChannel(val)
				}
			}
			f.channelMap.Range(func(key, val any) bool {
				closeChannel(val)
				return true
			})
		}()
		for {
			select {
			case buf, ok := <-incomingBufferChan:
				if !ok {
					return
				}

				id := binary.BigEndian.Uint64(buf[len(buf)-kUdpForwardChannelIdSize:])
				val, ok := f.channelMap.Load(id)
				if !ok {
					continue
				}

				if ch, ok := val.(chan []byte); ok {
					select {
					case ch <- buf[:len(buf)-kUdpForwardChannelIdSize]:
					default:
					}
				}

			case id, ok := <-f.closingCh:
				if !ok {
					return
				}
				if val, ok := f.channelMap.LoadAndDelete(id); ok {
					closeChannel(val)
				}
			}
		}
	}()
}

func (f *udpForwarder) sendDatagram(id uint64, buf []byte) bool {
	if f.closed.Load() {
		return false
	}

	if len(buf) > int(f.conn.GetMaxDatagramSize()) {
		return false
	}

	tag := make([]byte, kUdpForwardChannelIdSize)
	binary.BigEndian.PutUint64(tag, id)
	if err := f.conn.SendDatagram(append(buf, tag...)); err != nil {
		return false
	}
	return true
}

func (f *udpForwarder) Close() {
	f.closeMutex.Lock()
	defer f.closeMutex.Unlock()
	if !f.closed.CompareAndSwap(false, true) {
		return
	}

	if f.cancel != nil {
		f.cancel()
	}

	if f.closingCh != nil {
		close(f.closingCh)
	}
}

// packetConn implements PacketConn over either QUIC datagrams (unordered)
// or a reliable stream fallback. Read and Consume are mutually exclusive.
type packetConn struct {
	stream     Stream
	forwarder  *udpForwarder
	peerCheck  *timeoutChecker
	readMutex  sync.Mutex
	readerOnce sync.Once
	channelID  uint64
	channelCh  chan []byte
	streamCh   chan []byte
	consumeFn  atomic.Pointer[func([]byte) error]
	closed     atomic.Bool
	closeCh    chan struct{}
}

func newPacketConn(stream Stream, id uint64, forwarder *udpForwarder, peerCheck *timeoutChecker) *packetConn {
	var ch chan []byte
	if forwarder != nil {
		ch = forwarder.addChannel(id)
	}
	return &packetConn{
		stream:    stream,
		forwarder: forwarder,
		peerCheck: peerCheck,
		channelID: id,
		channelCh: ch,
		closeCh:   make(chan struct{}),
	}
}

func (c *packetConn) Consume(consumeFn func([]byte) error) error {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.closed.Load() {
		return io.EOF
	}

	c.consumeFn.Store(&consumeFn)
	defer func() { c.consumeFn.Store(nil) }()

	c.readerOnce.Do(c.startStreamReader)

	for {
		select {
		case buf, ok := <-c.channelCh:
			if !ok {
				return io.EOF
			}
			if err := consumeFn(buf); err != nil {
				return err
			}
		case buf, ok := <-c.streamCh:
			if !ok {
				return io.EOF
			}
			if err := consumeFn(buf); err != nil {
				return err
			}
		}
	}
}

func (c *packetConn) Read(buffer []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.closed.Load() {
		return 0, io.EOF
	}

	if c.forwarder == nil {
		return recvUdpPacket(c.stream, buffer)
	}

	c.readerOnce.Do(c.startStreamReader)

	select {
	case buf, ok := <-c.channelCh:
		if !ok {
			return 0, io.EOF
		}
		return copy(buffer, buf), nil
	case buf, ok := <-c.streamCh:
		if !ok {
			return 0, io.EOF
		}
		return copy(buffer, buf), nil
	}
}

func (c *packetConn) startStreamReader() {
	c.streamCh = make(chan []byte, 1)
	go func() {
		defer close(c.streamCh)
		buffer := make([]byte, 0xffff)
		for {
			n, err := recvUdpPacket(c.stream, buffer)
			if err != nil {
				return
			}

			if consumeFn := c.consumeFn.Load(); consumeFn != nil {
				if (*consumeFn)(buffer[:n]) != nil {
					return
				}
				continue
			}

			select {
			case c.streamCh <- append([]byte(nil), buffer[:n]...):
			case <-c.closeCh:
				return
			}
		}
	}()
}

func (c *packetConn) Write(buf []byte) error {
	if c.peerCheck.isTimeout() {
		if err := c.peerCheck.waitUntilReconnected(); err != nil {
			return err
		}
	}

	if c.forwarder != nil {
		if c.forwarder.sendDatagram(c.channelID, buf) {
			return nil
		}
	}

	if err := sendUdpPacket(c.stream, buf); err != nil {
		return err
	}
	return nil
}

func (c *packetConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(c.closeCh)

	if c.forwarder != nil {
		c.forwarder.removeChannel(c.channelID)
	}

	if c.stream == nil {
		return nil
	}
	return c.stream.Close()
}

func (s *sshUdpServer) handleDialUdpEvent(stream Stream) {
	var msg dialUdpMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv dial udp message failed: %v", err))
		return
	}

	if v := strings.ToLower(getSshdConfig("AllowTcpForwarding")); v == "no" || v == "remote" {
		sendProhibited(stream, "AllowTcpForwarding")
		return
	}

	if msg.Net == "unixgram" {
		if v := strings.ToLower(getSshdConfig("AllowStreamLocalForwarding")); v == "no" || v == "remote" {
			sendProhibited(stream, "AllowStreamLocalForwarding")
			return
		}
	}

	if v := strings.ToLower(getSshdConfig("DisableForwarding")); v == "yes" {
		sendProhibited(stream, "DisableForwarding")
		return
	}

	conn, err := dialUDP(&msg)
	if err != nil {
		sendError(stream, err)
		return
	}

	id := s.nextUdpFwdChannelID.Add(1)
	pconn := newPacketConn(stream, id, s.proto.getUdpForwarder(), s.clientChecker)

	resp := dialUdpResponse{ID: id}
	if err := sendResponse(stream, &resp); err != nil { // ack ok
		warning("send dial udp response failed: %v", err)
		return
	}

	var ok udpReadyMessage
	if err := recvMessage(stream, &ok); err != nil {
		warning("recv udp ready message failed: %v", err)
		return
	}

	forwardUDP(pconn, conn, &msg)
}

type unixgramConn struct {
	io.ReadWriteCloser
	localAddr string
}

func (c *unixgramConn) Close() error {
	err := c.ReadWriteCloser.Close()
	_ = os.Remove(c.localAddr)
	return err
}

func dialUDP(msg *dialUdpMessage) (io.ReadWriteCloser, error) {
	if msg.Net == "unixgram" {
		tmpFile, err := os.CreateTemp("", "tsshd_unixgram_*.sock")
		if err != nil {
			return nil, fmt.Errorf("create temp file failed: %v", err)
		}
		localAddr := tmpFile.Name()
		if err := tmpFile.Close(); err != nil {
			return nil, fmt.Errorf("close temp file failed: %v", err)
		}
		if err := os.Remove(localAddr); err != nil {
			return nil, fmt.Errorf("remove temp file failed: %v", err)
		}
		laddr := &net.UnixAddr{Net: "unixgram", Name: localAddr}
		raddr := &net.UnixAddr{Net: "unixgram", Name: msg.Addr}
		conn, err := net.DialUnix("unixgram", laddr, raddr)
		if err != nil {
			if _, err := os.Stat(localAddr); err == nil {
				_ = os.Remove(localAddr)
			}
			return nil, err
		}
		return &unixgramConn{conn, localAddr}, nil
	}

	var err error
	var addr *net.UDPAddr
	if msg.Timeout > 0 {
		addr, err = doWithTimeout(func() (*net.UDPAddr, error) {
			return net.ResolveUDPAddr(msg.Net, msg.Addr)
		}, msg.Timeout)
	} else {
		addr, err = net.ResolveUDPAddr(msg.Net, msg.Addr)
	}
	if err != nil {
		return nil, err
	}

	return net.DialUDP(msg.Net, nil, addr)
}

func forwardUDP(pconn *packetConn, conn io.ReadWriteCloser, msg *dialUdpMessage) {
	defer func() {
		_ = conn.Close()
		_ = pconn.Close()
	}()

	done1 := make(chan struct{})
	done2 := make(chan struct{})

	go func() {
		defer close(done1)
		var warnOnce sync.Once
		_ = pconn.Consume(func(buf []byte) error {
			if _, err := conn.Write(buf); err != nil {
				if isClosedError(err) {
					debug("udp forwarding write to [%s] [%s] closed: %v", msg.Net, msg.Addr, err)
					return err
				}
				warnOnce.Do(func() {
					warning("udp forwarding write to [%s] [%s] failed: %v", msg.Net, msg.Addr, err)
				})
			}
			return nil
		})
	}()

	go func() {
		defer close(done2)
		buffer := make([]byte, 0xffff)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if isClosedError(err) {
					debug("udp forwarding read from [%s] [%s] closed: %v", msg.Net, msg.Addr, err)
					return
				}
				warning("udp forwarding read from [%s] [%s] failed: %v", msg.Net, msg.Addr, err)
				return
			}
			if err := pconn.Write(buffer[:n]); err != nil {
				if isClosedError(err) {
					debug("udp forwarding [%s] [%s] write closed: %v", msg.Net, msg.Addr, err)
					return
				}
				warning("udp forwarding [%s] [%s] write failed: %v", msg.Net, msg.Addr, err)
				return
			}
		}
	}()

	select {
	case <-done1:
	case <-done2:
	}
}

type udpForwardSession struct {
	sessionKey   string
	listenerNet  string
	listenerAddr string
	listenerConn net.PacketConn
	forwardConn  *packetConn
	peerAddr     net.Addr
	warnOnce     sync.Once
	writeMu      sync.Mutex
	pendingBuf   [][]byte
	pendingFlag  bool
}

func (s *udpForwardSession) writePacket(data []byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.pendingFlag {
		if len(s.pendingBuf) >= kMaxUdpForwardPendingPackets {
			return
		}
		buf := make([]byte, len(data), len(data)+kUdpForwardChannelIdSize)
		copy(buf, data)
		s.pendingBuf = append(s.pendingBuf, buf)
		return
	}

	s.doWrite(data)
}

func (s *udpForwardSession) doWrite(data []byte) {
	if err := s.forwardConn.Write(data); err != nil {
		if isClosedError(err) {
			debug("udp forwarding [%s] [%s] write closed: %v", s.listenerNet, s.listenerAddr, err)
			return
		}
		s.warnOnce.Do(func() {
			warning("udp forwarding [%s] [%s] write failed: %v", s.listenerNet, s.listenerAddr, err)
		})
	}
}

func (s *udpForwardSession) attachStream(stream Stream) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.forwardConn.stream = stream
	s.pendingFlag = false

	for _, data := range s.pendingBuf {
		s.doWrite(data)
	}
	s.pendingBuf = nil
}

func (s *udpForwardSession) Close() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.forwardConn != nil {
		_ = s.forwardConn.Close()
	}
}

func (s *udpForwardSession) getPeerAddr() string {
	if s.peerAddr == nil {
		return "nil"
	}
	return s.peerAddr.String()
}

func (s *sshUdpServer) acquireUdpForwardSession(sessionKey, listenerNet, listenerAddr string,
	listenerConn net.PacketConn, peerAddr net.Addr) (*udpForwardSession, bool) {
	s.udpFwdSessionMutex.Lock()
	defer s.udpFwdSessionMutex.Unlock()

	if s.udpFwdSessionMap == nil {
		s.udpFwdSessionMap = make(map[string]*udpForwardSession)
	}

	session, exists := s.udpFwdSessionMap[sessionKey]
	if exists {
		return session, true
	}

	id := s.nextUdpFwdChannelID.Add(1)
	forwardConn := newPacketConn(nil, id, s.proto.getUdpForwarder(), s.clientChecker)
	session = &udpForwardSession{
		sessionKey:   sessionKey,
		listenerNet:  listenerNet,
		listenerAddr: listenerAddr,
		listenerConn: listenerConn,
		forwardConn:  forwardConn,
		peerAddr:     cloneNetAddr(peerAddr),
		pendingFlag:  true,
	}
	s.udpFwdSessionMap[sessionKey] = session

	return session, false
}

func (s *sshUdpServer) releaseUdpForwardSession(session *udpForwardSession) {
	s.udpFwdSessionMutex.Lock()
	delete(s.udpFwdSessionMap, session.sessionKey)
	s.udpFwdSessionMutex.Unlock()

	session.Close()
}

func (s *sshUdpServer) addUdpFwdPendingSession(id uint64, session *udpForwardSession) {
	s.udpFwdPendingMutex.Lock()
	defer s.udpFwdPendingMutex.Unlock()

	if s.udpFwdPendingMap == nil {
		s.udpFwdPendingMap = make(map[uint64]*udpForwardSession)
	}

	s.udpFwdPendingMap[id] = session
}

func (s *sshUdpServer) takeUdpFwdPendingSession(id uint64) *udpForwardSession {
	s.udpFwdPendingMutex.Lock()
	defer s.udpFwdPendingMutex.Unlock()

	if session, ok := s.udpFwdPendingMap[id]; ok {
		delete(s.udpFwdPendingMap, id)
		return session
	}

	return nil
}

func (s *sshUdpServer) handleListenUdpEvent(stream Stream) {
	var msg listenUdpMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv listen udp message failed: %v", err))
		return
	}

	if v := strings.ToLower(getSshdConfig("AllowTcpForwarding")); v == "no" || v == "local" {
		sendProhibited(stream, "AllowTcpForwarding")
		return
	}

	if msg.Net == "unixgram" {
		if v := strings.ToLower(getSshdConfig("AllowStreamLocalForwarding")); v == "no" || v == "local" {
			sendProhibited(stream, "AllowStreamLocalForwarding")
			return
		}
	}

	if v := strings.ToLower(getSshdConfig("DisableForwarding")); v == "yes" {
		sendProhibited(stream, "DisableForwarding")
		return
	}

	listenerConn, err := net.ListenPacket(msg.Net, msg.Addr)
	if err != nil {
		sendError(stream, err)
		return
	}

	addOnExitFunc(func() {
		_ = listenerConn.Close()
		if msg.Net == "unixgram" {
			_ = os.Remove(msg.Addr)
		}
	})
	defer func() { _ = listenerConn.Close() }()

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("udp listener [%s] [%s] ack ok failed: %v", msg.Net, msg.Addr, err)
		return
	}

	listenerID := s.nextUdpFwdListenerID.Add(1)
	buf := make([]byte, 0xffff)
	for {
		n, addr, err := listenerConn.ReadFrom(buf)
		if err != nil {
			if isClosedError(err) {
				debug("udp listener [%s] [%s] closed: %v", msg.Net, msg.Addr, err)
				break
			}
			warning("udp listener [%s] [%s] read failed: %v", msg.Net, msg.Addr, err)
			break
		}

		var sessionKey string
		if addr != nil {
			sessionKey = fmt.Sprintf("%d_%s", listenerID, addr.String())
		} else {
			sessionKey = fmt.Sprintf("%d_nil", listenerID)
		}

		session, exists := s.acquireUdpForwardSession(sessionKey, msg.Net, msg.Addr, listenerConn, addr)

		session.writePacket(buf[:n])

		if exists {
			continue
		}

		id := session.forwardConn.channelID
		s.addUdpFwdPendingSession(id, session)

		if err := sendMessage(stream, acceptUdpMessage{id}); err != nil {
			_ = s.takeUdpFwdPendingSession(id)
			s.releaseUdpForwardSession(session)
			if isClosedError(err) {
				debug("udp listener [%s] [%s] send accept udp message closed: %v", msg.Net, msg.Addr, err)
				return
			}
			warning("udp listener [%s] [%s] send accept udp message failed: %v", msg.Net, msg.Addr, err)
			continue
		}
	}
}

func (s *sshUdpServer) handleAcceptUdpEvent(stream Stream) {
	var msg acceptUdpMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv accept udp message failed: %v", err))
		return
	}

	session := s.takeUdpFwdPendingSession(msg.ID)

	if session == nil {
		sendError(stream, fmt.Errorf("invalid accept udp id: %d", msg.ID))
		return
	}

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("accept udp ack ok failed: %v", err)
		return
	}

	session.attachStream(stream)
	defer s.releaseUdpForwardSession(session)

	var warnOnce sync.Once
	_ = session.forwardConn.Consume(func(buf []byte) error {
		if _, err := session.listenerConn.WriteTo(buf, session.peerAddr); err != nil {
			if isClosedError(err) {
				if enableDebugLogging {
					debug("udp listener [%s] [%s] write to [%s] closed: %v", session.listenerNet, session.listenerAddr, session.getPeerAddr(), err)
				}
				return err
			}
			warnOnce.Do(func() {
				if enableWarningLogging {
					warning("udp listener [%s] [%s] write to [%s] failed: %v", session.listenerNet, session.listenerAddr, session.getPeerAddr(), err)
				}
			})
		}
		return nil
	})
}

func cloneNetAddr(addr net.Addr) net.Addr {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return &net.UDPAddr{
			IP:   append([]byte(nil), v.IP...),
			Port: v.Port,
			Zone: v.Zone,
		}
	case *net.IPAddr:
		return &net.IPAddr{
			IP:   append([]byte(nil), v.IP...),
			Zone: v.Zone,
		}
	case *net.UnixAddr:
		return &net.UnixAddr{
			Name: v.Name,
			Net:  v.Net,
		}
	default:
		return addr
	}
}
