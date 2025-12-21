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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

var globalUdpForwarder *udpForwarder

var udpForwardChannelID atomic.Uint64

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

type udpForwarder struct {
	conn       *quic.Conn
	channelMap sync.Map
	workerOnce sync.Once
	closingCh  chan uint64
}

func (f *udpForwarder) addChannel(id uint64) chan []byte {
	f.workerOnce.Do(f.startWorker)

	ch := make(chan []byte, 1024)
	f.channelMap.Store(id, ch)
	return ch
}

func (f *udpForwarder) removeChannel(id uint64) {
	f.workerOnce.Do(f.startWorker)
	f.closingCh <- id
}

func (f *udpForwarder) startWorker() {
	f.closingCh = make(chan uint64, 10)
	incomingBufferChan := make(chan []byte)

	go func() {
		defer close(incomingBufferChan)
		for {
			buf, err := f.conn.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}

			if len(buf) < 8 {
				continue
			}

			incomingBufferChan <- buf
		}
	}()

	go func() {
		for {
			select {
			case buf, ok := <-incomingBufferChan:
				if !ok {
					return
				}

				id := binary.BigEndian.Uint64(buf[len(buf)-8:])
				val, ok := f.channelMap.Load(id)
				if !ok {
					continue
				}

				if ch, ok := val.(chan []byte); ok {
					select {
					case ch <- buf[:len(buf)-8]:
					default:
					}
				}

			case id := <-f.closingCh:
				val, ok := f.channelMap.LoadAndDelete(id)
				if !ok {
					continue
				}

				if ch, ok := val.(chan []byte); ok {
					close(ch)
				}
			}
		}
	}()
}

func (f *udpForwarder) sendDatagram(id uint64, buf []byte) bool {
	// Since packet loss detection is not implemented, we conservatively limit
	// the payload size to avoid drops caused by exceeding the effective MTU.
	if len(buf) > 1100 {
		return false
	}

	tag := make([]byte, 8)
	binary.BigEndian.PutUint64(tag, id)
	if err := f.conn.SendDatagram(append(buf, tag...)); err != nil {
		return false
	}
	return true
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

	return c.stream.Close()
}

func handleDialUdpEvent(stream Stream) {
	var msg dialUdpMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv dial message failed: %v", err))
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

	addr, err := net.ResolveUDPAddr(msg.Net, msg.Addr)
	if err != nil {
		sendError(stream, err)
		return
	}

	conn, err := net.DialUDP(msg.Net, nil, addr)
	if err != nil {
		sendError(stream, err)
		return
	}

	id := udpForwardChannelID.Add(1)
	pconn := newPacketConn(stream, id, globalUdpForwarder, globalServerProxy.clientChecker)

	resp := dialUdpResponse{ID: id}
	if err := sendResponse(stream, &resp); err != nil { // ack ok
		warning("dial udp ack ok failed: %v", err)
		return
	}

	var ok udpReadyMessage
	if err := recvMessage(stream, &ok); err != nil {
		warning("recv udp ready message failed: %v", err)
		return
	}

	forwardUDP(pconn, conn)
}

func forwardUDP(pconn *packetConn, conn *net.UDPConn) {
	defer func() {
		_ = conn.Close()
		_ = pconn.Close()
	}()

	done1 := make(chan struct{})
	done2 := make(chan struct{})

	go func() {
		defer close(done1)
		_ = pconn.Consume(func(buf []byte) error {
			_, err := conn.Write(buf)
			return err
		})
	}()

	go func() {
		defer close(done2)
		buffer := make([]byte, 0xffff)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				return
			}
			if err := pconn.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()

	select {
	case <-done1:
	case <-done2:
	}
}
