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
	"crypto/aes"
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type proxyClientAddr struct {
	clientID uint64
}

func (a *proxyClientAddr) Network() string {
	return "udp"
}

func (a *proxyClientAddr) String() string {
	return strconv.FormatUint(a.clientID, 16)
}

type clientState struct {
	sealed       atomic.Bool
	server       atomic.Pointer[sshUdpServer]
	proxyAddr    proxyClientAddr
	serialNumber atomic.Uint64
	clientConn   atomic.Pointer[net.TCPConn]
	clientAddr   atomic.Pointer[net.UDPAddr]
	authedAddr   atomic.Pointer[net.UDPAddr]
	udpFrontConn atomic.Pointer[udpFrontendConn]
	clientMutex  sync.Mutex
	clientCond   *sync.Cond
	pktCache     packetCache
	kcpCrypto    *rotatingCrypto
}

func (c *clientState) remoteAddr() string {
	if addr := c.clientAddr.Load(); addr != nil {
		return addr.String()
	}
	if conn := c.clientConn.Load(); conn != nil {
		return conn.RemoteAddr().String()
	}
	return c.proxyAddr.String()
}

func (c *clientState) waitClientConn() *net.TCPConn {
	if conn := c.clientConn.Load(); conn != nil {
		return conn
	}

	c.clientMutex.Lock()
	defer c.clientMutex.Unlock()

	conn := c.clientConn.Load()
	for conn == nil {
		c.clientCond.Wait()
		conn = c.clientConn.Load()
	}

	return conn
}

func (c *clientState) setClientConn(conn *net.TCPConn) {
	c.clientMutex.Lock()
	oldConn := c.clientConn.Swap(conn)
	c.clientCond.Broadcast()
	c.clientMutex.Unlock()

	if oldConn != nil {
		_ = oldConn.Close()
	}
}

func (c *clientState) setClientAddr(addr *net.UDPAddr) {
	conn := c.udpFrontConn.Load()

	oldAddr := c.clientAddr.Swap(addr)

	if addr != nil && conn != nil {
		conn.addClientMap(c)
	}

	if oldAddr != nil && conn != nil {
		conn.delClientMap(oldAddr)
	}
}

func (c *clientState) setAuthedAddr(addr *net.UDPAddr) {
	conn := c.udpFrontConn.Load()

	oldAddr := c.authedAddr.Swap(addr)

	if addr != nil && conn != nil {
		conn.addAuthedMap(c)
	}

	if oldAddr != nil && conn != nil {
		conn.delAuthedMap(oldAddr)
	}
}

func (c *clientState) sendPacketCache(conn frontendConnection) bool {
	flushSize, flushCount := c.pktCache.sendCache(func(buf []byte) error {
		if c.kcpCrypto != nil {
			var err error
			buf, err = c.kcpCrypto.sealPacket(buf, false)
			if err != nil {
				return err
			}
		}
		return conn.writeTo(buf, c)
	})

	hasCache := flushSize > 0 || flushCount > 0

	if enableDebugLogging && hasCache {
		debug("send packet cache count [%d] size [%d]", flushCount, flushSize)
	}

	return hasCache
}

type frontendConnection interface {
	start(*serverProxy)
	readFrom([]byte) (int, *clientState)
	writeTo([]byte, *clientState) error
}

type udpFrontendConn struct {
	proxy       *serverProxy
	conn        atomic.Pointer[net.UDPConn]
	connList    []*net.UDPConn
	initMutex   sync.Mutex
	initCond    *sync.Cond
	cacheClient atomic.Pointer[clientState]
	clientMutex sync.Mutex
	clientMap   map[string]*clientState
	authedMutex sync.Mutex
	authedMap   map[string]*clientState
}

func (c *udpFrontendConn) start(proxy *serverProxy) {
	c.proxy = proxy
	c.initCond = sync.NewCond(&c.initMutex)

	if len(c.connList) == 1 {
		c.initConn(c.connList[0], nil, 0, 0)
	} else {
		for _, conn := range c.connList {
			go c.probeAuth(conn)
		}
	}
	c.connList = nil
}

func (c *udpFrontendConn) initConn(conn *net.UDPConn, addr *net.UDPAddr, clientID, newSerialNumber uint64) {
	setDSCP(conn, kProxyDSCP)
	_ = conn.SetReadBuffer(kProxyBufferSize)
	_ = conn.SetWriteBuffer(kProxyBufferSize)

	c.initMutex.Lock()
	defer c.initMutex.Unlock()

	if c.conn.Load() != nil {
		_ = conn.Close()
		return
	}
	c.conn.Store(conn)
	c.initCond.Broadcast()
	addOnExitFunc(func() { _ = conn.Close() })

	if addr != nil {
		client := c.proxy.getClient(clientID)
		if client == nil {
			warning("get client [%x] return nil", clientID)
			return
		}
		client.udpFrontConn.Store(c)
		oldSerialNumber := client.serialNumber.Load()
		if newSerialNumber > oldSerialNumber {
			if client.serialNumber.CompareAndSwap(oldSerialNumber, newSerialNumber) {
				client.setAuthedAddr(cloneNetAddr(addr).(*net.UDPAddr))
			}
		}
	}
}

func (c *udpFrontendConn) waitConn() *net.UDPConn {
	if conn := c.conn.Load(); conn != nil {
		return conn
	}

	c.initMutex.Lock()
	defer c.initMutex.Unlock()

	conn := c.conn.Load()
	for conn == nil {
		c.initCond.Wait()
		conn = c.conn.Load()
	}

	return conn
}

func (c *udpFrontendConn) probeAuth(conn *net.UDPConn) {
	buf := make([]byte, 128)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(c.proxy.args.ConnectTimeout))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			_ = conn.Close()
			return
		}

		isAuthPacket, clientID, serialNumber := c.proxy.openAuthPacket(buf[:n])
		if isAuthPacket {
			_ = conn.SetReadDeadline(time.Time{})
			c.initConn(conn, addr, clientID, serialNumber)
			return
		}
	}
}

func (c *udpFrontendConn) addClientMap(client *clientState) {
	if !c.proxy.args.Attachable {
		return
	}

	addr := client.clientAddr.Load()
	if addr == nil {
		return
	}

	c.clientMutex.Lock()
	if c.clientMap == nil {
		c.clientMap = make(map[string]*clientState)
	}
	c.clientMap[addr.String()] = client
	c.clientMutex.Unlock()
}

func (c *udpFrontendConn) delClientMap(addr *net.UDPAddr) {
	if !c.proxy.args.Attachable {
		return
	}

	if addr == nil {
		return
	}

	c.clientMutex.Lock()
	delete(c.clientMap, addr.String())
	c.clientMutex.Unlock()
}

func (c *udpFrontendConn) addAuthedMap(authed *clientState) {
	if !c.proxy.args.Attachable {
		return
	}

	addr := authed.authedAddr.Load()
	if addr == nil {
		return
	}

	c.authedMutex.Lock()
	if c.authedMap == nil {
		c.authedMap = make(map[string]*clientState)
	}
	c.authedMap[addr.String()] = authed
	c.authedMutex.Unlock()
}

func (c *udpFrontendConn) delAuthedMap(addr *net.UDPAddr) {
	if !c.proxy.args.Attachable {
		return
	}

	if addr == nil {
		return
	}

	c.authedMutex.Lock()
	delete(c.authedMap, addr.String())
	c.authedMutex.Unlock()
}

func isSameAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func (c *udpFrontendConn) getClient(addr *net.UDPAddr) (*clientState, bool, bool) {
	if !c.proxy.args.Attachable {
		client := c.proxy.soleClient
		if isSameAddr(client.clientAddr.Load(), addr) {
			return client, true, false
		}
		if isSameAddr(client.authedAddr.Load(), addr) {
			return client, false, true
		}
		return nil, false, false
	}

	if client := c.cacheClient.Load(); client != nil {
		if isSameAddr(client.clientAddr.Load(), addr) {
			return client, true, false
		}
		if isSameAddr(client.authedAddr.Load(), addr) {
			return client, false, true
		}
	}

	key := addr.String()

	c.clientMutex.Lock()
	client := c.clientMap[key]
	c.clientMutex.Unlock()

	if client != nil && isSameAddr(client.clientAddr.Load(), addr) {
		c.cacheClient.Store(client)
		return client, true, false
	}

	c.authedMutex.Lock()
	authed := c.authedMap[key]
	c.authedMutex.Unlock()

	if authed != nil && isSameAddr(authed.authedAddr.Load(), addr) {
		return authed, false, true
	}

	return nil, false, false
}

func (c *udpFrontendConn) readFrom(buf []byte) (int, *clientState) {
	conn := c.waitConn()

	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			warning("frontend read udp failed: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		client, isClientAddr, isAuthedAddr := c.getClient(addr)

		// Case 1: packet from current effective client.
		// Fast path — directly forward.
		if isClientAddr {
			if n <= kSafeToDropPacketLen {
				continue
			}
			return n, client
		}

		// Case 2: packet from authenticated but not yet activated client.
		if isAuthedAddr {

			// Check whether this is still an authentication packet.
			isAuthPacket, clientID, newSerialNumber := c.proxy.openAuthPacket(buf[:n])

			// First non-auth packet means handshake phase completed.
			// Promote authedAddr to effective client.
			if !isAuthPacket {
				if addr := client.authedAddr.Load(); addr != nil {
					client.setClientAddr(addr)
					client.setAuthedAddr(nil)
					c.proxy.onNewClientConn(client)
					if n <= kSafeToDropPacketLen {
						continue
					}
					return n, client
				} else {
					warning("authed addr missing: client_id=%x, new_serial=%d", clientID, newSerialNumber)
					continue
				}
			}

			// Client ID mismatch — this should not happen.
			if clientID != client.proxyAddr.clientID {
				warning("client id mismatch: expected=%d, got=%d", client.proxyAddr.clientID, clientID)
				client.setAuthedAddr(nil)
				continue
			}

			// Redundant authentication packet.
			// Update serial number if newer and resend auth response.
			oldSerialNumber := client.serialNumber.Load()
			if newSerialNumber < oldSerialNumber {
				debug("authenticate rejected: old_serial=%d, new_serial=%d", oldSerialNumber, newSerialNumber)
				continue
			}
			if !client.serialNumber.CompareAndSwap(oldSerialNumber, newSerialNumber) {
				debug("authenticate conflict: old_serial=%d, new_serial=%d", oldSerialNumber, newSerialNumber)
				newSerialNumber = client.serialNumber.Load()
			}
			if b, err := c.proxy.sealAuthPacket(newSerialNumber); err != nil {
				warning("seal auth packet failed: %v", err)
			} else if _, err := conn.WriteTo(b, addr); err != nil {
				warning("send auth packet failed: %v", err)
			}
			continue
		}

		// Case 3: packet from unknown address.
		// Only valid authentication packets can create a new authed address.
		isAuthPacket, clientID, newSerialNumber := c.proxy.openAuthPacket(buf[:n])
		if !isAuthPacket {
			continue
		}

		client = c.proxy.getClient(clientID)
		if client == nil {
			warning("get client [%x] return nil", clientID)
			continue
		}

		client.udpFrontConn.Store(c)
		oldSerialNumber := client.serialNumber.Load()
		if newSerialNumber <= oldSerialNumber {
			debug("authenticate rejected: old_serial=%d, new_serial=%d", oldSerialNumber, newSerialNumber)
			continue
		}

		if client.serialNumber.CompareAndSwap(oldSerialNumber, newSerialNumber) {
			debug("client [%x] [%d] authed from %s", clientID, newSerialNumber, addr)
			// Store as authenticated but not yet activated address.
			client.setAuthedAddr(cloneNetAddr(addr).(*net.UDPAddr))
		} else {
			debug("authenticate conflict: old_serial=%d, new_serial=%d", oldSerialNumber, newSerialNumber)
			newSerialNumber = client.serialNumber.Load()
		}
		// Send authentication response (ack).
		if b, err := c.proxy.sealAuthPacket(newSerialNumber); err != nil {
			warning("seal auth packet failed: %v", err)
		} else if _, err := conn.WriteTo(b, addr); err != nil {
			warning("send auth packet failed: %v", err)
		}
	}
}

func (c *udpFrontendConn) writeTo(buf []byte, client *clientState) error {
	addr := client.clientAddr.Load()
	if addr == nil {
		// Drop the packet immediately instead of waiting for the client to reconnect.
		// In attachable mode, waiting for the old client to reconnect may block new clients from sending packets.
		// In all modes, waiting could block subsequent packets and prevent caching of packets during disconnections.
		// In scenarios with frequent reconnections, a lack of cached packets may fail to reactivate the KCP/QUIC session.
		return fmt.Errorf("client addr is nil")
	}

	_, err := c.waitConn().WriteTo(buf, addr)
	return err
}

type tcpFrameSignal struct {
	conn   *net.TCPConn
	client *clientState
	length int
	ackCh  chan error
}

type tcpFrontendConn struct {
	proxy         *serverProxy
	listenerList  []*net.TCPListener
	frameSignalCh chan *tcpFrameSignal
}

func (c *tcpFrontendConn) start(proxy *serverProxy) {
	c.proxy = proxy

	if proxy.args.Attachable {
		c.frameSignalCh = make(chan *tcpFrameSignal, 10)
	}

	for _, listener := range c.listenerList {
		go c.serve(listener)
	}
	c.listenerList = nil
}

func (c *tcpFrontendConn) serve(listener *net.TCPListener) {
	defer func() { _ = listener.Close() }()
	beginTime := time.Now()
	neverAccepted := true

	for {
		if neverAccepted {
			_ = listener.SetDeadline(time.Now().Add(c.proxy.args.ConnectTimeout))
		}

		conn, err := listener.AcceptTCP()
		if err != nil {
			if neverAccepted && time.Since(beginTime) > c.proxy.args.ConnectTimeout-10*time.Millisecond {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			warning("frontend accept tcp failed: %v", err)
			return
		}

		if neverAccepted {
			neverAccepted = false
			_ = listener.SetDeadline(time.Time{})
			addOnExitFunc(func() { _ = listener.Close() })
		}

		go c.handshake(conn)
	}
}

func (c *tcpFrontendConn) handshake(conn *net.TCPConn) {
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()

	if err := conn.SetReadDeadline(time.Now().Add(c.proxy.args.ConnectTimeout)); err != nil {
		return
	}
	buffer := make([]byte, 128)
	n, err := recvUdpPacket(conn, buffer)
	if err != nil {
		return
	}

	isAuthPacket, clientID, newSerialNumber := c.proxy.openAuthPacket(buffer[:n])
	if !isAuthPacket {
		return
	}

	client := c.proxy.getClient(clientID)
	if client == nil {
		warning("get client [%x] return nil", clientID)
		return
	}
	oldSerialNumber := client.serialNumber.Load()
	if newSerialNumber <= oldSerialNumber {
		debug("handshake rejected: old_serial=%d, new_serial=%d", oldSerialNumber, newSerialNumber)
		return
	}
	if !client.serialNumber.CompareAndSwap(oldSerialNumber, newSerialNumber) {
		debug("handshake conflict: old_serial=%d, new_serial=%d", oldSerialNumber, newSerialNumber)
		return
	}

	// auth success
	debug("client [%x] [%d] authed from %s", clientID, newSerialNumber, conn.RemoteAddr())
	if b, err := c.proxy.sealAuthPacket(newSerialNumber); err != nil {
		warning("seal auth packet failed: %v", err)
		return
	} else if err := sendUdpPacket(conn, b); err != nil {
		warning("send auth packet failed: %v", err)
		return
	}

	setDSCP(conn, kProxyDSCP)
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetReadBuffer(kProxyBufferSize)
	_ = conn.SetWriteBuffer(kProxyBufferSize)

	client.setClientConn(conn)
	c.proxy.onNewClientConn(client)
	ok = true

	if c.proxy.args.Attachable {
		go c.readLoop(conn, client)
	}
}

func (c *tcpFrontendConn) readLoop(conn *net.TCPConn, client *clientState) {
	buf := make([]byte, 2)
	ackCh := make(chan error)

	defer func() {
		if client.clientConn.CompareAndSwap(conn, nil) {
			_ = conn.Close()
		}
		close(ackCh)
	}()

	for conn == client.clientConn.Load() {

		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}

		c.frameSignalCh <- &tcpFrameSignal{
			conn:   conn,
			client: client,
			length: int(binary.BigEndian.Uint16(buf)),
			ackCh:  ackCh,
		}

		if err := <-ackCh; err != nil {
			return
		}
	}
}

func (c *tcpFrontendConn) readFrom(buf []byte) (int, *clientState) {
	if c.proxy.args.Attachable {
		for {
			signal := <-c.frameSignalCh

			if len(buf) < int(signal.length) {
				warning("read buffer too short: buffer=%d, decoded frame length=%d", len(buf), signal.length)
				signal.ackCh <- io.ErrShortBuffer
				continue
			}

			n, err := io.ReadFull(signal.conn, buf[:signal.length])
			if err != nil {
				signal.ackCh <- err
				continue
			}

			signal.ackCh <- nil
			return n, signal.client
		}
	}

	client := c.proxy.soleClient
	for {
		conn := client.waitClientConn()

		n, err := recvUdpPacket(conn, buf)
		if err != nil {
			if client.clientConn.CompareAndSwap(conn, nil) {
				_ = conn.Close()
			}
			continue
		}

		return n, client
	}
}

func (c *tcpFrontendConn) writeTo(buf []byte, client *clientState) error {
	conn := client.clientConn.Load()
	if conn == nil {
		// Drop the packet immediately instead of waiting for the client to reconnect.
		// In attachable mode, waiting for the old client to reconnect may block new clients from sending packets.
		// In all modes, waiting could block subsequent packets and prevent caching of packets during disconnections.
		// In scenarios with frequent reconnections, a lack of cached packets may fail to reactivate the KCP/QUIC session.
		return fmt.Errorf("client conn is nil")
	}

	if err := sendUdpPacket(conn, buf); err != nil {
		if client.clientConn.CompareAndSwap(conn, nil) {
			_ = conn.Close()
		}
		return err
	}

	return nil
}

type serverProxy struct {
	args         *tsshdArgs
	readMutex    sync.Mutex
	frontendConn frontendConnection
	cipherBlock  *cipher.Block
	serverID     uint64
	clientID     uint64
	soleClient   *clientState
	clientMutex  sync.RWMutex
	cachingPkt   atomic.Bool
	// This map is intentionally not cleaned up to prevent replay attacks.
	// Only optimize if memory usage becomes a real issue, and even then,
	// serialNumber must be retained for replay protection.
	clientMap map[uint64]*clientState
	// KCP key
	kcpPass []byte
	kcpSalt []byte
}

func (p *serverProxy) newClientState(clientID uint64) (*clientState, error) {
	client := &clientState{proxyAddr: proxyClientAddr{clientID}}
	client.clientCond = sync.NewCond(&client.clientMutex)

	if p.args.KCP {
		crypto, err := newRotatingCrypto(nil, p.kcpPass, p.kcpSalt, 0, 0, false)
		if err != nil {
			return nil, fmt.Errorf("new rotating crypto failed: %v", err)
		}
		client.kcpCrypto = crypto
	}

	return client, nil
}

func (p *serverProxy) getClient(clientID uint64) *clientState {
	if !p.args.Attachable && clientID == p.clientID {
		return p.soleClient
	}

	p.clientMutex.RLock()
	client, ok := p.clientMap[clientID]
	p.clientMutex.RUnlock()
	if ok {
		return client
	}

	p.clientMutex.Lock()
	defer p.clientMutex.Unlock()

	if client, ok = p.clientMap[clientID]; ok {
		return client
	}

	client, err := p.newClientState(clientID)
	if err != nil {
		warning("new client state failed: %v", err)
		return nil
	}

	if p.clientMap == nil {
		p.clientMap = make(map[uint64]*clientState)
	}
	p.clientMap[clientID] = client

	return client
}

func (p *serverProxy) sealAuthPacket(serialNumber uint64) ([]byte, error) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], p.serverID)
	binary.BigEndian.PutUint64(data[8:16], serialNumber)
	buf := aesEncrypt(p.cipherBlock, data)
	if buf == nil {
		return nil, fmt.Errorf("aes encrypt failed")
	}
	return buf, nil
}

func (p *serverProxy) openAuthPacket(buf []byte) (bool, uint64, uint64) {
	data := aesDecrypt(p.cipherBlock, buf)
	if len(data) != 16 {
		return false, 0, 0
	}

	clientID := binary.BigEndian.Uint64(data[0:8])
	if !p.args.Attachable && clientID != p.clientID {
		return false, 0, 0
	}

	serialNumber := binary.BigEndian.Uint64(data[8:16])
	return true, clientID, serialNumber
}

func (p *serverProxy) onNewClientConn(client *clientState) {
	if enableDebugLogging {
		debug("client [%x] [%d] active from %s", client.proxyAddr.clientID, client.serialNumber.Load(), client.remoteAddr())
	}

	if server := client.server.Load(); server != nil {
		// Discard pending terminal input from previous sessions to prevent stale
		// or unintended input (possibly generated while the client was disconnected)
		// from being delivered after reconnection.
		server.enablePendingInputDiscard()

		client.sendPacketCache(p.frontendConn)
	}
}

func (p *serverProxy) ReadFrom(buf []byte) (int, net.Addr, error) {
	p.readMutex.Lock()
	defer p.readMutex.Unlock()

	var n int
	var client *clientState

	for {
		n, client = p.frontendConn.readFrom(buf)

		if client.kcpCrypto != nil {
			var err error
			n, err = client.kcpCrypto.openPacket(buf[:n])
			if err != nil {
				if enableDebugLogging {
					debug("open packet failed: len=%d, auth=%v", n, len(aesDecrypt(p.cipherBlock, buf[:n])) == 16)
				}
				continue
			}
		}

		break
	}

	if server := client.server.Load(); server != nil {
		server.clientChecker.updateNow()
	}

	return n, &client.proxyAddr, nil
}

// Do not return an error here, otherwise QUIC/KCP may drop all subsequent packets.
func (p *serverProxy) WriteTo(buf []byte, addr net.Addr) (int, error) {
	n := len(buf)
	clientAddr, ok := addr.(*proxyClientAddr)
	if !ok {
		warning("server proxy write to invalid addr type: %T", addr)
		return n, nil
	}

	client := p.getClient(clientAddr.clientID)
	if client == nil {
		warning("get client [%x] return nil", clientAddr.clientID)
		return n, nil
	}

	if server := client.server.Load(); server != nil {
		if server.clientChecker.isTimeout() {
			if enableDebugLogging && p.cachingPkt.CompareAndSwap(false, true) {
				debug("switching to packet caching mode")
			}
			client.pktCache.addPacket(buf)
			return n, nil
		} else if enableDebugLogging && p.cachingPkt.CompareAndSwap(true, false) {
			debug("switching to direct transmission mode")
		}

		if server.shouldSample.Load() && server.shouldSample.CompareAndSwap(true, false) {
			client.pktCache.addSample(buf)
		}
	}

	if client.kcpCrypto != nil {
		var err error
		buf, err = client.kcpCrypto.sealPacket(buf, true)
		if err != nil {
			warning("seal packet failed: %v", err)
			return n, nil
		}
	}

	if err := p.frontendConn.writeTo(buf, client); err != nil {
		debug("frontend write failed: %v", err)
	}
	return n, nil
}

func (p *serverProxy) Close() error {
	debug("server proxy call Close")
	return nil
}

func (p *serverProxy) LocalAddr() net.Addr {
	debug("server proxy call LocalAddr")
	return &net.UDPAddr{}
}

func (p *serverProxy) SetDeadline(t time.Time) error {
	debug("server proxy call SetDeadline with time=%v", t)
	return nil
}

func (p *serverProxy) SetReadDeadline(t time.Time) error {
	debug("server proxy call SetReadDeadline with time=%v", t)
	return nil
}

func (p *serverProxy) SetWriteDeadline(t time.Time) error {
	debug("server proxy call SetWriteDeadline with time=%v", t)
	return nil
}

func (p *serverProxy) SetReadBuffer(bytes int) error {
	debug("server proxy call SetReadBuffer with bytes=%v", bytes)
	return nil
}

func (p *serverProxy) SetWriteBuffer(bytes int) error {
	debug("server proxy call SetWriteBuffer with bytes=%v", bytes)
	return nil
}

func startServerProxy(args *tsshdArgs, info *ServerInfo, conn frontendConnection) (*serverProxy, error) {
	proxyKey := make([]byte, 32)
	if _, err := crypto_rand.Read(proxyKey); err != nil {
		return nil, fmt.Errorf("rand proxy key failed: %v", err)
	}
	info.ProxyKey = fmt.Sprintf("%x", proxyKey)
	cipherBlock, err := aes.NewCipher(proxyKey)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher failed: %v", err)
	}

	proxy := &serverProxy{
		args:         args,
		frontendConn: conn,
		cipherBlock:  &cipherBlock,
	}

	if args.KCP {
		proxy.kcpPass = make([]byte, 48)
		if _, err := crypto_rand.Read(proxy.kcpPass); err != nil {
			return nil, fmt.Errorf("rand pass failed: %v", err)
		}
		proxy.kcpSalt = make([]byte, 48)
		if _, err := crypto_rand.Read(proxy.kcpSalt); err != nil {
			return nil, fmt.Errorf("rand salt failed: %v", err)
		}
		info.Pass = fmt.Sprintf("%x", proxy.kcpPass)
		info.Salt = fmt.Sprintf("%x", proxy.kcpSalt)
	}

	if !args.Attachable {
		for info.ClientID == 0 {
			clientID := make([]byte, 8)
			if _, err := crypto_rand.Read(clientID); err != nil {
				return nil, fmt.Errorf("rand client id failed: %v", err)
			}
			info.ClientID = binary.BigEndian.Uint64(clientID)
		}
		proxy.clientID = info.ClientID

		client, err := proxy.newClientState(info.ClientID)
		if err != nil {
			return nil, fmt.Errorf("new client state failed: %v", err)
		}
		proxy.soleClient = client
	}

	serverID := make([]byte, 8)
	if _, err := crypto_rand.Read(serverID); err != nil {
		return nil, fmt.Errorf("rand server id failed: %v", err)
	}
	info.ServerID = binary.BigEndian.Uint64(serverID)
	proxy.serverID = info.ServerID

	if args.TCP {
		info.ProxyMode = kProxyModeTCP
	}

	conn.start(proxy)

	return proxy, nil
}
