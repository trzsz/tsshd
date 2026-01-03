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
	"crypto/aes"
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var globalServerProxy *serverProxy

const kProxyBufferSize = 1024 * 1024

const kProxyDSCP = 46

func setDSCP(conn net.Conn, dscp int) {
	_ = ipv4.NewConn(conn).SetTOS(dscp << 2)
	_ = ipv6.NewConn(conn).SetTrafficClass(dscp)
}

func aesEncrypt(cipherBlock *cipher.Block, buf []byte) []byte {
	gcm, err := cipher.NewGCM(*cipherBlock)
	if err != nil {
		return nil
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := crypto_rand.Read(nonce); err != nil {
		return nil
	}
	return gcm.Seal(nonce, nonce, buf, nil)
}

func aesDecrypt(cipherBlock *cipher.Block, buf []byte) []byte {
	gcm, err := cipher.NewGCM(*cipherBlock)
	if err != nil {
		return nil
	}
	nonceSize := gcm.NonceSize()
	if len(buf) < nonceSize {
		return nil
	}
	nonce, cipherText := buf[:nonceSize], buf[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil
	}
	return plainText
}

func sendUdpPacket(conn io.Writer, data []byte) error {
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	copy(buf[2:], data)
	return writeAll(conn, buf)
}

func recvUdpPacket(conn io.Reader, data []byte) (int, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(buf))
	if n < 0 || n > len(data) {
		return 0, fmt.Errorf("invalid udp length: %d", n)
	}
	if _, err := io.ReadFull(conn, data[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

type packetCache struct {
	buffer     [100][]byte
	mutex      sync.Mutex
	head       int
	tail       int
	size       int
	totalSize  int
	totalCount int
}

func (p *packetCache) addPacket(buf []byte) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	data := make([]byte, len(buf))
	copy(data, buf)

	p.buffer[p.tail] = data
	p.tail = (p.tail + 1) % len(p.buffer)

	if p.size < len(p.buffer) {
		p.size++
	} else {
		p.head = (p.head + 1) % len(p.buffer)
	}

	if enableDebugLogging {
		p.totalSize += len(buf)
		p.totalCount++
	}
}

func (p *packetCache) sendCache(writeFn func([]byte) error) (flushSize, flushCount int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i := 0; i < p.size; i++ {
		index := (p.head + i) % len(p.buffer)
		if p.buffer[index] == nil {
			continue
		}
		if enableDebugLogging {
			flushSize += len(p.buffer[index])
			flushCount++
		}
		_ = writeFn(p.buffer[index])
	}

	return flushSize, flushCount
}

func (p *packetCache) clearCache() (totalSize, totalCount int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i := 0; i < p.size; i++ {
		index := (p.head + i) % len(p.buffer)
		p.buffer[index] = nil
	}

	p.head, p.size = p.tail, 0

	if enableDebugLogging {
		totalSize, totalCount = p.totalSize, p.totalCount
		p.totalSize, p.totalCount = 0, 0
	}
	return
}

type clientConnection interface {
	Addr() string
	Close()
	Write([]byte) error
	Equal(clientConnection) bool
}

type tcpClientConn struct {
	conn net.Conn
}

func (t *tcpClientConn) Addr() string {
	if t == nil {
		return ""
	}
	return t.conn.RemoteAddr().String()
}

func (t *tcpClientConn) Close() {
	if t == nil {
		return
	}
	_ = t.conn.Close()
}

func (t *tcpClientConn) Write(buf []byte) error {
	if t == nil {
		return fmt.Errorf("tcpClientConn is nil")
	}
	return sendUdpPacket(t.conn, buf)
}

func (t *tcpClientConn) Equal(clientConnection) bool {
	return false
}

type udpClientConn struct {
	frontendConn *net.UDPConn
	clientAddr   *net.UDPAddr
}

func (u *udpClientConn) Addr() string {
	if u == nil {
		return ""
	}
	return u.clientAddr.String()
}

func (u *udpClientConn) Close() {
}

func (u *udpClientConn) Write(buf []byte) error {
	if u == nil {
		return fmt.Errorf("udpClientConn is nil")
	}
	_, err := u.frontendConn.WriteToUDP(buf, u.clientAddr)
	return err
}

func (u *udpClientConn) Equal(c clientConnection) bool {
	if u == nil {
		return false
	}

	if c, ok := c.(*udpClientConn); ok {
		return u.frontendConn == c.frontendConn &&
			u.clientAddr.Port == c.clientAddr.Port &&
			u.clientAddr.Zone == c.clientAddr.Zone &&
			u.clientAddr.IP.Equal(c.clientAddr.IP)
	}

	return false
}

type clientConnHolder struct {
	clientConnection
}

type udpBuffer struct {
	conn *udpClientConn
	data []byte
}

type serverProxy struct {
	args          *tsshdArgs
	frontendList  []io.Closer
	backendConn   *net.UDPConn
	clientConn    atomic.Pointer[clientConnHolder]
	authedConn    clientConnection
	cipherBlock   *cipher.Block
	clientID      uint64
	serverID      uint64
	serialNumber  atomic.Uint64
	bufChan       chan *udpBuffer
	pktCache      packetCache
	clientChecker *timeoutChecker
	sendCacheFlag atomic.Bool
}

func (p *serverProxy) sendAuthPacket(conn clientConnection) error {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], p.serverID)
	binary.BigEndian.PutUint64(data[8:16], p.serialNumber.Load())
	buf := aesEncrypt(p.cipherBlock, data)
	if buf == nil {
		return fmt.Errorf("aes encrypt failed")
	}
	return conn.Write(buf)
}

func (p *serverProxy) verifyAuthPacket(buf []byte) (bool, uint64) {
	data := aesDecrypt(p.cipherBlock, buf)
	if len(data) != 16 {
		return false, 0
	}
	clientID := binary.BigEndian.Uint64(data[0:8])
	if clientID != p.clientID {
		return false, 0
	}
	serialNumber := binary.BigEndian.Uint64(data[8:16])
	return true, serialNumber
}

func (p *serverProxy) setClientConn(newClientConn *clientConnHolder) {
	oldClientConn := p.clientConn.Swap(newClientConn)

	if enableDebugLogging {
		debug("new client address [%d]: %s", p.serialNumber.Load(), newClientConn.Addr())
	}

	p.clientChecker.updateNow()

	if oldClientConn != nil {
		oldClientConn.Close()
		enablePendingInputDiscard() // discard pending user input from previous connections
	}

	flushSize, flushCount := p.pktCache.sendCache(newClientConn.Write)
	if enableDebugLogging {
		debug("send packet cache count [%d] cache size [%d]", flushCount, flushSize)
	}
}

func (p *serverProxy) udpFrontendToBackend() {
	for buf := range p.bufChan {
		if conn := p.clientConn.Load(); conn != nil && conn.Equal(buf.conn) {
			p.onClientActive(conn.Write)
			if _, err := p.backendConn.Write(buf.data); err != nil {
				warning("write to backend failed: %v", err)
			}
			continue
		}

		if p.authedConn != nil && p.authedConn.Equal(buf.conn) {
			isAuthPacket, serialNumber := p.verifyAuthPacket(buf.data)
			if !isAuthPacket { // auth success
				p.setClientConn(&clientConnHolder{p.authedConn})
				p.authedConn = nil
				if _, err := p.backendConn.Write(buf.data); err != nil {
					warning("write to backend failed: %v", err)
				}
				continue
			}
			if serialNumber >= p.serialNumber.Load() {
				p.serialNumber.Store(serialNumber)
				_ = p.sendAuthPacket(buf.conn)
			}
			continue
		}

		isAuthPacket, serialNumber := p.verifyAuthPacket(buf.data)
		if isAuthPacket && serialNumber > p.serialNumber.Load() {
			if enableDebugLogging {
				debug("new authed address [%d]: %s", serialNumber, buf.conn.Addr())
			}
			p.authedConn = buf.conn
			p.serialNumber.Store(serialNumber)
			_ = p.sendAuthPacket(buf.conn)
			continue
		}
	}
}

func (p *serverProxy) udpServeFrontendConn(conn *net.UDPConn) {
	defer func() { _ = conn.Close() }()
	beginTime := time.Now()
	neverReceived := true

	current := 0
	buffers := [2][]byte{make([]byte, 0xffff), make([]byte, 0xffff)}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(p.args.ConnectTimeout))
		n, addr, err := conn.ReadFromUDP(buffers[current])
		if err != nil {
			if neverReceived && time.Since(beginTime) > p.args.ConnectTimeout-10*time.Millisecond {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			warning("frontend read udp failed: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		neverReceived = false
		p.bufChan <- &udpBuffer{
			conn: &udpClientConn{
				frontendConn: conn,
				clientAddr: &net.UDPAddr{
					IP:   append([]byte(nil), addr.IP...),
					Port: addr.Port,
					Zone: addr.Zone,
				},
			},
			data: buffers[current][:n],
		}
		current = 1 - current
	}
}

func (p *serverProxy) onClientActive(writeFn func([]byte) error) {
	p.clientChecker.updateNow()

	if p.sendCacheFlag.Load() {
		p.sendCacheFlag.Store(false)
		flushSize, flushCount := p.pktCache.sendCache(writeFn)
		if enableDebugLogging {
			debug("send packet cache count [%d] cache size [%d]", flushCount, flushSize)
		}
	}
}

func (p *serverProxy) tcpFrontendToBackend(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(p.args.ConnectTimeout)); err != nil {
		return
	}
	buffer := make([]byte, 0xffff)
	n, err := recvUdpPacket(conn, buffer)
	if err != nil {
		return
	}

	isAuthPacket, newSerialNumber := p.verifyAuthPacket(buffer[:n])
	if !isAuthPacket {
		return
	}
	debug("new authed address [%d]: %s", newSerialNumber, conn.RemoteAddr().String())

	oldSerialNumber := p.serialNumber.Load()
	if newSerialNumber <= oldSerialNumber {
		return
	}
	if !p.serialNumber.CompareAndSwap(oldSerialNumber, newSerialNumber) {
		return
	}

	// auth success
	clientConn := &tcpClientConn{conn}
	if err := p.sendAuthPacket(clientConn); err != nil {
		return
	}

	p.setClientConn(&clientConnHolder{clientConn})

	_ = conn.SetReadDeadline(time.Time{})
	for {
		n, err := recvUdpPacket(conn, buffer)
		if err != nil { // server ignore TCP frontend error
			return
		}

		p.onClientActive(clientConn.Write)

		if _, err := p.backendConn.Write(buffer[:n]); err != nil {
			warning("write to backend failed: %v", err)
		}
	}
}

func (p *serverProxy) tcpServeFrontendListener(listener *net.TCPListener) {
	defer func() { _ = listener.Close() }()
	beginTime := time.Now()
	neverAccepted := true

	for {
		_ = listener.SetDeadline(time.Now().Add(p.args.ConnectTimeout))
		conn, err := listener.AcceptTCP()
		if err != nil {
			if neverAccepted && time.Since(beginTime) > p.args.ConnectTimeout-10*time.Millisecond {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			warning("frontend accept tcp failed: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		neverAccepted = false
		setDSCP(conn, kProxyDSCP)
		_ = conn.SetReadBuffer(kProxyBufferSize)
		_ = conn.SetWriteBuffer(kProxyBufferSize)
		go p.tcpFrontendToBackend(conn)
	}
}

func (p *serverProxy) backendToFrontend() {
	buffer := make([]byte, 0xffff)
	for {
		n, err := p.backendConn.Read(buffer)
		if err != nil {
			warning("backend read udp failed: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if p.clientChecker.isTimeout() {
			p.pktCache.addPacket(buffer[:n])
			continue
		}

		if conn := p.clientConn.Load(); conn != nil {
			_ = conn.Write(buffer[:n])
		}
	}
}

func (p *serverProxy) serveProxy() {
	if p.args.TCP {
		for _, c := range p.frontendList {
			if listener, ok := c.(*net.TCPListener); ok {
				go p.tcpServeFrontendListener(listener)
			}
		}
	} else {
		p.bufChan = make(chan *udpBuffer) // unbuffered channel to avaid copying buffer
		for _, c := range p.frontendList {
			if conn, ok := c.(*net.UDPConn); ok {
				setDSCP(conn, kProxyDSCP)
				_ = conn.SetReadBuffer(kProxyBufferSize)
				_ = conn.SetWriteBuffer(kProxyBufferSize)
				go p.udpServeFrontendConn(conn)
			}
		}
		go p.udpFrontendToBackend()
	}

	_ = p.backendConn.SetReadBuffer(kProxyBufferSize)
	_ = p.backendConn.SetWriteBuffer(kProxyBufferSize)
	go p.backendToFrontend()
}

func startServerProxy(args *tsshdArgs, info *ServerInfo, frontendList []io.Closer) (*net.UDPConn, error) {
	localAddr := "127.0.0.1:0"
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr [%s] failed: %v", localAddr, err)
	}
	serverConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp on [%s] failed: %v", localAddr, err)
	}
	svrAddr := serverConn.LocalAddr().String()
	svrUdpAddr, err := net.ResolveUDPAddr("udp", svrAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr [%s] failed: %v", svrAddr, err)
	}
	backendConn, err := net.DialUDP("udp", nil, svrUdpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial udp [%s] failed: %v", svrAddr, err)
	}

	proxyKey := make([]byte, 32)
	if _, err := crypto_rand.Read(proxyKey); err != nil {
		return nil, fmt.Errorf("rand proxy key failed: %v", err)
	}
	cipherBlock, err := aes.NewCipher(proxyKey)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher failed: %v", err)
	}
	clientID := make([]byte, 8)
	if _, err := crypto_rand.Read(clientID); err != nil {
		return nil, fmt.Errorf("rand client id failed: %v", err)
	}
	serverID := make([]byte, 8)
	if _, err := crypto_rand.Read(serverID); err != nil {
		return nil, fmt.Errorf("rand server id failed: %v", err)
	}

	if args.TCP {
		info.ProxyMode = kProxyModeTCP
	}
	info.ProxyKey = fmt.Sprintf("%x", proxyKey)
	info.ClientID = binary.BigEndian.Uint64(clientID)
	info.ServerID = binary.BigEndian.Uint64(serverID)

	globalServerProxy = &serverProxy{
		args:          args,
		frontendList:  frontendList,
		backendConn:   backendConn,
		cipherBlock:   &cipherBlock,
		clientID:      info.ClientID,
		serverID:      info.ServerID,
		clientChecker: newTimeoutChecker(args.ConnectTimeout),
	}

	if enableDebugLogging {
		globalServerProxy.clientChecker.onTimeout(func() {
			debug("blocked due to no client input for [%dms]", globalServerProxy.clientChecker.timeoutMilli.Load())
		})
		globalServerProxy.clientChecker.onReconnected(func() {
			debug("resumed after receiving client input")
		})
	}

	globalServerProxy.clientChecker.onTimeout(func() {
		globalServerProxy.sendCacheFlag.Store(true)
	})

	go globalServerProxy.serveProxy()

	return serverConn, nil
}

type tcpServerConn struct {
	conn net.Conn
}

func (t *tcpServerConn) Close() error {
	return t.conn.Close()
}

func (t *tcpServerConn) Write(buf []byte) error {
	return sendUdpPacket(t.conn, buf)
}

func (t *tcpServerConn) Read(buf []byte) (int, error) {
	return recvUdpPacket(t.conn, buf)
}

func (t *tcpServerConn) Consume(consumeFn func([]byte) error) error {
	buffer := make([]byte, 0xffff)
	for {
		n, err := t.Read(buffer)
		if err != nil {
			return err
		}
		if err := consumeFn(buffer[:n]); err != nil {
			return err
		}
	}
}

type udpServerConn struct {
	conn *net.UDPConn
}

func (u *udpServerConn) Close() error {
	return u.conn.Close()
}

func (u *udpServerConn) Write(buf []byte) error {
	_, err := u.conn.Write(buf)
	return err
}

func (u *udpServerConn) Read(buf []byte) (int, error) {
	return u.conn.Read(buf)
}

func (u *udpServerConn) Consume(consumeFn func([]byte) error) error {
	buffer := make([]byte, 0xffff)
	for {
		n, err := u.Read(buffer)
		if err != nil {
			return err
		}
		if err := consumeFn(buffer[:n]); err != nil {
			return err
		}
	}
}

type serverConnHolder struct {
	PacketConn
}

type clientProxy struct {
	client        *SshUdpClient
	frontendConn  *net.UDPConn
	backendConn   atomic.Pointer[serverConnHolder]
	proxyMode     string
	serverNet     string
	serverAddr    string
	cipherBlock   *cipher.Block
	clientID      uint64
	serverID      uint64
	renewMutex    sync.Mutex
	serialNumber  uint64
	pktCache      packetCache
	serverChecker *timeoutChecker
	closed        atomic.Bool
}

func (p *clientProxy) frontendToBackend() {
	var clientAddr *net.UDPAddr
	buffer := make([]byte, 0xffff)
	for !p.closed.Load() {
		n, addr, err := p.frontendConn.ReadFromUDP(buffer)
		if err != nil {
			if isClosedError(err) {
				break
			}
			p.client.warning("frontend read udp failed: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if clientAddr == nil {
			clientAddr = &net.UDPAddr{
				IP:   append([]byte(nil), addr.IP...),
				Port: addr.Port,
				Zone: addr.Zone,
			}
			go p.backendToFrontend(clientAddr)
		}

		if clientAddr.Port != addr.Port || !clientAddr.IP.Equal(addr.IP) || clientAddr.Zone != addr.Zone {
			continue
		}

		if p.serverChecker.isTimeout() {
			p.pktCache.addPacket(buffer[:n])
			continue
		}

		if conn := p.backendConn.Load(); conn != nil {
			_ = conn.Write(buffer[:n])
		}
	}
}

func (p *clientProxy) backendToFrontend(clientAddr *net.UDPAddr) {
	for !p.closed.Load() {
		if conn := p.backendConn.Load(); conn != nil {
			if err := conn.Consume(func(buf []byte) error {
				p.serverChecker.updateNow()
				if _, err := p.frontendConn.WriteToUDP(buf, clientAddr); err != nil {
					p.client.warning("write to frontend failed: %v", err)
				}
				return nil
			}); err != nil { // client ignore backend error
				time.Sleep(10 * time.Millisecond)
				continue
			}
		} else {
			time.Sleep(5 * time.Millisecond) // wait for reconnect
		}
	}
}

func (p *clientProxy) renewTransportPath(proxyClient *SshUdpClient, connectTimeout time.Duration) error {
	p.renewMutex.Lock()
	defer p.renewMutex.Unlock()
	p.serialNumber++

	if conn := p.backendConn.Load(); conn != nil {
		_ = conn.Close()
		p.backendConn.Store(nil)
	}

	var err error
	if p.proxyMode == kProxyModeTCP {
		err = p.renewTcpPath(proxyClient, connectTimeout)
	} else {
		err = p.renewUdpPath(proxyClient, connectTimeout)
	}
	if err != nil {
		return err
	}

	p.serverChecker.updateNow()

	flushSize, flushCount := p.pktCache.sendCache(p.backendConn.Load().Write)
	if enableDebugLogging {
		p.client.debug("send packet cache count [%d] cache size [%d]", flushCount, flushSize)
	}
	return nil
}

func (p *clientProxy) renewTcpPath(proxyClient *SshUdpClient, connectTimeout time.Duration) error {
	var conn *serverConnHolder
	var setReadDeadline func(t time.Time) error
	if proxyClient != nil {
		tcpConn, err := proxyClient.DialTimeout(p.serverNet, p.serverAddr, connectTimeout)
		if err != nil {
			return fmt.Errorf("proxy dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		setReadDeadline = tcpConn.SetReadDeadline
		conn = &serverConnHolder{&tcpServerConn{tcpConn}}
	} else {
		serverAddr, err := doWithTimeout(func() (*net.TCPAddr, error) {
			return net.ResolveTCPAddr(p.serverNet, p.serverAddr)
		}, connectTimeout)
		if err != nil {
			return fmt.Errorf("resolve addr [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		tcpConn, err := doWithTimeout(func() (*net.TCPConn, error) {
			return net.DialTCP(p.serverNet, nil, serverAddr)
		}, connectTimeout)
		if err != nil {
			return fmt.Errorf("dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		setDSCP(tcpConn, kProxyDSCP)
		_ = tcpConn.SetReadBuffer(kProxyBufferSize)
		_ = tcpConn.SetWriteBuffer(kProxyBufferSize)
		setReadDeadline = tcpConn.SetReadDeadline
		conn = &serverConnHolder{&tcpServerConn{tcpConn}}
	}

	if err := p.sendAuthPacket(conn); err != nil {
		_ = conn.Close()
		return err
	}

	if err := setReadDeadline(time.Now().Add(connectTimeout)); err != nil {
		_ = conn.Close()
		return fmt.Errorf("set read deadline failed: %v", err)
	}

	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("recv auth packet failed: %v", err)
	}

	if !p.isAuthSuccessful(buffer[:n]) {
		_ = conn.Close()
		return fmt.Errorf("proxy auth failed")
	}
	p.client.debug("serial number [%d] auth success", p.serialNumber)

	_ = setReadDeadline(time.Time{})
	p.backendConn.Store(conn)
	return nil
}

func (p *clientProxy) renewUdpPath(proxyClient *SshUdpClient, connectTimeout time.Duration) error {
	var conn *serverConnHolder
	if proxyClient != nil {
		udpConn, err := proxyClient.DialUDP(p.serverNet, p.serverAddr, connectTimeout)
		if err != nil {
			return fmt.Errorf("proxy dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		conn = &serverConnHolder{udpConn}
	} else {
		serverAddr, err := doWithTimeout(func() (*net.UDPAddr, error) {
			return net.ResolveUDPAddr(p.serverNet, p.serverAddr)
		}, connectTimeout)
		if err != nil {
			return fmt.Errorf("resolve addr [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		udpConn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			return fmt.Errorf("dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		setDSCP(udpConn, kProxyDSCP)
		_ = udpConn.SetReadBuffer(kProxyBufferSize)
		_ = udpConn.SetWriteBuffer(kProxyBufferSize)
		conn = &serverConnHolder{&udpServerConn{udpConn}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer close(done)
		buffer := make([]byte, 256)
		for ctx.Err() == nil {
			n, err := conn.Read(buffer)
			if err != nil {
				done <- fmt.Errorf("read auth packet failed: %v", err)
				return
			}
			if p.isAuthSuccessful(buffer[:n]) {
				p.client.debug("serial number [%d] auth success", p.serialNumber)
				p.backendConn.Store(conn)
				done <- nil
				return
			}
		}
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	if err := p.sendAuthPacket(conn); err != nil {
		_ = conn.Close()
		return fmt.Errorf("send auth packet failed: %v", err)
	}

	for {
		select {
		case err := <-done:
			return err
		case <-ticker.C:
			if err := p.sendAuthPacket(conn); err != nil {
				_ = conn.Close()
				return fmt.Errorf("send auth packet failed: %v", err)
			}
		case <-ctx.Done():
			_ = conn.Close()
			return fmt.Errorf("renew path to [%s] [%s] timeout [%v]", p.serverNet, p.serverAddr, connectTimeout)
		}
	}
}

func (p *clientProxy) sendAuthPacket(conn PacketConn) error {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], p.clientID)
	binary.BigEndian.PutUint64(data[8:16], p.serialNumber)
	buf := aesEncrypt(p.cipherBlock, data)
	if buf == nil {
		return fmt.Errorf("aes encrypt failed")
	}
	return conn.Write(buf)
}

func (p *clientProxy) isAuthSuccessful(buf []byte) bool {
	data := aesDecrypt(p.cipherBlock, buf)
	if len(data) != 16 {
		return false
	}
	serverID := binary.BigEndian.Uint64(data[0:8])
	if serverID != p.serverID {
		return false
	}
	serialNumber := binary.BigEndian.Uint64(data[8:16])
	if serialNumber > p.serialNumber {
		p.serialNumber = serialNumber
		return false
	}
	return p.serialNumber == serialNumber
}

func (p *clientProxy) serveProxy() {
	_ = p.frontendConn.SetReadBuffer(kProxyBufferSize)
	_ = p.frontendConn.SetWriteBuffer(kProxyBufferSize)
	go p.frontendToBackend()
}

func (p *clientProxy) Close() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}

	if conn := p.backendConn.Load(); conn != nil {
		_ = conn.Close()
		p.backendConn.Store(nil)
	}

	_ = p.frontendConn.Close()

	p.serverChecker.Close()
}

func startClientProxy(client *SshUdpClient, opts *UdpClientOptions) (string, *clientProxy, error) {
	proxyKey, err := hex.DecodeString(opts.ServerInfo.ProxyKey)
	if err != nil {
		return "", nil, fmt.Errorf("decode proxy key [%s] failed: %v", opts.ServerInfo.ProxyKey, err)
	}
	cipherBlock, err := aes.NewCipher(proxyKey)
	if err != nil {
		return "", nil, fmt.Errorf("aes new cipher for key [%s] failed: %v", opts.ServerInfo.ProxyKey, err)
	}

	localAddr := "127.0.0.1:0"
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return "", nil, fmt.Errorf("resolve udp addr [%s] failed: %v", localAddr, err)
	}
	frontendConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", nil, fmt.Errorf("listen udp on [%s] failed: %v", localAddr, err)
	}
	proxyAddr := frontendConn.LocalAddr().String()

	network := "udp"
	if opts.ServerInfo.ProxyMode == kProxyModeTCP {
		network = "tcp"
	}
	if opts.IPv4 && !opts.IPv6 {
		network += "4"
	} else if opts.IPv6 && !opts.IPv4 {
		network += "6"
	}

	proxy := &clientProxy{
		client:        client,
		frontendConn:  frontendConn,
		proxyMode:     opts.ServerInfo.ProxyMode,
		serverNet:     network,
		serverAddr:    opts.TsshdAddr,
		cipherBlock:   &cipherBlock,
		clientID:      opts.ServerInfo.ClientID,
		serverID:      opts.ServerInfo.ServerID,
		serverChecker: newTimeoutChecker(opts.HeartbeatTimeout),
	}

	if enableDebugLogging {
		proxy.serverChecker.onTimeout(func() {
			client.debug("blocked due to no server output for [%v]", opts.HeartbeatTimeout)
		})
		proxy.serverChecker.onReconnected(func() {
			client.debug("resumed after receiving server output")
		})
	}

	if opts.ProxyClient != nil {
		opts.ProxyClient.activeChecker.onReconnected(func() {
			if conn := proxy.backendConn.Load(); conn != nil {
				flushSize, flushCount := proxy.pktCache.sendCache(conn.Write)
				if enableDebugLogging {
					client.debug("send packet cache count [%d] cache size [%d]", flushCount, flushSize)
				}
			}
		})
	}

	go proxy.serveProxy()

	return proxyAddr, proxy, nil
}
