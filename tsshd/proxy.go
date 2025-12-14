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
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const kProxyBufferSize = 1024 * 1024

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

func sendUdpPacket(conn net.Conn, data []byte) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
}

func recvUdpPacket(conn net.Conn, data []byte) (int, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(buf))
	if n <= 0 || n > len(data) {
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

func (p *packetCache) flushCache(writeFn func([]byte) error) (int, int, int, int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var totalSize, totalCount, flushSize, flushCount int

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
		p.buffer[index] = nil
	}

	p.head, p.size = p.tail, 0

	if enableDebugLogging {
		totalSize, totalCount = p.totalSize, p.totalCount
		p.totalSize, p.totalCount = 0, 0
	}

	return totalSize, totalCount, flushSize, flushCount
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
		if u.frontendConn != c.frontendConn {
			return false
		}
		if u.clientAddr.Port != c.clientAddr.Port {
			return false
		}
		return u.clientAddr.IP.Equal(c.clientAddr.IP)
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
	args         *tsshdArgs
	frontendList []io.Closer
	backendConn  *net.UDPConn
	clientConn   atomic.Pointer[clientConnHolder]
	authedConn   clientConnection
	cipherBlock  *cipher.Block
	clientID     uint64
	serverID     uint64
	serialNumber atomic.Uint64
	bufChan      chan *udpBuffer
	pktCache     packetCache
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

	if inputChecker != nil {
		inputChecker.updateTime(time.Now().UnixMilli())
	}

	if oldClientConn != nil {
		oldClientConn.Close()
		enablePendingInputDiscard() // discard pending user input from previous connections
	}

	totalSize, totalCount, flushSize, flushCount := p.pktCache.flushCache(newClientConn.Write)
	if enableDebugLogging {
		debug("total packet cache count [%d] cache size [%d]", totalCount, totalSize)
		debug("flush packet cache count [%d] cache size [%d]", flushCount, flushSize)
	}
}

func (p *serverProxy) udpFrontendToBackend() {
	for buf := range p.bufChan {
		if c := p.clientConn.Load(); c != nil && c.Equal(buf.conn) {
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
			if serialNumber > p.serialNumber.Load() {
				p.serialNumber.Store(serialNumber)
			}
			if serialNumber == p.serialNumber.Load() {
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
		if err != nil || n <= 0 {
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
				clientAddr:   addr,
			},
			data: buffers[current][:n],
		}
		current = 1 - current
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
		go p.tcpFrontendToBackend(conn)
	}
}

func (p *serverProxy) backendToFrontend() {
	buffer := make([]byte, 0xffff)
	for {
		n, _, err := p.backendConn.ReadFromUDP(buffer)
		if err != nil || n <= 0 {
			warning("backend read udp failed: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if inputChecker != nil && inputChecker.isTimeout() {
			p.pktCache.addPacket(buffer[:n])
			continue
		}
		if conn := p.clientConn.Load(); conn != nil {
			if p.pktCache.size > 0 {
				totalSize, totalCount, flushSize, flushCount := p.pktCache.flushCache(conn.Write)
				if enableDebugLogging {
					debug("total packet cache count [%d] cache size [%d]", totalCount, totalSize)
					debug("flush packet cache count [%d] cache size [%d]", flushCount, flushSize)
				}
			}
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

func startServerProxy(args *tsshdArgs, info *ServerInfo, frontendList []io.Closer) ([]io.Closer, error) {
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

	proxy := &serverProxy{
		args:         args,
		frontendList: frontendList,
		backendConn:  backendConn,
		cipherBlock:  &cipherBlock,
		clientID:     info.ClientID,
		serverID:     info.ServerID,
	}
	go proxy.serveProxy()

	return []io.Closer{serverConn}, nil
}

type serverConnection interface {
	Close()
	Read([]byte) (int, error)
	Write([]byte) error
}

type tcpServerConn struct {
	conn net.Conn
}

func (t *tcpServerConn) Close() {
	_ = t.conn.Close()
}

func (t *tcpServerConn) Read(buf []byte) (int, error) {
	return recvUdpPacket(t.conn, buf)
}

func (t *tcpServerConn) Write(buf []byte) error {
	return sendUdpPacket(t.conn, buf)
}

type udpServerConn struct {
	conn *net.UDPConn
}

func (u *udpServerConn) Close() {
	_ = u.conn.Close()
}

func (u *udpServerConn) Read(buf []byte) (int, error) {
	n, _, err := u.conn.ReadFromUDP(buf)
	return n, err
}

func (u *udpServerConn) Write(buf []byte) error {
	_, err := u.conn.Write(buf)
	return err
}

type serverConnHolder struct {
	serverConnection
}

type clientProxy struct {
	client       *SshUdpClient
	frontendConn *net.UDPConn
	backendConn  atomic.Pointer[serverConnHolder]
	proxyMode    string
	serverNet    string
	serverAddr   string
	clientAddr   atomic.Pointer[net.UDPAddr]
	cipherBlock  *cipher.Block
	clientID     uint64
	serverID     uint64
	renewMutex   sync.Mutex
	serialNumber uint64
	pktCache     packetCache
}

func (p *clientProxy) isClientAddr(addr *net.UDPAddr) bool {
	clientAddr := p.clientAddr.Load()
	if clientAddr == nil {
		return false
	}
	if clientAddr.Port != addr.Port {
		return false
	}
	return clientAddr.IP.Equal(addr.IP)
}

func (p *clientProxy) frontendToBackend() {
	buffer := make([]byte, 0xffff)
	for {
		n, addr, err := p.frontendConn.ReadFromUDP(buffer)
		if err != nil || n <= 0 {
			p.client.warning("frontend read udp failed: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if p.clientAddr.Load() == nil {
			p.clientAddr.Store(addr)
		}
		if !p.isClientAddr(addr) {
			continue
		}
		if conn := p.backendConn.Load(); conn != nil {
			_ = conn.Write(buffer[:n])
		} else {
			p.pktCache.addPacket(buffer[:n])
		}
	}
}

func (p *clientProxy) backendToFrontend() {
	buffer := make([]byte, 0xffff)
	for {
		if conn := p.backendConn.Load(); conn != nil {
			n, err := conn.Read(buffer)
			if err != nil || n <= 0 { // client ignore backend error
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if addr := p.clientAddr.Load(); addr != nil {
				if _, err := p.frontendConn.WriteToUDP(buffer[:n], addr); err != nil {
					p.client.warning("write to frontend failed: %v", err)
				}
			}
		} else {
			time.Sleep(10 * time.Millisecond) // wait for reconnect
		}
	}
}

func (p *clientProxy) renewTransportPath(connectTimeout time.Duration) error {
	p.renewMutex.Lock()
	defer p.renewMutex.Unlock()
	p.serialNumber++

	if conn := p.backendConn.Load(); conn != nil {
		conn.Close()
		p.backendConn.Store(nil)
	}

	var err error
	if p.proxyMode == kProxyModeTCP {
		err = p.renewTcpPath(connectTimeout)
	} else {
		err = p.renewUdpPath(connectTimeout)
	}
	if err != nil {
		return err
	}

	totalSize, totalCount, flushSize, flushCount := p.pktCache.flushCache(p.backendConn.Load().Write)
	if enableDebugLogging {
		p.client.debug("total packet cache count [%d] cache size [%d]", totalCount, totalSize)
		p.client.debug("flush packet cache count [%d] cache size [%d]", flushCount, flushSize)
	}
	return nil
}

func (p *clientProxy) renewTcpPath(connectTimeout time.Duration) error {
	conn, err := net.DialTimeout(p.serverNet, p.serverAddr, connectTimeout)
	if err != nil {
		return fmt.Errorf("dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
	}

	svrConn := serverConnHolder{&tcpServerConn{conn}}

	if err := p.sendAuthPacket(svrConn); err != nil {
		_ = conn.Close()
		return err
	}

	if err := conn.SetReadDeadline(time.Now().Add(connectTimeout)); err != nil {
		return fmt.Errorf("set read deadline failed: %v", err)
	}

	buffer := make([]byte, 256)
	n, err := recvUdpPacket(conn, buffer)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("recv auth packet failed: %v", err)
	}

	if !p.isAuthSuccessful(buffer[:n]) {
		_ = conn.Close()
		return fmt.Errorf("proxy auth failed")
	}
	p.client.debug("serial number [%d] auth success", p.serialNumber)

	_ = conn.SetReadDeadline(time.Time{})
	p.backendConn.Store(&svrConn)
	return nil
}

func (p *clientProxy) renewUdpPath(connectTimeout time.Duration) error {
	serverAddr, err := net.ResolveUDPAddr(p.serverNet, p.serverAddr)
	if err != nil {
		return fmt.Errorf("resolve addr [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return fmt.Errorf("dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
	}
	_ = conn.SetReadBuffer(kProxyBufferSize)
	_ = conn.SetWriteBuffer(kProxyBufferSize)
	svrConn := serverConnHolder{&udpServerConn{conn}}

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	go func() {
		_ = p.sendAuthPacket(svrConn)
		for {
			select {
			case <-ctx.Done():
				if err := ctx.Err(); err != nil && errors.Is(err, context.DeadlineExceeded) {
					_ = conn.Close()
				}
				return
			case <-time.After(100 * time.Millisecond):
				_ = p.sendAuthPacket(svrConn)
			}
		}
	}()

	buffer := make([]byte, 256)
	for {
		if err := ctx.Err(); err != nil {
			_ = conn.Close()
			return fmt.Errorf("renew path to [%s] [%s] failed: %v", p.serverNet, serverAddr.String(), err)
		}
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil || n <= 0 {
			_ = conn.Close()
			return fmt.Errorf("read auth packet failed: %v", err)
		}
		if p.isAuthSuccessful(buffer[:n]) {
			p.client.debug("serial number [%d] auth success", p.serialNumber)
			p.backendConn.Store(&svrConn)
			return nil
		}
	}
}

func (p *clientProxy) sendAuthPacket(conn serverConnection) error {
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
	go p.backendToFrontend()
}

func startClientProxy(client *SshUdpClient, serverNet, serverAddr string, info *ServerInfo) (string, *clientProxy, error) {
	proxyKey, err := hex.DecodeString(info.ProxyKey)
	if err != nil {
		return "", nil, fmt.Errorf("decode proxy key [%s] failed: %v", info.ProxyKey, err)
	}
	cipherBlock, err := aes.NewCipher(proxyKey)
	if err != nil {
		return "", nil, fmt.Errorf("aes new cipher failed: %v", err)
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

	proxy := &clientProxy{
		client:       client,
		frontendConn: frontendConn,
		proxyMode:    info.ProxyMode,
		serverNet:    serverNet,
		serverAddr:   serverAddr,
		cipherBlock:  &cipherBlock,
		clientID:     info.ClientID,
		serverID:     info.ServerID,
	}
	go proxy.serveProxy()

	return proxyAddr, proxy, nil
}
