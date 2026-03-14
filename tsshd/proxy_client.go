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
)

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
	readMutex     sync.Mutex
	backendConn   atomic.Pointer[serverConnHolder]
	backendMutex  sync.Mutex
	backendCond   *sync.Cond
	proxyMode     string
	serverNet     string
	serverAddr    string
	remoteAddr    net.Addr
	cipherBlock   *cipher.Block
	clientID      uint64
	serverID      uint64
	renewMutex    sync.Mutex
	serialNumber  uint64
	pktCache      packetCache
	serverChecker *timeoutChecker
	closed        atomic.Bool
}

func (p *clientProxy) renewTransportPath(proxyClient *SshUdpClient, connectTimeout time.Duration) error {
	p.renewMutex.Lock()
	defer p.renewMutex.Unlock()
	p.serialNumber++

	if conn := p.backendConn.Swap(nil); conn != nil {
		_ = conn.Close()
	}

	var err error
	var conn *serverConnHolder
	if p.proxyMode == kProxyModeTCP {
		conn, err = p.renewTcpPath(proxyClient, connectTimeout)
	} else {
		conn, err = p.renewUdpPath(proxyClient, connectTimeout)
	}
	if err != nil {
		return err
	}

	p.backendMutex.Lock()
	p.backendConn.Store(conn)
	p.backendCond.Broadcast()
	p.backendMutex.Unlock()

	p.serverChecker.updateNow()

	flushSize, flushCount := p.pktCache.sendCache(conn.Write)
	if p.client.enableDebugging && (flushSize > 0 || flushCount > 0) {
		p.client.debug("send packet cache count [%d] size [%d]", flushCount, flushSize)
	}

	return nil
}

func (p *clientProxy) renewTcpPath(proxyClient *SshUdpClient, connectTimeout time.Duration) (conn *serverConnHolder, err error) {
	var setReadDeadline func(t time.Time) error
	if proxyClient != nil {
		tcpConn, err := proxyClient.DialTimeout(p.serverNet, p.serverAddr, connectTimeout)
		if err != nil {
			return nil, fmt.Errorf("proxy dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		setReadDeadline = tcpConn.SetReadDeadline
		conn = &serverConnHolder{&tcpServerConn{tcpConn}}
	} else {
		serverAddr, err := doWithTimeout(func() (*net.TCPAddr, error) {
			return net.ResolveTCPAddr(p.serverNet, p.serverAddr)
		}, connectTimeout)
		if err != nil {
			return nil, fmt.Errorf("resolve tcp addr [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		tcpConn, err := doWithTimeout(func() (*net.TCPConn, error) {
			return net.DialTCP(p.serverNet, nil, serverAddr)
		}, connectTimeout)
		if err != nil {
			return nil, fmt.Errorf("dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		setDSCP(tcpConn, kProxyDSCP)
		_ = tcpConn.SetReadBuffer(kProxyBufferSize)
		_ = tcpConn.SetWriteBuffer(kProxyBufferSize)
		setReadDeadline = tcpConn.SetReadDeadline
		conn = &serverConnHolder{&tcpServerConn{tcpConn}}
	}

	if err := p.sendAuthPacket(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err := setReadDeadline(time.Now().Add(connectTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set read deadline failed: %v", err)
	}

	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("recv auth packet failed: %v", err)
	}

	if !p.isAuthSuccessful(buffer[:n]) {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy auth failed")
	}
	p.client.debug("serial number [%d] auth success", p.serialNumber)

	_ = setReadDeadline(time.Time{})

	return conn, nil
}

func (p *clientProxy) renewUdpPath(proxyClient *SshUdpClient, connectTimeout time.Duration) (conn *serverConnHolder, err error) {
	if proxyClient != nil {
		udpConn, err := proxyClient.DialUDP(p.serverNet, p.serverAddr, connectTimeout)
		if err != nil {
			return nil, fmt.Errorf("proxy dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		conn = &serverConnHolder{udpConn}
	} else {
		serverAddr, err := doWithTimeout(func() (*net.UDPAddr, error) {
			return net.ResolveUDPAddr(p.serverNet, p.serverAddr)
		}, connectTimeout)
		if err != nil {
			return nil, fmt.Errorf("resolve udp addr [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
		}
		udpConn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			return nil, fmt.Errorf("dial [%s] [%s] failed: %v", p.serverNet, p.serverAddr, err)
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
				done <- nil
				return
			}
		}
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	if err := p.sendAuthPacket(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send auth packet failed: %v", err)
	}

	for {
		select {
		case err := <-done:
			return conn, err
		case <-ticker.C:
			if err := p.sendAuthPacket(conn); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("send auth packet failed: %v", err)
			}
		case <-ctx.Done():
			_ = conn.Close()
			return nil, fmt.Errorf("renew path to [%s] [%s] timeout [%v]", p.serverNet, p.serverAddr, connectTimeout)
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

func (p *clientProxy) ReadFrom(buf []byte) (int, net.Addr, error) {
	p.readMutex.Lock()
	defer p.readMutex.Unlock()
	for {
		if p.closed.Load() {
			return 0, nil, io.EOF
		}

		if conn := p.backendConn.Load(); conn != nil {
			n, err := conn.Read(buf)
			if err != nil {
				if p.backendConn.CompareAndSwap(conn, nil) {
					_ = conn.Close()
				}
				continue
			}
			p.serverChecker.updateNow()
			return n, p.remoteAddr, nil
		}

		// wait for reconnect
		p.backendMutex.Lock()
		for p.backendConn.Load() == nil && !p.closed.Load() {
			p.backendCond.Wait()
		}
		p.backendMutex.Unlock()
	}
}

func (p *clientProxy) WriteTo(buf []byte, _ net.Addr) (int, error) {
	for {
		if p.closed.Load() {
			return 0, io.EOF
		}

		if p.serverChecker.isTimeout() {
			p.pktCache.addPacket(buf)
			return len(buf), nil
		}

		if conn := p.backendConn.Load(); conn != nil {
			if err := conn.Write(buf); err != nil {
				if p.backendConn.CompareAndSwap(conn, nil) {
					_ = conn.Close()
				}
			}
			// Do not return an error here, otherwise QUIC/KCP may drop all subsequent packets.
			return len(buf), nil
		}

		// wait for reconnect
		p.backendMutex.Lock()
		for p.backendConn.Load() == nil && !p.closed.Load() {
			p.backendCond.Wait()
		}
		p.backendMutex.Unlock()
	}
}

func (p *clientProxy) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}

	p.backendMutex.Lock()
	p.backendCond.Broadcast()
	p.backendMutex.Unlock()

	p.client.debug("client proxy call Close")

	if conn := p.backendConn.Swap(nil); conn != nil {
		_ = conn.Close()
	}

	p.serverChecker.Close()

	return nil
}

func (p *clientProxy) LocalAddr() net.Addr {
	if !p.closed.Load() {
		p.client.debug("client proxy call LocalAddr")
	}
	return &net.UDPAddr{}
}

func (p *clientProxy) SetDeadline(t time.Time) error {
	if !p.closed.Load() {
		p.client.debug("client proxy call SetDeadline with time=%v", t)
	}
	return nil
}

func (p *clientProxy) SetReadDeadline(t time.Time) error {
	if !p.closed.Load() {
		p.client.debug("client proxy call SetReadDeadline with time=%v", t)
	}
	return nil
}

func (p *clientProxy) SetWriteDeadline(t time.Time) error {
	if !p.closed.Load() {
		p.client.debug("client proxy call SetWriteDeadline with time=%v", t)
	}
	return nil
}

func (p *clientProxy) SetReadBuffer(bytes int) error {
	if !p.closed.Load() {
		p.client.debug("client proxy call SetReadBuffer with bytes=%v", bytes)
	}
	return nil
}

func (p *clientProxy) SetWriteBuffer(bytes int) error {
	if !p.closed.Load() {
		p.client.debug("client proxy call SetWriteBuffer with bytes=%v", bytes)
	}
	return nil
}

type proxyServerAddr struct {
	addr string
}

func (a *proxyServerAddr) Network() string {
	return "udp"
}

func (a *proxyServerAddr) String() string {
	return a.addr
}

func startClientProxy(client *SshUdpClient, opts *UdpClientOptions) (*clientProxy, error) {
	proxyKey, err := hex.DecodeString(opts.ServerInfo.ProxyKey)
	if err != nil {
		return nil, fmt.Errorf("decode proxy key [%s] failed: %v", opts.ServerInfo.ProxyKey, err)
	}
	cipherBlock, err := aes.NewCipher(proxyKey)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher for key [%s] failed: %v", opts.ServerInfo.ProxyKey, err)
	}

	network := "udp"
	if opts.ServerInfo.ProxyMode == kProxyModeTCP {
		network = "tcp"
	}
	if opts.IPv4 && !opts.IPv6 {
		network += "4"
	} else if opts.IPv6 && !opts.IPv4 {
		network += "6"
	}

	clientID := opts.ServerInfo.ClientID
	for clientID == 0 {
		buf := make([]byte, 8)
		if _, err := crypto_rand.Read(buf); err != nil {
			return nil, fmt.Errorf("rand client id failed: %v", err)
		}
		clientID = binary.BigEndian.Uint64(buf)
	}

	proxy := &clientProxy{
		client:        client,
		proxyMode:     opts.ServerInfo.ProxyMode,
		serverNet:     network,
		serverAddr:    opts.TsshdAddr,
		remoteAddr:    &proxyServerAddr{opts.TsshdAddr},
		cipherBlock:   &cipherBlock,
		clientID:      clientID,
		serverID:      opts.ServerInfo.ServerID,
		serverChecker: newTimeoutChecker(opts.HeartbeatTimeout),
	}
	proxy.backendCond = sync.NewCond(&proxy.backendMutex)

	if client.enableDebugging {
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
				if client.enableDebugging && (flushSize > 0 || flushCount > 0) {
					client.debug("send packet cache count [%d] size [%d]", flushCount, flushSize)
				}
			}
		})
	}

	return proxy, nil
}
