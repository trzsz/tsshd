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

type udpConn struct {
	frontendConn *net.UDPConn
	clientAddr   *net.UDPAddr
}

type udpBuffer struct {
	conn *udpConn
	data []byte
}

type serverProxy struct {
	connectTimeout time.Duration
	frontendList   []*net.UDPConn
	backendConn    *net.UDPConn
	clientConn     atomic.Pointer[udpConn]
	authedConn     *udpConn
	cipherBlock    *cipher.Block
	clientID       uint64
	serverID       uint64
	serialNumber   uint64
	bufChan        chan *udpBuffer
}

func (p *serverProxy) isClientConn(conn *udpConn) bool {
	clientConn := p.clientConn.Load()
	if clientConn == nil {
		return false
	}
	if clientConn.frontendConn != conn.frontendConn {
		return false
	}
	if clientConn.clientAddr.Port != conn.clientAddr.Port {
		return false
	}
	return clientConn.clientAddr.IP.Equal(conn.clientAddr.IP)
}

func (p *serverProxy) isAuthedConn(conn *udpConn) bool {
	if p.authedConn == nil {
		return false
	}
	if p.authedConn.frontendConn != conn.frontendConn {
		return false
	}
	if p.authedConn.clientAddr.Port != conn.clientAddr.Port {
		return false
	}
	return p.authedConn.clientAddr.IP.Equal(conn.clientAddr.IP)
}

func (p *serverProxy) sendAuthPacket(conn *udpConn) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], p.serverID)
	binary.BigEndian.PutUint64(data[8:16], p.serialNumber)
	buf := aesEncrypt(p.cipherBlock, data)
	if buf == nil {
		return
	}
	_, _ = conn.frontendConn.WriteToUDP(buf, conn.clientAddr)
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

func (p *serverProxy) frontendToBackend() {
	for buf := range p.bufChan {
		if p.isClientConn(buf.conn) {
			_, _ = p.backendConn.Write(buf.data)
			continue
		}

		if p.isAuthedConn(buf.conn) {
			isAuthPacket, serialNumber := p.verifyAuthPacket(buf.data)
			if !isAuthPacket { // auth success
				p.clientConn.Store(p.authedConn)
				p.authedConn = nil
				_, _ = p.backendConn.Write(buf.data)
				continue
			}
			if serialNumber > p.serialNumber {
				p.serialNumber = serialNumber
			}
			if serialNumber == p.serialNumber {
				p.sendAuthPacket(buf.conn)
			}
			continue
		}

		isAuthPacket, serialNumber := p.verifyAuthPacket(buf.data)
		if isAuthPacket && serialNumber > p.serialNumber {
			p.authedConn = buf.conn
			p.serialNumber = serialNumber
			p.sendAuthPacket(buf.conn)
			continue
		}
	}
}

func (p *serverProxy) backendToFrontend() {
	buffer := make([]byte, 0xffff)
	for {
		n, _, err := p.backendConn.ReadFromUDP(buffer)
		if err != nil || n <= 0 {
			continue
		}
		if conn := p.clientConn.Load(); conn != nil {
			_, _ = conn.frontendConn.WriteToUDP(buffer[:n], conn.clientAddr)
		}
	}
}

func (p *serverProxy) serveFrontendConn(conn *net.UDPConn) {
	defer func() { _ = conn.Close() }()
	beginTime := time.Now()
	neverReceived := true

	current := 0
	buffers := [2][]byte{make([]byte, 0xffff), make([]byte, 0xffff)}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(p.connectTimeout))
		n, addr, err := conn.ReadFromUDP(buffers[current])
		if err != nil || n <= 0 {
			if neverReceived && time.Since(beginTime) > p.connectTimeout {
				return
			}
			continue
		}
		neverReceived = false
		p.bufChan <- &udpBuffer{
			conn: &udpConn{
				frontendConn: conn,
				clientAddr:   addr,
			},
			data: buffers[current][:n],
		}
		current = 1 - current
	}
}

func (p *serverProxy) serveProxy() {
	for _, conn := range p.frontendList {
		_ = conn.SetReadBuffer(kProxyBufferSize)
		_ = conn.SetWriteBuffer(kProxyBufferSize)
		go p.serveFrontendConn(conn)
	}
	_ = p.backendConn.SetReadBuffer(kProxyBufferSize)
	_ = p.backendConn.SetWriteBuffer(kProxyBufferSize)
	go p.frontendToBackend()
	go p.backendToFrontend()
}

func startServerProxy(frontendList []*net.UDPConn, info *ServerInfo, connectTimeout time.Duration) ([]*net.UDPConn, error) {
	localAddr := "127.0.0.1:0"
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr [%s] failed: %v", localAddr, err)
	}
	serverConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp on [%s] failed: %v", localAddr, err)
	}
	svrAddr := fmt.Sprintf("127.0.0.1:%d", serverConn.LocalAddr().(*net.UDPAddr).Port)
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

	info.ProxyKey = fmt.Sprintf("%x", proxyKey)
	info.ClientID = binary.BigEndian.Uint64(clientID)
	info.ServerID = binary.BigEndian.Uint64(serverID)

	proxy := &serverProxy{
		connectTimeout: connectTimeout,
		frontendList:   frontendList,
		backendConn:    backendConn,
		cipherBlock:    &cipherBlock,
		clientID:       info.ClientID,
		serverID:       info.ServerID,
		bufChan:        make(chan *udpBuffer), // unbuffered channel to avaid copying buffer
	}
	go proxy.serveProxy()

	return []*net.UDPConn{serverConn}, nil
}

type clientProxy struct {
	frontendConn *net.UDPConn
	backendConn  atomic.Pointer[net.UDPConn]
	serverAddr   *net.UDPAddr
	clientAddr   atomic.Pointer[net.UDPAddr]
	cipherBlock  *cipher.Block
	clientID     uint64
	serverID     uint64
	renewMutex   sync.Mutex
	serialNumber uint64
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
			continue
		}
		if p.clientAddr.Load() == nil {
			p.clientAddr.Store(addr)
		}
		if !p.isClientAddr(addr) {
			continue
		}
		if conn := p.backendConn.Load(); conn != nil {
			_, _ = conn.Write(buffer[:n])
		}
	}
}

func (p *clientProxy) backendToFrontend() {
	buffer := make([]byte, 0xffff)
	for {
		if conn := p.backendConn.Load(); conn != nil {
			n, _, err := conn.ReadFromUDP(buffer)
			if err != nil || n <= 0 {
				continue
			}
			if addr := p.clientAddr.Load(); addr != nil {
				_, _ = p.frontendConn.WriteToUDP(buffer[:n], addr)
			}
		}
	}
}

func (p *clientProxy) renewUdpPath(connectTimeout time.Duration) error {
	p.renewMutex.Lock()
	defer p.renewMutex.Unlock()
	p.serialNumber++

	newConn, err := net.DialUDP("udp", nil, p.serverAddr)
	if err != nil {
		return fmt.Errorf("dial udp [%s] failed: %v", p.serverAddr.String(), err)
	}
	_ = newConn.SetReadBuffer(kProxyBufferSize)
	_ = newConn.SetWriteBuffer(kProxyBufferSize)

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	go func() {
		p.sendAuthPacket(newConn)
		for {
			select {
			case <-ctx.Done():
				if err := ctx.Err(); err != nil && errors.Is(err, context.DeadlineExceeded) {
					_ = newConn.Close()
				}
				return
			case <-time.After(100 * time.Millisecond):
				p.sendAuthPacket(newConn)
			}
		}
	}()

	buffer := make([]byte, 256)
	for {
		if err := ctx.Err(); err != nil {
			_ = newConn.Close()
			return fmt.Errorf("renew udp path to [%s] failed: %v", p.serverAddr.String(), err)
		}
		n, _, err := newConn.ReadFromUDP(buffer)
		if err != nil || n <= 0 {
			continue
		}
		if p.isAuthSuccessful(buffer[:n]) {
			if conn := p.backendConn.Load(); conn != nil {
				_ = conn.Close()
			}
			p.backendConn.Store(newConn)
			return nil
		}
	}
}

func (p *clientProxy) sendAuthPacket(conn *net.UDPConn) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], p.clientID)
	binary.BigEndian.PutUint64(data[8:16], p.serialNumber)
	buf := aesEncrypt(p.cipherBlock, data)
	if buf == nil {
		return
	}
	_, _ = conn.Write(buf)
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
	for p.backendConn.Load() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	go p.frontendToBackend()
	go p.backendToFrontend()
}

func startClientProxy(svrAddr string, info *ServerInfo) (string, *clientProxy, error) {
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
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", frontendConn.LocalAddr().(*net.UDPAddr).Port)
	serverAddr, err := net.ResolveUDPAddr("udp", svrAddr)
	if err != nil {
		return "", nil, fmt.Errorf("resolve udp addr [%s] failed: %v", svrAddr, err)
	}

	proxy := &clientProxy{
		frontendConn: frontendConn,
		serverAddr:   serverAddr,
		cipherBlock:  &cipherBlock,
		clientID:     info.ClientID,
		serverID:     info.ServerID,
	}
	go proxy.serveProxy()

	return proxyAddr, proxy, nil
}
