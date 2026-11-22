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
	"bufio"
	"bytes"
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
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/x/ansi"
)

type tcpServerConn struct {
	conn io.ReadWriteCloser
}

func (t *tcpServerConn) Close() error {
	return t.conn.Close()
}

func (t *tcpServerConn) Write(buf []byte) error {
	return sendUdpPacket(t.conn, buf)
}

func (t *tcpServerConn) WriteWithContext(ctx context.Context, buf []byte) error {
	if ctx.Done() == nil {
		return sendUdpPacket(t.conn, buf)
	}

	buffer := append([]byte(nil), buf...)
	_, err := doWithContext(ctx, func() (int, error) { return 0, sendUdpPacket(t.conn, buffer) })
	return err
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

type proxyCmdConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	closed atomic.Bool
}

func (c *proxyCmdConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	_ = c.stdin.Close()
	_ = c.stdout.Close()

	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}

	return nil
}

func (c *proxyCmdConn) Write(buf []byte) (int, error) {
	return c.stdin.Write(buf)
}

func (c *proxyCmdConn) Read(buf []byte) (int, error) {
	return c.stdout.Read(buf)
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

func (u *udpServerConn) WriteWithContext(ctx context.Context, buf []byte) error {
	if ctx.Done() == nil {
		_, err := u.conn.Write(buf)
		return err
	}

	buffer := append([]byte(nil), buf...)
	_, err := doWithContext(ctx, func() (int, error) { return u.conn.Write(buffer) })
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
	renewMutex    chan struct{}
	serialNumber  atomic.Uint64
	serverChecker *timeoutChecker
	closed        atomic.Bool
	udpTraffic    *trafficStats
	proxyCmds     []string
	cumTraffic    cumulativeTraffic
	// clientNonce is fresh for each client, so that the server never mistakes
	// this client for an earlier one started with the same server info.
	clientNonce []byte
	// kcpAliveCheck means that KCP refreshes serverChecker itself, once a
	// packet from the server has been authenticated and is not a replay.
	kcpAliveCheck bool
}

// cumulativeTraffic counts UDP wire datagrams for the lifetime of the
// connection (always on, unlike the windowed debug-only trafficStats).
type cumulativeTraffic struct {
	sentPackets atomic.Uint64
	sentBytes   atomic.Uint64
	recvPackets atomic.Uint64
	recvBytes   atomic.Uint64
}

func (p *clientProxy) clearBackendConn(oldConn *serverConnHolder) {
	if oldConn != nil {
		if !p.backendConn.CompareAndSwap(oldConn, nil) {
			oldConn = nil
		}
	} else {
		oldConn = p.backendConn.Swap(nil)
	}

	if oldConn != nil {
		_ = oldConn.Close()
	}
}

func (p *clientProxy) renewTransportPath(ctx context.Context, proxyClient *SshUdpClient) error {
	select {
	case p.renewMutex <- struct{}{}:
		defer func() {
			<-p.renewMutex
		}()
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for renew lock failed: %v", err)
		}
	case <-ctx.Done():
		return fmt.Errorf("wait for renew lock failed: %v", ctx.Err())
	}

	if p.closed.Load() {
		return errors.New("client proxy closed")
	}

	p.serialNumber.Add(1)
	p.clearBackendConn(nil)

	var err error
	var conn *serverConnHolder

	if proxyClient == nil && len(p.proxyCmds) > 0 && p.proxyMode != kProxyModeTCP {
		return errors.New("proxy command only supports tcp proxy mode")
	}
	p.client.debug("tsshd server: network=%s, address=%s", p.serverNet, p.serverAddr)
	if p.proxyMode == kProxyModeTCP {
		conn, err = p.renewTcpPath(ctx, proxyClient)
	} else {
		conn, err = p.renewUdpPath(ctx, proxyClient)
	}
	if err != nil {
		return err
	}

	p.backendMutex.Lock()
	if p.closed.Load() {
		p.backendMutex.Unlock()
		_ = conn.Close()
		return errors.New("client proxy closed")
	}
	p.backendConn.Store(conn)
	p.backendCond.Broadcast()
	p.backendMutex.Unlock()

	subCtx, cancel := context.WithTimeout(ctx, p.serverChecker.heartbeatTimeout)
	defer cancel()

	// In UDP mode, send dummy (non-authenticated) packets to notify the server that the transport path is active.
	// This helps the server acknowledge the connection and allows KCP/QUIC to resume.
	if p.proxyMode != kProxyModeTCP {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					buf := make([]byte, kSafeToDropPacketLen)
					_, _ = crypto_rand.Read(buf)
					if err := conn.WriteWithContext(subCtx, buf); err != nil {
						if subCtx.Err() != nil {
							return
						}
						p.client.warning("send dummy packet failed: %v", err)
					}
				case <-subCtx.Done():
					return
				}
			}
		}()
	}

	if p.client.protoClient != nil {
		p.client.protoClient.reset()
	}

	// Block until reconnection is confirmed by the arrival of valid QUIC/KCP packets,
	// or abort if no server response is received before the heartbeat deadline.
	if err := p.serverChecker.waitReconnect(subCtx); err != nil {
		p.clearBackendConn(conn)
		return fmt.Errorf("wait for server response failed: %v", err)
	}

	return nil
}

func (p *clientProxy) dialStream(ctx context.Context, proxyClient *SshUdpClient, network string) (*serverConnHolder, error) {
	if proxyClient != nil {
		// dialContext waits for the jump host until the deadline, even if ctx is cancelled.
		tcpConn, err := doWithContext(ctx, func() (Stream, error) {
			return proxyClient.dialContext(network, p.serverAddr, ctx)
		})
		if err != nil {
			return nil, fmt.Errorf("proxy dial [%s] [%s] failed: %v", network, p.serverAddr, err)
		}
		return &serverConnHolder{&tcpServerConn{tcpConn}}, nil
	}

	if len(p.proxyCmds) > 0 {
		cmd := exec.Command(p.proxyCmds[0], p.proxyCmds[1:]...)

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("proxy command [%s] stdin pipe failed: %v", cmd.String(), err)
		}

		stdoutReader, stdoutWriter, err := os.Pipe()
		if err != nil {
			_ = stdin.Close()
			return nil, fmt.Errorf("proxy command [%s] stdout pipe failed: %v", cmd.String(), err)
		}
		// Close the parent's write end to avoid blocking EOF, even if Start fails.
		defer func() { _ = stdoutWriter.Close() }()
		cmd.Stdout = stdoutWriter

		var stderrReader, stderrWriter *os.File
		if p.client.enableDebugging {
			stderrReader, stderrWriter, err = os.Pipe()
			if err != nil {
				_ = stdin.Close()
				_ = stdoutReader.Close()
				return nil, fmt.Errorf("proxy command [%s] stderr pipe failed: %v", cmd.String(), err)
			}
			// Close the parent's write end to avoid blocking EOF, even if Start fails.
			defer func() { _ = stderrWriter.Close() }()
			cmd.Stderr = stderrWriter
		} else {
			cmd.Stderr = io.Discard
		}

		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			_ = stdoutReader.Close()
			if stderrReader != nil {
				_ = stderrReader.Close()
			}
			return nil, fmt.Errorf("proxy command [%s] start failed: %v", cmd.String(), err)
		}

		if stderrReader != nil {
			go func() {
				defer func() { _ = stderrReader.Close() }()
				scanner := bufio.NewScanner(stderrReader)
				for scanner.Scan() {
					line := strings.TrimSpace(ansi.Strip(scanner.Text()))
					if line != "" {
						p.client.debug("proxy command stderr: %s", line)
					}
				}
			}()
		}

		conn := &proxyCmdConn{cmd: cmd, stdin: stdin, stdout: stdoutReader}

		go func() {
			if err := cmd.Wait(); err != nil && !conn.closed.Load() && p.client.enableDebugging {
				p.client.debug("proxy command [%s] exited: %v", cmd.String(), err)
			}
		}()

		return &serverConnHolder{&tcpServerConn{conn}}, nil
	}

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, network, p.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial [%s] [%s] failed: %v", network, p.serverAddr, err)
	}

	tcpConn, ok := rawConn.(*net.TCPConn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("dial [%s] [%s] returned unexpected connection type: %T", network, p.serverAddr, rawConn)
	}

	setDSCP(tcpConn, kProxyDSCP)
	_ = tcpConn.SetReadBuffer(kProxyBufferSize)
	_ = tcpConn.SetWriteBuffer(kProxyBufferSize)
	return &serverConnHolder{&tcpServerConn{tcpConn}}, nil
}

func (p *clientProxy) renewTcpPath(ctx context.Context, proxyClient *SshUdpClient) (*serverConnHolder, error) {
	networks := p.raceNetworks()
	if proxyClient == nil && len(p.proxyCmds) > 0 {
		// The proxy command picks the address family.
		networks = []string{"tcp"}
	}
	return p.racePath(ctx, networks, p.authTcpPath, func(ctx context.Context, network string) (*serverConnHolder, error) {
		return p.dialStream(ctx, proxyClient, network)
	})
}

// authTcpPath closes conn if it fails.
func (p *clientProxy) authTcpPath(ctx context.Context, conn *serverConnHolder) error {
	if err := p.sendAuthPacket(ctx, conn); err != nil {
		_ = conn.Close()
		return fmt.Errorf("send auth packet failed: %v", err)
	}

	buffer := make([]byte, 256)
	n, err := doWithContext(ctx, func() (int, error) { return conn.Read(buffer) })
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("recv auth packet failed: %v", err)
	}

	if !p.isAuthSuccessful(buffer[:n]) {
		_ = conn.Close()
		return errors.New("proxy auth failed")
	}
	return nil
}

func (p *clientProxy) renewUdpPath(ctx context.Context, proxyClient *SshUdpClient) (*serverConnHolder, error) {
	return p.raceUdpPath(ctx, func(ctx context.Context, network string) (*serverConnHolder, error) {
		return p.dialPacket(ctx, proxyClient, network)
	})
}

func (p *clientProxy) dialPacket(ctx context.Context, proxyClient *SshUdpClient, network string) (*serverConnHolder, error) {
	if proxyClient != nil {
		// dialUDP waits for the jump host until the deadline, even if ctx is cancelled.
		udpConn, err := doWithContext(ctx, func() (PacketConn, error) {
			return proxyClient.dialUDP(network, p.serverAddr, ctx, false)
		})
		if err != nil {
			return nil, fmt.Errorf("proxy dial [%s] [%s] failed: %v", network, p.serverAddr, err)
		}
		return &serverConnHolder{udpConn}, nil
	}

	serverAddr, err := doWithContext(ctx, func() (*net.UDPAddr, error) {
		return net.ResolveUDPAddr(network, p.serverAddr)
	})
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr [%s] [%s] failed: %v", network, p.serverAddr, err)
	}
	udpConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial [%s] [%s] failed: %v", network, p.serverAddr, err)
	}
	setDSCP(udpConn, kProxyDSCP)
	_ = udpConn.SetReadBuffer(kProxyBufferSize)
	_ = udpConn.SetWriteBuffer(kProxyBufferSize)
	return &serverConnHolder{&udpServerConn{udpConn}}, nil
}

// authUdpPath closes conn if it fails.
func (p *clientProxy) authUdpPath(ctx context.Context, conn *serverConnHolder) error {
	done := make(chan error, 1)
	go func() {
		// Windows fails the read if a datagram is larger than the buffer.
		buffer := make([]byte, 0xffff)
		for ctx.Err() == nil {
			n, err := conn.Read(buffer)
			if err != nil {
				done <- fmt.Errorf("read auth packet failed: %v", err)
				return
			}
			if p.isAuthSuccessful(buffer[:n]) {
				done <- nil
				return
			}
		}
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	if err := p.sendAuthPacket(ctx, conn); err != nil {
		_ = conn.Close()
		return fmt.Errorf("send auth packet failed: %v", err)
	}

	for {
		select {
		case err := <-done:
			if err != nil {
				_ = conn.Close()
				return err
			}
			return nil
		case <-ticker.C:
			if err := p.sendAuthPacket(ctx, conn); err != nil {
				_ = conn.Close()
				return fmt.Errorf("send auth packet failed: %v", err)
			}
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		}
	}
}

func (p *clientProxy) raceUdpPath(ctx context.Context, dial func(context.Context, string) (*serverConnHolder, error)) (*serverConnHolder, error) {
	return p.racePath(ctx, p.raceNetworks(), p.authUdpPath, dial)
}

// raceNetworks returns IPv4 and IPv6 unless a family is forced.
func (p *clientProxy) raceNetworks() []string {
	if p.serverNet == "udp" || p.serverNet == "tcp" {
		return []string{p.serverNet + "4", p.serverNet + "6"}
	}
	return []string{p.serverNet}
}

// racePath tries all networks at once and keeps the first path that authenticates.
// All attempts use the same serial number, so the server accepts only the first.
func (p *clientProxy) racePath(ctx context.Context, networks []string, auth func(context.Context, *serverConnHolder) error,
	dial func(context.Context, string) (*serverConnHolder, error)) (*serverConnHolder, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		network string
		conn    *serverConnHolder
		err     error
	}
	results := make(chan result, len(networks))
	for _, network := range networks {
		go func() {
			conn, err := dial(ctx, network)
			if err == nil {
				if err = auth(ctx, conn); err != nil {
					err = fmt.Errorf("renew path to [%s] [%s] failed: %v", network, p.serverAddr, err)
				}
			}
			results <- result{network, conn, err}
		}()
	}

	var conn *serverConnHolder
	var errs []error
	for range networks {
		res := <-results
		if res.err != nil {
			errs = append(errs, res.err)
		} else if conn == nil {
			conn = res.conn
			cancel()
			p.client.debug("serial number [%d] auth success over [%s]", p.serialNumber.Load(), res.network)
		} else {
			_ = res.conn.Close()
		}
	}
	if conn == nil {
		return nil, errors.Join(errs...)
	}
	return conn, nil
}

func (p *clientProxy) sendAuthPacket(ctx context.Context, conn PacketConn) error {
	data := make([]byte, 16, 20+kClientNonceSize)
	binary.BigEndian.PutUint64(data[0:8], p.clientID)
	binary.BigEndian.PutUint64(data[8:16], p.serialNumber.Load())
	if p.client.protoVersion >= 3 {
		// Announce the protocol version and the client nonce, so that the
		// server knows how the following KCP packets are protected before the
		// first one arrives.
		data = binary.BigEndian.AppendUint32(data, uint32(p.client.protoVersion))
		data = append(data, p.clientNonce...)
	}
	buf := aesEncrypt(p.cipherBlock, data)
	if buf == nil {
		return errors.New("aes encrypt failed")
	}
	return conn.WriteWithContext(ctx, buf)
}

func (p *clientProxy) isAuthSuccessful(buf []byte) bool {
	data := aesDecrypt(p.cipherBlock, buf)
	if p.client.protoVersion >= 3 {
		// The server echoes the client nonce, so that an acknowledgment
		// sent to an earlier client with the same server info is not accepted.
		if len(data) != 16+kClientNonceSize || !bytes.Equal(data[16:], p.clientNonce) {
			return false
		}
	} else if len(data) != 16 {
		return false
	}
	serverID := binary.BigEndian.Uint64(data[0:8])
	if serverID != p.serverID {
		return false
	}
	serialNumber := binary.BigEndian.Uint64(data[8:16])
	oldSerialNumber := p.serialNumber.Load()
	if serialNumber > oldSerialNumber {
		// Another attempt may have raised it already.
		p.serialNumber.CompareAndSwap(oldSerialNumber, serialNumber)
		return false
	}
	return serialNumber == oldSerialNumber
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
				p.clearBackendConn(conn)
				continue
			}

			if !p.kcpAliveCheck {
				p.serverChecker.updateNow()
			}

			p.cumTraffic.recvPackets.Add(1)
			p.cumTraffic.recvBytes.Add(uint64(n))

			if p.client.enableDebugging && p.udpTraffic.recFlag.Load() {
				p.udpTraffic.recvCount.Add(1)
				p.udpTraffic.recvBytes.Add(uint64(n))
			}

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
	if p.closed.Load() {
		return 0, io.EOF
	}

	if conn := p.backendConn.Load(); conn != nil {
		if err := conn.Write(buf); err != nil {
			p.client.debug("backend write failed: %v", err)
			p.clearBackendConn(conn)
		} else {
			p.cumTraffic.sentPackets.Add(1)
			p.cumTraffic.sentBytes.Add(uint64(len(buf)))
			if p.client.enableDebugging && p.udpTraffic.recFlag.Load() {
				p.udpTraffic.sendCount.Add(1)
				p.udpTraffic.sendBytes.Add(uint64(len(buf)))
			}
		}
	}

	// Do not return an error here, otherwise QUIC/KCP may drop all subsequent packets.
	return len(buf), nil
}

func (p *clientProxy) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}

	p.backendMutex.Lock()
	p.backendCond.Broadcast()
	p.backendMutex.Unlock()

	p.client.debug("client proxy call Close")

	p.clearBackendConn(nil)

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

	clientNonce := make([]byte, kClientNonceSize)
	if _, err := crypto_rand.Read(clientNonce); err != nil {
		return nil, fmt.Errorf("rand client nonce failed: %v", err)
	}

	var proxyCmds []string
	if opts.ProxyCommand != "" {
		proxyCmds, err = splitCommandLine(opts.ProxyCommand)
		if err != nil {
			return nil, fmt.Errorf("split proxy command [%s] failed: %v", opts.ProxyCommand, err)
		}
	}

	proxy := &clientProxy{
		client:        client,
		renewMutex:    make(chan struct{}, 1),
		proxyMode:     opts.ServerInfo.ProxyMode,
		serverNet:     network,
		serverAddr:    opts.TsshdAddr,
		remoteAddr:    &proxyServerAddr{opts.TsshdAddr},
		cipherBlock:   &cipherBlock,
		clientID:      clientID,
		serverID:      opts.ServerInfo.ServerID,
		serverChecker: newTimeoutChecker(opts.HeartbeatTimeout),
		proxyCmds:     proxyCmds,
		udpTraffic:    &trafficStats{},
		clientNonce:   clientNonce,
		// Before protocol version 3, KCP cannot tell a replayed packet apart.
		kcpAliveCheck: opts.ServerInfo.Mode == kUdpModeKCP && client.protoVersion >= 3,
	}
	proxy.backendCond = sync.NewCond(&proxy.backendMutex)

	if client.enableDebugging {
		proxy.serverChecker.onTimeout(func() {
			client.debug("blocked due to no server output for [%v]", opts.HeartbeatTimeout)
		})
		proxy.serverChecker.onReconnected(func() {
			client.debug("resumed after receiving server output")
		})

		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for range ticker.C {
				if proxy.closed.Load() {
					return
				}
				if proxy.udpTraffic.recFlag.Load() {
					if msg := proxy.udpTraffic.flushLog(); msg != "" {
						client.debug("%s", msg)
					}
				}
			}
		}()
	}

	return proxy, nil
}
