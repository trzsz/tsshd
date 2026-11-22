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
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// localhostAddrs skips the test unless localhost has an IPv4 and an IPv6 address.
func localhostAddrs(t *testing.T) (*net.UDPAddr, *net.UDPAddr) {
	t.Helper()
	addr4, err4 := net.ResolveUDPAddr("udp4", "localhost:0")
	addr6, err6 := net.ResolveUDPAddr("udp6", "localhost:0")
	if err4 != nil || err6 != nil {
		t.Skipf("localhost is not dual-stack: %v, %v", err4, err6)
	}
	return addr4, addr6
}

// listenLocalhost binds both localhost addresses on one port. Nothing replies.
func listenLocalhost(t *testing.T) (string, *net.UDPConn, *net.UDPConn) {
	t.Helper()
	addr4, addr6 := localhostAddrs(t)
	var err error
	for range 10 {
		var conn4, conn6 *net.UDPConn
		conn4, err = net.ListenUDP("udp4", addr4)
		require.NoError(t, err)
		addr6.Port = conn4.LocalAddr().(*net.UDPAddr).Port
		conn6, err = net.ListenUDP("udp6", addr6)
		if err == nil {
			t.Cleanup(func() { _ = conn4.Close(); _ = conn6.Close() })
			return net.JoinHostPort("localhost", strconv.Itoa(addr6.Port)), conn4, conn6
		}
		_ = conn4.Close()
	}
	t.Skipf("listen on [%v] failed: %v", addr6, err)
	return "", nil, nil
}

// serveAuth answers auth packets like tsshd.
func serveAuth(t *testing.T, conn net.PacketConn) {
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	peer := &startupPeer{conn, block, nil}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 0xffff)
		for {
			if _, _, err := peer.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
}

func newAuthProxy(t *testing.T, addr string, ipv4, ipv6 bool) *clientProxy {
	t.Helper()
	proxy, err := startClientProxy(&SshUdpClient{}, &UdpClientOptions{TsshdAddr: addr, IPv4: ipv4, IPv6: ipv6,
		ServerInfo: &ServerInfo{ProxyKey: strings.Repeat("00", 32), ServerID: 42, ClientID: 23}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

type dialFunc func(p *clientProxy, ctx context.Context, network string) (*serverConnHolder, error)

func dialDirect(p *clientProxy, ctx context.Context, network string) (*serverConnHolder, error) {
	return p.dialPacket(ctx, nil, network)
}

// dialFromJumpHost dials like a jump host does for a dial-udp request.
func dialFromJumpHost(p *clientProxy, ctx context.Context, network string) (*serverConnHolder, error) {
	conn, err := dialUDP(&dialUdpMessage{Net: network, Addr: p.serverAddr})
	if err != nil {
		return nil, err
	}
	return &serverConnHolder{&udpServerConn{conn.(*net.UDPConn)}}, nil
}

// raceOnce returns the network of the path raceUdpPath kept.
func raceOnce(t *testing.T, addr string, dial dialFunc) string {
	t.Helper()
	proxy := newAuthProxy(t, addr, false, false)
	winner, _ := racePaths(t, proxy, proxy.authUdpPath, dial)
	return winner
}

// racePaths returns the network and the path racePath kept.
func racePaths(t *testing.T, proxy *clientProxy, auth func(context.Context, *serverConnHolder) error, dial dialFunc) (string, *serverConnHolder) {
	t.Helper()
	var mutex sync.Mutex
	paths := make(map[string]*serverConnHolder)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := proxy.racePath(ctx, proxy.raceNetworks(), auth, func(ctx context.Context, network string) (*serverConnHolder, error) {
		path, err := dial(proxy, ctx, network)
		mutex.Lock()
		defer mutex.Unlock()
		paths[network] = path
		return path, err
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.Less(t, time.Since(start), time.Second)

	// No lock: -race fails here if racePath did not wait for every dial.
	require.Len(t, paths, 2)
	var winner string
	for network, path := range paths {
		if path == conn {
			winner = network
		} else if path != nil {
			err := path.Write([]byte{0})
			require.True(t, errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe), "path over [%s] left open: %v", network, err)
		}
	}
	require.NotEmpty(t, winner)
	return winner, conn
}

func TestRaceUdpPath_Localhost(t *testing.T) {
	t.Run("IPv6Only", func(t *testing.T) {
		addr, _, conn6 := listenLocalhost(t)
		serveAuth(t, conn6)
		require.Equal(t, "udp6", raceOnce(t, addr, dialDirect))
	})

	t.Run("IPv4Only", func(t *testing.T) {
		addr, conn4, _ := listenLocalhost(t)
		serveAuth(t, conn4)
		require.Equal(t, "udp4", raceOnce(t, addr, dialDirect))
	})

	t.Run("Both", func(t *testing.T) {
		addr, conn4, conn6 := listenLocalhost(t)
		serveAuth(t, conn4)
		serveAuth(t, conn6)
		raceOnce(t, addr, dialDirect)
	})

	t.Run("IPv6PortUnreachable", func(t *testing.T) {
		addr, conn4, conn6 := listenLocalhost(t)
		serveAuth(t, conn4)
		_ = conn6.Close()
		require.Equal(t, "udp4", raceOnce(t, addr, func(p *clientProxy, ctx context.Context, network string) (*serverConnHolder, error) {
			if network == "udp4" {
				// Let the IPv6 port-unreachable error arrive before IPv4 can answer.
				time.Sleep(200 * time.Millisecond)
			}
			return dialDirect(p, ctx, network)
		}))
	})

	t.Run("JumpHost", func(t *testing.T) {
		addr, _, conn6 := listenLocalhost(t)
		serveAuth(t, conn6)
		require.Equal(t, "udp6", raceOnce(t, addr, dialFromJumpHost))
	})
}

func TestRaceUdpPath_IPv6Literal(t *testing.T) {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("listen on IPv6 loopback failed: %v", err)
	}
	serveAuth(t, conn)
	require.Equal(t, "udp6", raceOnce(t, conn.LocalAddr().String(), dialDirect))
}

// fakeDialer connects every path to one IPv4 socket and records the networks.
type fakeDialer struct {
	addr     *net.UDPAddr
	mutex    sync.Mutex
	networks []string
}

func (d *fakeDialer) dial(ctx context.Context, network string) (*serverConnHolder, error) {
	d.mutex.Lock()
	d.networks = append(d.networks, network)
	d.mutex.Unlock()
	conn, err := net.DialUDP("udp", nil, d.addr)
	if err != nil {
		return nil, err
	}
	return &serverConnHolder{&udpServerConn{conn}}, nil
}

func TestRaceUdpPath_ExplicitFamily(t *testing.T) {
	server := listenRandomUDP(t)
	serveAuth(t, server)
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			proxy := newAuthProxy(t, "localhost:1", network == "udp4", network == "udp6")
			dialer := &fakeDialer{addr: server.LocalAddr().(*net.UDPAddr)}
			for range 2 {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				conn, err := proxy.raceUdpPath(ctx, dialer.dial)
				cancel()
				require.NoError(t, err)
				_ = conn.Close()
			}
			require.Equal(t, []string{network, network}, dialer.networks)
		})
	}
}

func TestRaceUdpPath_NoFamilyAnswers(t *testing.T) {
	server := listenRandomUDP(t)
	defer func() { _ = server.Close() }()
	proxy := newAuthProxy(t, "localhost:1", false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := proxy.raceUdpPath(ctx, (&fakeDialer{addr: server.LocalAddr().(*net.UDPAddr)}).dial)
	require.Less(t, time.Since(start), time.Second)
	require.ErrorContains(t, err, "renew path to [udp4] [localhost:1] failed")
	require.ErrorContains(t, err, "renew path to [udp6] [localhost:1] failed")
	require.ErrorContains(t, err, "context deadline exceeded")
}

func TestRenewTransportPath_TCPLocalhost(t *testing.T) {
	localhostAddrs(t)
	defer cleanupOnExit()

	args := &tsshdArgs{TCP: true, IPv6: true, Port: "31000-65000", ConnectTimeout: 3 * time.Second}
	_, output, err := initServer(args)
	require.NoError(t, err)
	var info ServerInfo
	require.NoError(t, json.Unmarshal([]byte(output), &info))

	proxy, err := startClientProxy(&SshUdpClient{}, &UdpClientOptions{
		TsshdAddr: net.JoinHostPort("localhost", strconv.Itoa(info.Port)), ServerInfo: &info})
	require.NoError(t, err)
	defer func() { _ = proxy.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), args.ConnectTimeout)
	defer cancel()
	require.NoError(t, proxy.renewTransportPath(ctx, nil))
}

// junkFirst sends a large non-auth datagram before each reply.
type junkFirst struct{ net.PacketConn }

func (c junkFirst) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		_, _ = c.PacketConn.WriteTo(make([]byte, 1200), addr)
	}
	return n, addr, err
}

func TestRaceUdpPath_SkipsLargeDatagram(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	serveAuth(t, junkFirst{conn})

	proxy := newAuthProxy(t, conn.LocalAddr().String(), true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	path, err := proxy.raceUdpPath(ctx, func(ctx context.Context, network string) (*serverConnHolder, error) {
		return dialDirect(proxy, ctx, network)
	})
	require.NoError(t, err)
	_ = path.Close()
}

// jumpHost serves dial streams like tsshd on a jump host.
type jumpHost struct {
	protocolClient
	server *sshUdpServer
	stall  bool // never answer a dial
	mutex  sync.Mutex
	peers  []net.Conn
}

func (j *jumpHost) newStream(context.Context) (Stream, error) {
	conn, peer := net.Pipe()
	j.mutex.Lock()
	j.peers = append(j.peers, peer)
	j.mutex.Unlock()
	go func() {
		stream := startupPipeStream{peer}
		defer func() { _ = stream.Close() }()
		cmd, err := recvCommand(stream)
		if err != nil || !j.stall && cmd != "dial" {
			return
		}
		if err := sendSuccess(stream); err != nil {
			return
		}
		if j.stall {
			_, _ = io.Copy(io.Discard, stream)
			return
		}
		j.server.handleDialEvent(stream)
	}()
	return startupPipeStream{conn}, nil
}

func newJumpHost(t *testing.T, stall bool) *SshUdpClient {
	jump := &jumpHost{server: &sshUdpServer{clientChecker: newTimeoutChecker(0)}, stall: stall}
	client := &SshUdpClient{protoClient: jump, clientProxy: &clientProxy{serverChecker: newTimeoutChecker(0)}}
	t.Cleanup(func() {
		jump.mutex.Lock()
		for _, peer := range jump.peers {
			_ = peer.Close()
		}
		jump.mutex.Unlock()
		jump.server.clientChecker.Close()
		client.clientProxy.serverChecker.Close()
	})
	return client
}

// A dial that the jump host never answers must not hold back the other family.
func TestRaceUdpPath_JumpHostStalledDial(t *testing.T) {
	server := listenRandomUDP(t)
	serveAuth(t, server)
	stalled := newJumpHost(t, true)
	addr := net.JoinHostPort("localhost", strconv.Itoa(server.LocalAddr().(*net.UDPAddr).Port))
	require.Equal(t, "udp4", raceOnce(t, addr, func(p *clientProxy, ctx context.Context, network string) (*serverConnHolder, error) {
		if network == "udp6" {
			return p.dialPacket(ctx, stalled, network)
		}
		return dialDirect(p, ctx, network)
	}))
}

// listenLocalhostTCP binds both localhost addresses on one port.
func listenLocalhostTCP(t *testing.T) (string, *net.TCPListener, *net.TCPListener) {
	t.Helper()
	addr4, addr6 := localhostAddrs(t)
	var err error
	for range 10 {
		var listener4, listener6 *net.TCPListener
		listener4, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: addr4.IP})
		require.NoError(t, err)
		port := listener4.Addr().(*net.TCPAddr).Port
		listener6, err = net.ListenTCP("tcp6", &net.TCPAddr{IP: addr6.IP, Port: port, Zone: addr6.Zone})
		if err == nil {
			t.Cleanup(func() { _ = listener4.Close(); _ = listener6.Close() })
			return net.JoinHostPort("localhost", strconv.Itoa(port)), listener4, listener6
		}
		_ = listener4.Close()
	}
	t.Skipf("listen on [%v] failed: %v", addr6, err)
	return "", nil, nil
}

func listenLoopbackTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// startTcpFrontend runs the TCP handshake of tsshd on the listeners.
func startTcpFrontend(t *testing.T, attachable bool, listeners ...*net.TCPListener) (*serverProxy, *ServerInfo) {
	t.Helper()
	info := &ServerInfo{}
	args := &tsshdArgs{TCP: true, Attachable: attachable, ConnectTimeout: 3 * time.Second}
	server, err := startServerProxy(args, info, &tcpFrontendConn{listenerList: listeners})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupOnExit()
		server.clientMutex.RLock()
		defer server.clientMutex.RUnlock()
		for _, client := range server.clientMap {
			client.setClientConn(nil, nil)
		}
		if server.soleClient != nil {
			server.soleClient.setClientConn(nil, nil)
		}
	})
	return server, info
}

func newTcpProxy(t *testing.T, addr string, info *ServerInfo, ipv4, ipv6 bool) *clientProxy {
	t.Helper()
	proxy, err := startClientProxy(&SshUdpClient{protoVersion: kTsshdProtocol},
		&UdpClientOptions{TsshdAddr: addr, IPv4: ipv4, IPv6: ipv6, ServerInfo: info})
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

// raceTcpOnce returns the network and the local address of the path kept.
func raceTcpOnce(t *testing.T, proxy *clientProxy, dial dialFunc) (string, string) {
	t.Helper()
	proxy.serialNumber.Add(1)
	winner, conn := racePaths(t, proxy, proxy.authTcpPath, dial)
	if tcpConn, ok := conn.PacketConn.(*tcpServerConn).conn.(*net.TCPConn); ok {
		return winner, tcpConn.LocalAddr().String()
	}
	return winner, ""
}

func dialStreamDirect(p *clientProxy, ctx context.Context, network string) (*serverConnHolder, error) {
	return p.dialStream(ctx, nil, network)
}

// heldConns reports on connections that are accepted and never answered.
type heldConns struct {
	received chan struct{} // an auth packet arrived
	closed   chan struct{} // the client closed a connection
}

func holdTCP(t *testing.T, listener net.Listener) *heldConns {
	held := &heldConns{make(chan struct{}, 16), make(chan struct{}, 16)}
	serveTCP(t, listener, func(conn net.Conn, _ func(net.Conn)) {
		if _, err := recvUdpPacket(conn, make([]byte, 128)); err == nil {
			held.received <- struct{}{}
			_, _ = io.Copy(io.Discard, conn)
		}
		held.closed <- struct{}{}
	})
	return held
}

// serveTCP closes the listener and all connections, tracked ones too, when the test ends.
func serveTCP(t *testing.T, listener net.Listener, handle func(conn net.Conn, track func(net.Conn))) {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var conns []net.Conn
	track := func(conn net.Conn) {
		mutex.Lock()
		defer mutex.Unlock()
		conns = append(conns, conn)
	}
	wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			track(conn)
			wg.Go(func() { handle(conn, track) })
		}
	})
	t.Cleanup(func() {
		_ = listener.Close()
		mutex.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mutex.Unlock()
		wg.Wait()
	})
}

// dialAfterReceived holds back the dial on network until held got an auth packet.
func dialAfterReceived(held *heldConns, network string, dial dialFunc) dialFunc {
	return func(p *clientProxy, ctx context.Context, n string) (*serverConnHolder, error) {
		if n == network {
			select {
			case <-held.received:
			case <-ctx.Done():
			}
		}
		return dial(p, ctx, n)
	}
}

func requireSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting until %s", what)
	}
}

func dialStreamVia(jump *SshUdpClient) dialFunc {
	return func(p *clientProxy, ctx context.Context, network string) (*serverConnHolder, error) {
		return p.dialStream(ctx, jump, network)
	}
}

func TestRaceTcpPath_Localhost(t *testing.T) {
	t.Run("IPv6Only", func(t *testing.T) {
		addr, listener4, listener6 := listenLocalhostTCP(t)
		holdTCP(t, listener4)
		_, info := startTcpFrontend(t, false, listener6)
		winner, _ := raceTcpOnce(t, newTcpProxy(t, addr, info, false, false), dialStreamDirect)
		require.Equal(t, "tcp6", winner)
	})

	t.Run("IPv4Only", func(t *testing.T) {
		addr, listener4, listener6 := listenLocalhostTCP(t)
		holdTCP(t, listener6)
		_, info := startTcpFrontend(t, false, listener4)
		winner, _ := raceTcpOnce(t, newTcpProxy(t, addr, info, false, false), dialStreamDirect)
		require.Equal(t, "tcp4", winner)
	})

	// The server sees the same serial number twice and keeps one connection.
	t.Run("Both", func(t *testing.T) {
		forEachAttachable(t, func(t *testing.T, attachable bool) {
			addr, listener4, listener6 := listenLocalhostTCP(t)
			server, info := startTcpFrontend(t, attachable, listener4, listener6)
			proxy := newTcpProxy(t, addr, info, false, false)
			for serial := uint64(1); serial <= 3; serial++ {
				_, localAddr := raceTcpOnce(t, proxy, dialStreamDirect)
				client := server.getClient(proxy.clientID)
				require.Equal(t, serial, client.serialNumber.Load())
				require.Eventually(t, func() bool {
					conn := client.clientConn.Load()
					return conn != nil && conn.RemoteAddr().String() == localAddr
				}, time.Second, time.Millisecond)
			}
		})
	})

	t.Run("LoserWaitingForAck", func(t *testing.T) {
		addr, listener4, listener6 := listenLocalhostTCP(t)
		held := holdTCP(t, listener4)
		_, info := startTcpFrontend(t, false, listener6)
		winner, _ := raceTcpOnce(t, newTcpProxy(t, addr, info, false, false), dialAfterReceived(held, "tcp6", dialStreamDirect))
		require.Equal(t, "tcp6", winner)
		requireSignal(t, held.closed, "the IPv4 connection is closed")
	})

	t.Run("JumpHost", func(t *testing.T) {
		addr, listener4, listener6 := listenLocalhostTCP(t)
		held := holdTCP(t, listener4)
		_, info := startTcpFrontend(t, false, listener6)
		dial := dialStreamVia(newJumpHost(t, false))
		winner, _ := raceTcpOnce(t, newTcpProxy(t, addr, info, false, false), dialAfterReceived(held, "tcp6", dial))
		require.Equal(t, "tcp6", winner)
		requireSignal(t, held.closed, "the jump host closes the IPv4 connection")
	})
}

func TestRaceTcpPath_IPv6Literal(t *testing.T) {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("listen on IPv6 loopback failed: %v", err)
	}
	_, info := startTcpFrontend(t, false, listener)
	winner, _ := raceTcpOnce(t, newTcpProxy(t, listener.Addr().String(), info, false, false), dialStreamDirect)
	require.Equal(t, "tcp6", winner)
}

func TestRaceTcpPath_JumpHostStalledDial(t *testing.T) {
	listener := listenLoopbackTCP(t)
	_, info := startTcpFrontend(t, false, listener)
	dial, stalled := dialStreamVia(newJumpHost(t, false)), dialStreamVia(newJumpHost(t, true))
	proxy := newTcpProxy(t, net.JoinHostPort("localhost", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)), info, false, false)
	winner, _ := raceTcpOnce(t, proxy, func(p *clientProxy, ctx context.Context, network string) (*serverConnHolder, error) {
		if network == "tcp6" {
			return stalled(p, ctx, network)
		}
		return dial(p, ctx, network)
	})
	require.Equal(t, "tcp4", winner)
}

// fakeTcpDialer connects every path to one IPv4 listener and records the networks.
type fakeTcpDialer struct {
	addr     string
	mutex    sync.Mutex
	networks []string
}

func (d *fakeTcpDialer) dial(_ *clientProxy, ctx context.Context, network string) (*serverConnHolder, error) {
	d.mutex.Lock()
	d.networks = append(d.networks, network)
	d.mutex.Unlock()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", d.addr)
	if err != nil {
		return nil, err
	}
	return &serverConnHolder{&tcpServerConn{conn}}, nil
}

func TestRaceTcpPath_ExplicitFamily(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			listener := listenLoopbackTCP(t)
			_, info := startTcpFrontend(t, false, listener)
			proxy := newTcpProxy(t, "localhost:1", info, network == "tcp4", network == "tcp6")
			require.Equal(t, []string{network}, proxy.raceNetworks())
			dialer := &fakeTcpDialer{addr: listener.Addr().String()}
			for range 2 {
				proxy.serialNumber.Add(1)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				conn, err := proxy.racePath(ctx, proxy.raceNetworks(), proxy.authTcpPath, func(ctx context.Context, network string) (*serverConnHolder, error) {
					return dialer.dial(proxy, ctx, network)
				})
				cancel()
				require.NoError(t, err)
				_ = conn.Close()
			}
			require.Equal(t, []string{network, network}, dialer.networks)
		})
	}
}

func TestRaceTcpPath_NoFamilyAnswers(t *testing.T) {
	listener := listenLoopbackTCP(t)
	held := holdTCP(t, listener)
	proxy := newTcpProxy(t, "localhost:1", &ServerInfo{ProxyKey: strings.Repeat("00", 32), ProxyMode: kProxyModeTCP}, false, false)
	dialer := &fakeTcpDialer{addr: listener.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := proxy.racePath(ctx, proxy.raceNetworks(), proxy.authTcpPath, func(ctx context.Context, network string) (*serverConnHolder, error) {
		return dialer.dial(proxy, ctx, network)
	})
	require.Less(t, time.Since(start), time.Second)
	require.ErrorContains(t, err, "renew path to [tcp4] [localhost:1] failed")
	require.ErrorContains(t, err, "renew path to [tcp6] [localhost:1] failed")
	require.ErrorContains(t, err, "context deadline exceeded")
	requireSignal(t, held.closed, "the first connection is closed")
	requireSignal(t, held.closed, "the second connection is closed")
}

const kProxyCommandHelperEnv = "TSSHD_TEST_PROXY_COMMAND_ADDR"

// TestProxyCommandHelper is the proxy command of TestRenewTcpPath_ProxyCommand.
func TestProxyCommandHelper(t *testing.T) {
	addr := os.Getenv(kProxyCommandHelperEnv)
	if addr == "" {
		return
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		os.Exit(1)
	}
	go func() { _, _ = io.Copy(conn, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, conn)
	os.Exit(0)
}

// newProxyCommandProxy forces IPv6, which a proxy command must ignore.
func newProxyCommandProxy(t *testing.T, info *ServerInfo, target net.Addr) *clientProxy {
	t.Helper()
	t.Setenv(kProxyCommandHelperEnv, target.String())
	proxy := newTcpProxy(t, "localhost:1", info, false, true)
	proxy.proxyCmds = []string{os.Args[0], "-test.run=^TestProxyCommandHelper$"}
	return proxy
}

// relayAfterPause counts connections and forwards them to target after a pause.
// The pause lets a second proxy command connect before the first is answered.
func relayAfterPause(t *testing.T, target net.Addr) (net.Addr, *atomic.Int32) {
	t.Helper()
	listener := listenLoopbackTCP(t)
	count := &atomic.Int32{}
	serveTCP(t, listener, func(conn net.Conn, track func(net.Conn)) {
		defer func() { _ = conn.Close() }()
		count.Add(1)
		time.Sleep(200 * time.Millisecond)
		server, err := net.Dial("tcp", target.String())
		if err != nil {
			return
		}
		track(server)
		go func() { _, _ = io.Copy(server, conn); _ = server.Close() }()
		_, _ = io.Copy(conn, server)
	})
	return listener.Addr(), count
}

func TestRenewTcpPath_ProxyCommand(t *testing.T) {
	t.Run("DialsOnce", func(t *testing.T) {
		listener := listenLoopbackTCP(t)
		server, info := startTcpFrontend(t, false, listener)
		relay, count := relayAfterPause(t, listener.Addr())
		proxy := newProxyCommandProxy(t, info, relay)
		for serial := uint64(1); serial <= 2; serial++ {
			proxy.serialNumber.Add(1)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			conn, err := proxy.renewTcpPath(ctx, nil)
			cancel()
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			require.Equal(t, serial, server.soleClient.serialNumber.Load())
			require.Equal(t, int32(serial), count.Load())
		}
	})

	t.Run("KilledOnCancel", func(t *testing.T) {
		listener := listenLoopbackTCP(t)
		held := holdTCP(t, listener)
		proxy := newProxyCommandProxy(t, &ServerInfo{ProxyKey: strings.Repeat("00", 32), ProxyMode: kProxyModeTCP}, listener.Addr())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		go func() {
			select {
			case <-held.received:
				cancel()
			case <-ctx.Done():
			}
		}()
		_, err := proxy.renewTcpPath(ctx, nil)
		require.ErrorContains(t, err, "context canceled")
		requireSignal(t, held.closed, "the proxy command is killed")
	})
}
