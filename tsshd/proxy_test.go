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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type kcpStartupFrontend struct {
	frontendConnection
	t *testing.T
}

func (c *kcpStartupFrontend) start(proxy *serverProxy) {
	// A frontend can authenticate a client as soon as start is called,
	// before initServer has created the KCP listener.
	require.NotNil(c.t, proxy.kcpCrypto)
	client, err := proxy.newClientState(1)
	require.NoError(c.t, err)
	crypto := client.kcpCrypto.Load()
	require.NotNil(c.t, crypto)
	require.Equal(c.t, proxy.kcpCrypto.keyPass, crypto.keyPass)
	require.Equal(c.t, proxy.kcpCrypto.keySalt, crypto.keySalt)
}

func TestKCP_CryptoReadyBeforeFrontendStart(t *testing.T) {
	info := &ServerInfo{}
	proxy, err := startServerProxy(&tsshdArgs{KCP: true, Attachable: true}, info, &kcpStartupFrontend{t: t})
	require.NoError(t, err)
	require.Equal(t, kUdpModeKCP, info.Mode)
	require.Equal(t, fmt.Sprintf("%x", proxy.kcpCrypto.keyPass), info.Pass)
	require.Equal(t, fmt.Sprintf("%x", proxy.kcpCrypto.keySalt), info.Salt)
}

type echoServer struct {
	t *testing.T
}

func (m *echoServer) handleStream(stream Stream) {
	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if !IsClosedError(err) {
				m.t.Fatalf("server read failed: %v", err)
			}
			return
		}
		if _, err := stream.Write(buf[:n]); err != nil {
			m.t.Fatalf("server write failed: %v", err)
			return
		}
	}
}

func runStreamEchoTest(t *testing.T, stream Stream) {
	for size := 1; size <= 2000; size += 3 {
		_ = stream.SetDeadline(time.Now().Add(2 * time.Second))

		send := make([]byte, size)
		for i := range send {
			send[i] = byte(i)
		}

		_, err := stream.Write(send)
		if err != nil {
			t.Fatalf("client write failed: %v", err)
		}

		recv := make([]byte, size)

		_, err = io.ReadFull(stream, recv)
		if err != nil {
			t.Fatalf("client read failed: %v", err)
		}

		if !bytes.Equal(send, recv) {
			t.Fatalf("echo mismatch size=%d", size)
		}
	}
}

// startProxyEchoServer starts an echo server for the test.
func startProxyEchoServer(t *testing.T, args *tsshdArgs) *ServerInfo {
	oriNew := newSshUdpServer
	t.Cleanup(func() {
		newSshUdpServer = oriNew
		cleanupOnExit()
	})

	server := &echoServer{t}
	newSshUdpServer = func(args *tsshdArgs, proxy *serverProxy, addr net.Addr, proto protocolServer) streamHandler {
		return server
	}

	_, output, err := initServer(args)
	if err != nil {
		t.Fatalf("init server failed: %v", err)
	}

	var info ServerInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}
	return &info
}

func newProxyEchoOptions(args *tsshdArgs, info *ServerInfo, host string) *UdpClientOptions {
	return &UdpClientOptions{
		TsshdAddr:        net.JoinHostPort(host, strconv.Itoa(info.Port)),
		ServerInfo:       info,
		ConnectTimeout:   args.ConnectTimeout,
		HeartbeatTimeout: 3 * time.Second,
	}
}

func runProxyEchoTest(t *testing.T, args *tsshdArgs, host string, protoVersion int) {
	info := startProxyEchoServer(t, args)
	runProxyEchoClients(t, args, newProxyEchoOptions(args, info, host), protoVersion, nil)
}

// runProxyEchoClients runs the echo test before and after a second renewTransportPath.
func runProxyEchoClients(t *testing.T, args *tsshdArgs, opts *UdpClientOptions, protoVersion int, beforeRenew func(*clientProxy)) {
	clientCount := 1
	if args.Attachable {
		clientCount = 3
	}

	var wg sync.WaitGroup

	for i := range clientCount {
		// Clients speaking different protocol versions can attach to the same server.
		clientProtoVersion := protoVersion
		if i%2 == 1 {
			clientProtoVersion = kTsshdProtocol
		}

		wg.Go(func() {
			client := &SshUdpClient{protoVersion: clientProtoVersion, activeChecker: newTimeoutChecker(0)}
			proxy, err := startClientProxy(client, opts)
			if err != nil {
				t.Fatalf("start client proxy failed: %v", err)
			}
			defer func() { _ = proxy.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectTimeout)
			err = proxy.renewTransportPath(ctx, nil)
			cancel()
			if err != nil {
				t.Fatalf("renew transport path failed: %v", err)
			}

			client.clientProxy = proxy
			ctx, cancel = context.WithTimeout(context.Background(), opts.ConnectTimeout)
			proto, err := newProtoClient(ctx, opts, client)
			cancel()
			if err != nil {
				t.Fatalf("new proto client failed: %v", err)
			}
			defer func() { _ = proto.Close() }()

			ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			stream, err := proto.newStream(ctx)
			cancel()
			if err != nil {
				t.Fatalf("proto new stream failed: %v", err)
			}
			defer func() { _ = stream.Close() }()

			runStreamEchoTest(t, stream)

			if beforeRenew != nil {
				beforeRenew(proxy)
			}
			ctx, cancel = context.WithTimeout(context.Background(), opts.ConnectTimeout)
			err = proxy.renewTransportPath(ctx, nil)
			cancel()
			if err != nil {
				t.Fatalf("renew transport path failed: %v", err)
			}

			runStreamEchoTest(t, stream)
		})
	}

	wg.Wait()
}

func TestProxy(t *testing.T) {
	tests := []struct {
		name       string
		kcp        bool
		tcp        bool
		attachable bool
	}{
		{"QUIC", false, false, false},
		{"QUIC_TCP", false, true, false},
		{"QUIC_Attachable", false, false, true},
		{"QUIC_TCP_Attachable", false, true, true},
		{"KCP", true, false, false},
		{"KCP_TCP", true, true, false},
		{"KCP_Attachable", true, false, true},
		{"KCP_TCP_Attachable", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := &tsshdArgs{
				KCP:            tt.kcp,
				TCP:            tt.tcp,
				Attachable:     tt.attachable,
				Port:           "31000-65000",
				ConnectTimeout: 3 * time.Second,
			}

			for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
				t.Run(host, func(t *testing.T) {
					skipUnlessUsableHost(t, host)
					runProxyEchoTest(t, args, host, kTsshdProtocol)
				})
			}

			// trzsz/trzsz-ssh#258: IPv6 SSH login, IPv4 client.
			t.Run("IPv6SshConnection", func(t *testing.T) {
				t.Setenv("SSH_CONNECTION", "::1 50818 ::1 22")
				info := startProxyEchoServer(t, args)
				opts := newProxyEchoOptions(args, info, "127.0.0.1")
				opts.IPv4 = true
				runProxyEchoClients(t, args, opts, kTsshdProtocol, nil)
			})

			t.Run("FirstContactAfterConnectTimeout", func(t *testing.T) {
				idleArgs := *args
				idleArgs.ConnectTimeout = 300 * time.Millisecond
				info := startProxyEchoServer(t, &idleArgs)
				time.Sleep(2 * idleArgs.ConnectTimeout)
				runProxyEchoClients(t, &idleArgs, newProxyEchoOptions(args, info, "127.0.0.1"), kTsshdProtocol, nil)
			})

			t.Run("MoveToOtherFamily", func(t *testing.T) {
				skipUnlessBindable(t, "::1")
				info := startProxyEchoServer(t, args)
				network := "udp6"
				if tt.tcp {
					network = "tcp6"
				}
				runProxyEchoClients(t, args, newProxyEchoOptions(args, info, "127.0.0.1"), kTsshdProtocol, func(proxy *clientProxy) {
					proxy.networks = []string{network}
					proxy.serverAddr = net.JoinHostPort("::1", strconv.Itoa(info.Port))
				})
			})

			// Clients older than protocol version 3 neither announce their
			// version nor use directional KCP keys, and must keep working.
			t.Run("LegacyClient", func(t *testing.T) {
				runProxyEchoTest(t, args, "127.0.0.1", 2)
			})
		})
	}
}

type idleFrontend struct {
	frontendConnection
}

func (c *idleFrontend) start(proxy *serverProxy) {}

func TestProxy_ClientHello(t *testing.T) {
	info := &ServerInfo{}
	server, err := startServerProxy(&tsshdArgs{KCP: true}, info, &idleFrontend{})
	require.NoError(t, err)

	newClient := func(protoVersion int) *clientProxy {
		opts := &UdpClientOptions{ServerInfo: info, HeartbeatTimeout: time.Second}
		proxy, err := startClientProxy(&SshUdpClient{protoVersion: protoVersion}, opts)
		require.NoError(t, err)
		t.Cleanup(func() { _ = proxy.Close() })
		proxy.serialNumber.Store(1)
		return proxy
	}

	// authenticate delivers the authentication packet of the client to the server.
	authenticate := func(proxy *clientProxy) *clientHello {
		clientConn, serverConn := net.Pipe()
		defer func() { _ = clientConn.Close() }()
		defer func() { _ = serverConn.Close() }()

		go func() { _ = proxy.sendAuthPacket(context.Background(), &tcpServerConn{clientConn}) }()

		buf := make([]byte, 128)
		n, err := recvUdpPacket(serverConn, buf)
		require.NoError(t, err)

		isAuthPacket, clientID, serialNumber, hello := server.openAuthPacket(buf[:n])
		require.True(t, isAuthPacket)
		require.Equal(t, info.ClientID, clientID)
		require.Equal(t, uint64(1), serialNumber)
		return hello
	}

	acknowledge := func(hello *clientHello) []byte {
		buf, err := server.sealAuthPacket(1, hello)
		require.NoError(t, err)
		return buf
	}

	// Clients older than protocol version 3 do not announce anything.
	legacyClient := newClient(2)
	legacyHello := authenticate(legacyClient)
	require.Equal(t, &clientHello{}, legacyHello)
	require.True(t, legacyClient.isAuthSuccessful(acknowledge(legacyHello)))

	// A newer client never negotiates more than the server supports.
	require.Equal(t, kTsshdProtocol, authenticate(newClient(kTsshdProtocol+1)).protoVersion)

	client := newClient(kTsshdProtocol)
	hello := authenticate(client)
	require.Equal(t, &clientHello{kTsshdProtocol, client.clientNonce}, hello)
	require.Len(t, client.clientNonce, kClientNonceSize)

	// The first authentication decides, and may be repeated when reconnecting.
	require.True(t, server.acceptClientHello(server.soleClient, hello))
	require.True(t, server.acceptClientHello(server.soleClient, authenticate(client)))
	require.True(t, client.isAuthSuccessful(acknowledge(hello)))

	// Another client started with the same server info has the same client ID
	// and starts with the same serial number, but must not take over.
	otherClient := newClient(kTsshdProtocol)
	otherHello := authenticate(otherClient)
	require.NotEqual(t, client.clientNonce, otherClient.clientNonce)
	require.False(t, server.acceptClientHello(server.soleClient, otherHello))
	require.False(t, server.acceptClientHello(server.soleClient, legacyHello))

	// An acknowledgment sent to the first client must not convince the other
	// one that it has been authenticated.
	require.False(t, otherClient.isAuthSuccessful(acknowledge(hello)))
	require.False(t, otherClient.isAuthSuccessful(acknowledge(legacyHello)))
	require.False(t, legacyClient.isAuthSuccessful(acknowledge(hello)))

	// The KCP traffic keys belong to the client that authenticated first.
	newCrypto := func(proxy *clientProxy) *rotatingCrypto {
		crypto, err := newClientCrypto(nil, kTsshdProtocol, proxy.clientID, proxy.clientNonce,
			server.kcpCrypto.keyPass, server.kcpCrypto.keySalt)
		require.NoError(t, err)
		return crypto
	}
	_, err = openTestPacket(server.kcpCrypto, sealTestPacket(t, newCrypto(otherClient), []byte("hello")))
	require.Error(t, err)
	_, err = openTestPacket(server.kcpCrypto, sealTestPacket(t, newCrypto(client), []byte("hello")))
	require.NoError(t, err)

	// Authentication packets of any other length are rejected.
	for _, size := range []int{0, 15, 17, 20, 35, 37, 52} {
		isAuthPacket, _, _, _ := server.openAuthPacket(aesEncrypt(server.cipherBlock, make([]byte, size)))
		require.False(t, isAuthPacket, "auth packet of %d bytes accepted", size)
	}
}

// Since protocol version 3, datagrams that KCP does not accept, such as
// replayed packets, must not make the server look alive.
func TestProxy_KcpAliveCheck(t *testing.T) {
	const kHeartbeatTimeout = 100 * time.Millisecond

	info := &ServerInfo{ProtoVer: kTsshdProtocol, ProxyKey: strings.Repeat("00", 32)}
	serverCrypto, err := newKcpServerCrypto(info, false)
	require.NoError(t, err)

	client := &SshUdpClient{protoVersion: kTsshdProtocol}
	opts := &UdpClientOptions{ServerInfo: info, HeartbeatTimeout: kHeartbeatTimeout}
	proxy, err := startClientProxy(client, opts)
	require.NoError(t, err)
	defer func() { _ = proxy.Close() }()
	client.clientProxy = proxy
	require.NoError(t, serverCrypto.setClientHello(kTsshdProtocol, proxy.clientID, proxy.clientNonce))

	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	proxy.backendConn.Store(&serverConnHolder{&tcpServerConn{clientConn}})

	kcpClient, err := newKcpClient(opts, client, proxy, proxy.remoteAddr)
	require.NoError(t, err)
	defer func() { _ = kcpClient.Close() }()

	isAlive := func() bool { return !proxy.serverChecker.isTimeout() }
	send := func(packet []byte) {
		t.Helper()
		require.NoError(t, serverConn.SetWriteDeadline(time.Now().Add(time.Second)))
		require.NoError(t, sendUdpPacket(serverConn, packet))
	}

	require.Eventually(t, func() bool { return !isAlive() }, time.Second, 10*time.Millisecond)

	packet := sealTestPacket(t, serverCrypto, make([]byte, 64))
	send(packet)
	require.Eventually(t, isAlive, time.Second, 5*time.Millisecond)

	require.Eventually(t, func() bool { return !isAlive() }, time.Second, 10*time.Millisecond)

	// Neither replayed packets nor garbage refresh the checker.
	for range 5 {
		send(packet)
		send(make([]byte, 64))
	}
	require.Never(t, isAlive, 2*kHeartbeatTimeout, 5*time.Millisecond)

	send(sealTestPacket(t, serverCrypto, make([]byte, 64)))
	require.Eventually(t, isAlive, time.Second, 5*time.Millisecond)
}

// Clients attached to the same server share the initial secret. Their traffic
// keys are bound to the authenticated client ID, so that they stay apart even
// if two clients announce the same nonce.
func TestProxy_AttachedClientsWithSameNonce(t *testing.T) {
	info := &ServerInfo{}
	server, err := startServerProxy(&tsshdArgs{KCP: true, Attachable: true}, info, &idleFrontend{})
	require.NoError(t, err)

	clientNonce := bytes.Repeat([]byte{7}, kClientNonceSize)
	pass, salt := server.kcpCrypto.keyPass, server.kcpCrypto.keySalt

	var clientCryptos, serverCryptos []*rotatingCrypto
	for clientID := uint64(1); clientID <= 2; clientID++ {
		client := server.getClient(clientID)
		require.NotNil(t, client)
		require.True(t, server.acceptClientHello(client, &clientHello{kTsshdProtocol, clientNonce}))
		serverCryptos = append(serverCryptos, client.kcpCrypto.Load())

		crypto, err := newClientCrypto(nil, kTsshdProtocol, clientID, clientNonce, pass, salt)
		require.NoError(t, err)
		clientCryptos = append(clientCryptos, crypto)
	}

	for i := range 2 {
		fromClient := sealTestPacket(t, clientCryptos[i], []byte("hello"))
		_, err := openTestPacket(serverCryptos[1-i], fromClient)
		require.Error(t, err, "packet accepted on the connection of another client")
		_, err = openTestPacket(serverCryptos[i], fromClient)
		require.NoError(t, err)

		fromServer := sealTestPacket(t, serverCryptos[i], []byte("hello"))
		_, err = openTestPacket(clientCryptos[1-i], fromServer)
		require.Error(t, err, "packet sent to another client accepted")
		_, err = openTestPacket(clientCryptos[i], fromServer)
		require.NoError(t, err)
	}
}

// queueFrontend hands the queued datagrams of the sole client to the server proxy.
type queueFrontend struct {
	proxy   *serverProxy
	packets chan []byte
}

func (c *queueFrontend) start(proxy *serverProxy) { c.proxy = proxy }

func (c *queueFrontend) readFrom(buf []byte) (int, *clientState) {
	packet, ok := <-c.packets
	if !ok {
		return 0, nil
	}
	return copy(buf, packet), c.proxy.soleClient
}

func (c *queueFrontend) writeTo(buf []byte, client *clientState) error { return nil }

func (c *queueFrontend) addClientMap(*clientState) {}

func (c *queueFrontend) delClientMap(*clientState, *udpPath) {}

func (c *queueFrontend) addAuthedMap(*clientState) {}

func (c *queueFrontend) delAuthedMap(*clientState, *udpPath) {}

func (c *queueFrontend) Close() {}

// Datagrams that the KCP listener does not accept must not make the client
// look alive, in particular the replayed packets since protocol version 3.
func TestProxy_KcpClientAliveCheck(t *testing.T) {
	const kHeartbeatTimeout = 100 * time.Millisecond

	info := &ServerInfo{}
	frontend := &queueFrontend{packets: make(chan []byte)}
	proxy, err := startServerProxy(&tsshdArgs{KCP: true}, info, frontend)
	require.NoError(t, err)

	clientNonce := bytes.Repeat([]byte{7}, kClientNonceSize)
	require.True(t, proxy.acceptClientHello(proxy.soleClient, &clientHello{kTsshdProtocol, clientNonce}))
	clientCrypto, err := newClientCrypto(nil, kTsshdProtocol, info.ClientID, clientNonce,
		proxy.kcpCrypto.keyPass, proxy.kcpCrypto.keySalt)
	require.NoError(t, err)

	clientChecker := newTimeoutChecker(kHeartbeatTimeout)
	defer clientChecker.Close()
	proxy.soleClient.server.Store(&sshUdpServer{clientChecker: clientChecker})

	listener, err := listenKCP(proxy, proxy.kcpCrypto)
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	defer close(frontend.packets)

	isAlive := func() bool { return !clientChecker.isTimeout() }
	send := func(packet []byte) {
		t.Helper()
		select {
		case frontend.packets <- packet:
		case <-time.After(time.Second):
			t.Fatal("server proxy did not read the packet")
		}
	}

	require.Eventually(t, func() bool { return !isAlive() }, time.Second, 10*time.Millisecond)

	// A single byte passes the crypto, which refreshes the checker, but is
	// too short for the KCP listener to create a session that would outlive
	// the test.
	packet := sealTestPacket(t, clientCrypto, make([]byte, 1))
	send(packet)
	require.Eventually(t, isAlive, time.Second, 5*time.Millisecond)

	require.Eventually(t, func() bool { return !isAlive() }, time.Second, 10*time.Millisecond)

	// Neither replayed packets nor garbage refresh the checker.
	for range 5 {
		send(packet)
		send(make([]byte, 64))
	}
	require.Never(t, isAlive, 2*kHeartbeatTimeout, 5*time.Millisecond)

	send(sealTestPacket(t, clientCrypto, make([]byte, 1)))
	require.Eventually(t, isAlive, time.Second, 5*time.Millisecond)

	require.NoError(t, listener.SetReadDeadline(time.Now()))
	_, err = listener.AcceptKCP()
	require.Error(t, err, "KCP session created by the test packets")
}

// skipUnlessUsableHost skips ::1 without IPv6 and localhost without both families.
func skipUnlessUsableHost(t *testing.T, host string) {
	t.Helper()
	if host == "127.0.0.1" {
		return
	}
	skipUnlessBindable(t, "::1")
	if host == "localhost" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		var has4, has6 bool
		for _, ip := range ips {
			has4 = has4 || ip.Unmap().Is4()
			has6 = has6 || !ip.Unmap().Is4()
		}
		if !has4 || !has6 {
			t.Skipf("%s is not dual-stack: %v, %v", host, ips, err)
		}
	}
}
