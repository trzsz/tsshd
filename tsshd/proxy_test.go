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
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestPacketCache_Basic(t *testing.T) {
	var p packetCache

	for i := range 10 {
		p.addPacket([]byte{byte(i)})
	}

	var got []byte
	p.sendCache(func(b []byte) error {
		got = append(got, b[0])
		return nil
	})

	// first 10
	for i := range 10 {
		if got[i] != byte(i) {
			t.Fatalf("expect %d got %d", i, got[i])
		}
	}
}

func TestPacketCache_FirstAndRecent(t *testing.T) {
	var p packetCache

	total := kPacketCacheSize * 3
	for i := range total {
		p.addPacket([]byte{byte(i)})
	}

	var got []byte
	p.sendCache(func(b []byte) error {
		got = append(got, b[0])
		return nil
	})

	// first 100
	for i := range kPacketCacheSize {
		if got[i] != byte(i) {
			t.Fatalf("first mismatch at %d, got[%d]", i, got[i])
		}
	}

	// last 100
	start := total - kPacketCacheSize
	for i := range kPacketCacheSize {
		if got[kPacketCacheSize+i] != byte(start+i) {
			t.Logf("%v", got)
			t.Fatalf("recent mismatch at %d, got [%d]", kPacketCacheSize+i, got[kPacketCacheSize+i])
		}
	}
}

func TestPacketCache_RecentPartial(t *testing.T) {
	var p packetCache

	for i := range kPacketCacheSize {
		p.addPacket([]byte{byte(i)})
	}

	for i := range kPacketCacheSize / 2 {
		p.addPacket([]byte{byte(100 + i)})
	}

	var got []byte
	p.sendCache(func(b []byte) error {
		got = append(got, b[0])
		return nil
	})

	// first 100
	for i := range kPacketCacheSize {
		if got[i] != byte(i) {
			t.Fatalf("first mismatch at %d, got %d", i, got[i])
		}
	}

	// last 50
	for i := range kPacketCacheSize / 2 {
		if got[kPacketCacheSize+i] != byte(100+i) {
			t.Fatalf("recent partial mismatch at %d, got %d", i, got[kPacketCacheSize+i])
		}
	}
}

func TestPacketCache_ClearAndReuse(t *testing.T) {
	var p packetCache

	for i := range kPacketCacheSize * 2 {
		p.addPacket([]byte{byte(i)})
	}

	p.clearCache()

	for i := 100; i < 110; i++ {
		p.addPacket([]byte{byte(i)})
	}

	var got []byte
	p.sendCache(func(b []byte) error {
		got = append(got, b[0])
		return nil
	})

	// first 10
	for i := range 10 {
		if got[i] != byte(100+i) {
			t.Fatalf("reuse mismatch at %d, got %d", i, got[i])
		}
	}
}

type echoServer struct {
	t *testing.T
}

func (m *echoServer) handleStream(stream Stream) {
	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if !isClosedError(err) {
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

func runProxyEchoTest(t *testing.T, args *tsshdArgs) {
	oriNew := newSshUdpServer
	defer func() {
		newSshUdpServer = oriNew
		cleanupOnExit()
	}()

	server := &echoServer{t}
	newSshUdpServer = func(args *tsshdArgs, proxy *serverProxy, addr net.Addr, proto protocolServer) streamHandler {
		return server
	}

	if args.KCP && args.Attachable || !args.KCP && !args.Attachable {
		_ = os.Unsetenv("SSH_CONNECTION")
		if v := os.Getenv("SSH_CONNECTION"); v != "" {
			t.Fatalf("SSH_CONNECTION should be unset, got %q", v)
		}
	} else {
		const kSshConn = "127.0.0.1 50818 127.0.0.1 22"
		_ = os.Setenv("SSH_CONNECTION", kSshConn)
		if v := os.Getenv("SSH_CONNECTION"); v != kSshConn {
			t.Fatalf("SSH_CONNECTION mismatch: want %q, got %q", kSshConn, v)
		}
	}

	output, err := initServer(args)
	if err != nil {
		t.Fatalf("init server failed: %v", err)
	}

	var info ServerInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	opts := &UdpClientOptions{
		TsshdAddr:        net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)),
		ServerInfo:       &info,
		ConnectTimeout:   args.ConnectTimeout,
		HeartbeatTimeout: 3 * time.Second,
	}

	clientCount := 1
	if args.Attachable {
		clientCount = 3
	}

	var wg sync.WaitGroup

	for range clientCount {
		wg.Go(func() {
			proxy, err := startClientProxy(&SshUdpClient{}, opts)
			if err != nil {
				t.Fatalf("start client proxy failed: %v", err)
			}
			defer func() { _ = proxy.Close() }()

			if err := proxy.renewTransportPath(nil, opts.ConnectTimeout); err != nil {
				t.Fatalf("renew transport path failed: %v", err)
			}

			proto, err := newProtoClient(opts, proxy, proxy.remoteAddr)
			if err != nil {
				t.Fatalf("new proto client failed: %v", err)
			}
			defer func() { _ = proto.closeClient() }()

			stream, err := proto.newStream(time.Second)
			if err != nil {
				t.Fatalf("proto new stream failed: %v", err)
			}
			defer func() { _ = stream.Close() }()

			runStreamEchoTest(t, stream)

			if err := proxy.renewTransportPath(nil, opts.ConnectTimeout); err != nil {
				t.Fatalf("renew transport path failed: %v", err)
			}

			runStreamEchoTest(t, stream)
		})
	}

	wg.Wait()
}

func TestProxy_QUIC(t *testing.T) {
	runProxyEchoTest(t, &tsshdArgs{
		KCP:            false,
		TCP:            false,
		Attachable:     false,
		Port:           "31000-65000",
		ConnectTimeout: 3 * time.Second,
	})
}

func TestProxy_QUIC_TCP(t *testing.T) {
	runProxyEchoTest(t, &tsshdArgs{
		KCP:            false,
		TCP:            true,
		Attachable:     false,
		Port:           "31000-65000",
		ConnectTimeout: 3 * time.Second,
	})
}

func TestProxy_QUIC_Attachable(t *testing.T) {
	runProxyEchoTest(t, &tsshdArgs{
		KCP:            false,
		TCP:            false,
		Attachable:     true,
		Port:           "31000-65000",
		ConnectTimeout: 3 * time.Second,
	})
}

func TestProxy_QUIC_TCP_Attachable(t *testing.T) {
	runProxyEchoTest(t, &tsshdArgs{
		KCP:            false,
		TCP:            true,
		Attachable:     true,
		Port:           "31000-65000",
		ConnectTimeout: 3 * time.Second,
	})
}

func TestProxy_KCP(t *testing.T) {
	runProxyEchoTest(t, &tsshdArgs{
		KCP:            true,
		TCP:            false,
		Attachable:     false,
		Port:           "31000-65000",
		ConnectTimeout: 3 * time.Second,
	})
}

func TestProxy_KCP_TCP(t *testing.T) {
	runProxyEchoTest(t, &tsshdArgs{
		KCP:            true,
		TCP:            true,
		Attachable:     false,
		Port:           "31000-65000",
		ConnectTimeout: 3 * time.Second,
	})
}

func TestProxy_KCP_Attachable(t *testing.T) {
	runProxyEchoTest(t, &tsshdArgs{
		KCP:            true,
		TCP:            false,
		Attachable:     true,
		Port:           "31000-65000",
		ConnectTimeout: 3 * time.Second,
	})
}

func TestProxy_KCP_TCP_Attachable(t *testing.T) {
	runProxyEchoTest(t, &tsshdArgs{
		KCP:            true,
		TCP:            true,
		Attachable:     true,
		Port:           "31000-65000",
		ConnectTimeout: 3 * time.Second,
	})
}

type mockFrontendConn struct {
	mu   sync.Mutex
	data [][]byte
}

type proxyTestAdapter struct {
	writeFn func([]byte) error
	flushFn func()
	getAll  func() [][]byte
}

func runProxyWriteAndCacheTest(t *testing.T, adapter *proxyTestAdapter, crypto *rotatingCrypto, checker *timeoutChecker) {
	nonceSize := crypto.NonceSize()

	// ---------- test direct WriteTo ----------
	payloads := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("kcp-test"),
	}

	for _, p := range payloads {
		buf := make([]byte, crypto.NonceSize()+len(p))
		copy(buf[crypto.NonceSize():], p)
		if err := adapter.writeFn(buf); err != nil {
			t.Fatalf("WriteTo failed: %v", err)
		}
	}

	writes := adapter.getAll()
	if len(writes) != len(payloads) {
		t.Fatalf("unexpected write count: got=%d want=%d", len(writes), len(payloads))
	}

	// Verify decryption correctness
	for i, enc := range writes {
		decBuf := make([]byte, len(enc))
		copy(decBuf, enc)

		n, err := crypto.openPacket(decBuf)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}

		if !bytes.Equal(decBuf[nonceSize:n], payloads[i]) {
			t.Fatalf("payload mismatch: got=%s want=%s", decBuf[nonceSize:n], payloads[i])
		}
	}

	// ---------- test pktCache + flush ----------
	// Simulate timeout so packets are cached instead of sent
	checker.timeoutFlag.Store(true)

	cachePayloads := [][]byte{
		[]byte("cache1"),
		[]byte("cache2"),
	}

	for _, p := range cachePayloads {
		buf := make([]byte, crypto.NonceSize()+len(p))
		copy(buf[crypto.NonceSize():], p)

		if err := adapter.writeFn(buf); err != nil {
			t.Fatalf("WriteTo failed: %v", err)
		}
	}

	// Ensure nothing new was written (still cached)
	if len(adapter.getAll()) != len(payloads) {
		t.Fatalf("cache should not flush yet")
	}

	offset := len(payloads)

	flushAndVerify := func(roundStart, roundEnd int) {
		nonceSize := crypto.NonceSize()

		for round := roundStart; round <= roundEnd; round++ {
			// Manually trigger flush
			adapter.flushFn()

			writes := adapter.getAll()
			expectedTotal := len(payloads) + (round)*len(cachePayloads)
			if len(writes) != expectedTotal {
				t.Fatalf("unexpected total writes after flush #%d: got=%d want=%d",
					round, len(writes), expectedTotal)
			}

			// Verify only the new batch sent in this round
			for i := range cachePayloads {
				enc := writes[offset]
				offset++

				decBuf := make([]byte, len(enc))
				copy(decBuf, enc)

				n, err := crypto.openPacket(decBuf)
				if err != nil {
					t.Fatalf("round %d decrypt failed: %v", round, err)
				}

				if !bytes.Equal(decBuf[nonceSize:n], cachePayloads[i]) {
					t.Fatalf("round %d payload mismatch: got=%q want=%q",
						round, decBuf[nonceSize:n], cachePayloads[i])
				}
			}
		}
	}

	// First 3 flushes
	flushAndVerify(1, 3)

	// rekey: install a new key and promote it
	if err := crypto.installKey([]byte("test key"), true); err != nil {
		t.Fatalf("install key failed: %v", err)
	}
	crypto.promoteKey(1)

	// Next 3 flushes after rekey
	flushAndVerify(4, 6)
}

func (m *mockFrontendConn) start(*serverProxy) {}

func (m *mockFrontendConn) readFrom([]byte) (int, *clientState) {
	return 0, nil
}

func (m *mockFrontendConn) writeTo(buf []byte, _ *clientState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Copy to avoid mutation from in-place encryption
	cp := make([]byte, len(buf))
	copy(cp, buf)
	m.data = append(m.data, cp)
	return nil
}

func (m *mockFrontendConn) getAll() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data
}

func TestServerProxyWriteToAndCache(t *testing.T) {
	// ---------- setup ----------
	args := &tsshdArgs{KCP: true}
	mockConn := &mockFrontendConn{}

	info := &ServerInfo{}
	proxy, err := startServerProxy(args, info, mockConn)
	if err != nil {
		t.Fatalf("startServerProxy failed: %v", err)
	}

	client := proxy.soleClient
	if client == nil {
		t.Fatalf("client is nil")
	}

	client.server.Store(&sshUdpServer{clientChecker: newTimeoutChecker(0)})

	// ---------- adapter ----------
	adapter := &proxyTestAdapter{
		writeFn: func(buf []byte) error {
			_, err := proxy.WriteTo(buf, &client.proxyAddr)
			return err
		},
		flushFn: func() {
			client.sendPacketCache(mockConn)
		},
		getAll: mockConn.getAll,
	}

	runProxyWriteAndCacheTest(t, adapter, client.kcpCrypto, client.server.Load().clientChecker)
}

type mockPacketConn struct {
	mu   sync.Mutex
	data [][]byte
}

func (m *mockPacketConn) Close() error { return nil }

func (m *mockPacketConn) Write(buf []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := make([]byte, len(buf))
	copy(cp, buf)
	m.data = append(m.data, cp)
	return nil
}

func (m *mockPacketConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (m *mockPacketConn) Consume(consumeFn func([]byte) error) error {
	return nil
}

func (m *mockPacketConn) getAll() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data
}

func TestClientProxyWriteToAndCache(t *testing.T) {
	// ---------- setup ----------
	_, pass, salt := newTestKcpConfig(t)
	kcpCrypto, err := newRotatingCrypto(nil, pass, salt, 0, 0, false)
	if err != nil {
		t.Fatalf("newRotatingCrypto failed: %v", err)
	}

	mockConn := &mockPacketConn{}

	proxy := &clientProxy{
		client:        &SshUdpClient{},
		kcpCrypto:     kcpCrypto,
		serverChecker: newTimeoutChecker(0),
	}
	proxy.backendCond = sync.NewCond(&proxy.backendMutex)
	proxy.backendConn.Store(&serverConnHolder{mockConn})

	// ---------- adapter ----------
	adapter := &proxyTestAdapter{
		writeFn: func(buf []byte) error {
			_, err := proxy.WriteTo(buf, nil)
			return err
		},
		flushFn: func() {
			proxy.sendPacketCache()
		},
		getAll: mockConn.getAll,
	}

	runProxyWriteAndCacheTest(t, adapter, proxy.kcpCrypto, proxy.serverChecker)
}
