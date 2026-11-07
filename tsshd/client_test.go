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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trzsz/smux"
)

func TestQuicStartupTimeoutCleanup(t *testing.T) {
	cert, key, err := generateCertKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"connected", "missing", "failed"} {
		t.Run(backend, func(t *testing.T) {
			sink := listenRandomUDP(t)
			defer func() { _ = sink.Close() }()
			opts := &UdpClientOptions{
				TsshdAddr: sink.LocalAddr().String(), ConnectTimeout: 100 * time.Millisecond,
				ServerInfo: &ServerInfo{ProxyKey: strings.Repeat("00", 32),
					ServerCert: hex.EncodeToString(cert), ClientCert: hex.EncodeToString(cert), ClientKey: hex.EncodeToString(key)},
			}
			proxy, err := startClientProxy(&SshUdpClient{}, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = proxy.Close() }()
			switch backend {
			case "connected":
				conn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
				if err != nil {
					t.Fatal(err)
				}
				proxy.backendConn.Store(&serverConnHolder{&udpServerConn{conn}})
			case "failed":
				conn, peer := net.Pipe()
				_ = peer.Close()
				proxy.backendConn.Store(&serverConnHolder{&tcpServerConn{conn}})
			}
			done := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectTimeout)
				_, err := newQuicClient(ctx, opts, proxy, proxy.remoteAddr)
				cancel()
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expected handshake timeout, got %v", err)
				}
			case <-time.After(time.Second):
				// Release the old implementation's deadlocked reader before failing.
				_ = proxy.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("dial did not stop even after closing the proxy")
				}
				t.Fatal("QUIC handshake timeout blocked on transport cleanup")
			}
			if !proxy.closed.Load() || proxy.backendConn.Load() != nil {
				t.Fatal("failed QUIC dial did not release its packet connection")
			}
		})
	}
}

func TestQuicConstructorHandshakeTimeout(t *testing.T) {
	cert, key, err := generateCertKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	conn := listenRandomUDP(t)
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	peer := &startupPeer{conn, block}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			// Authentication is acknowledged by startupPeer; QUIC is blackholed.
			if _, _, err := peer.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	defer func() { _ = peer.Close(); <-done }()
	opts := &UdpClientOptions{
		TsshdAddr: conn.LocalAddr().String(), ConnectTimeout: 100 * time.Millisecond,
		HeartbeatTimeout: time.Hour, IntervalTime: time.Second, AliveTimeout: time.Hour,
		ServerInfo: &ServerInfo{ProtoVer: kTsshdProtocol, Mode: kUdpModeQUIC,
			ServerID: 42, ClientID: 23, ProxyKey: strings.Repeat("00", 32),
			ServerCert: hex.EncodeToString(cert), ClientCert: hex.EncodeToString(cert), ClientKey: hex.EncodeToString(key)},
	}
	start := time.Now()
	client, err := NewSshUdpClient(opts)
	if client != nil {
		_ = client.Close()
		t.Fatal("blackholed QUIC handshake succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "quic dial") {
		t.Fatalf("expected QUIC handshake timeout after successful auth, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("constructor blocked during handshake cleanup")
	}
}

type startupPipeStream struct{ net.Conn }

func (s startupPipeStream) CloseRead() error  { return s.Close() }
func (s startupPipeStream) CloseWrite() error { return s.Close() }

type startupProtocol struct {
	protocolClient
	stream  Stream
	opening bool
	closed  chan struct{}
	once    sync.Once
}

func (p *startupProtocol) newStream(ctx context.Context) (Stream, error) {
	if p.opening {
		select {
		case <-p.closed:
			return nil, io.ErrClosedPipe
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return p.stream, nil
}

func (p *startupProtocol) Close() error {
	p.once.Do(func() {
		_ = p.stream.Close()
		close(p.closed)
	})
	return nil
}

func isStartupTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestBusStartupBlockedIO(t *testing.T) {
	for _, stage := range []string{"open", "command-write", "message-write", "response-body"} {
		t.Run(stage, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer func() { _ = peer.Close() }()
			proto := &startupProtocol{stream: startupPipeStream{conn}, opening: stage == "open", closed: make(chan struct{})}
			defer func() { _ = proto.Close() }()
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				if stage == "message-write" || stage == "response-body" {
					if _, err := recvCommand(peer); err != nil {
						return
					}
					if err := sendSuccess(startupPipeStream{peer}); err != nil {
						return
					}
				}
				if stage == "response-body" {
					var msg busMessage
					if err := recvMessage(peer, &msg); err != nil {
						return
					}
					// Send a response length but withhold the body.
					_, _ = peer.Write([]byte{0, 0, 0, 100})
				}
				<-proto.closed
			}()
			client := &SshUdpClient{protoClient: proto, connectTimeout: 100 * time.Millisecond}
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), client.connectTimeout)
			err := client.initBusStream(ctx, &UdpClientOptions{})
			cancel()
			if client.busStream != nil || !isStartupTimeout(err) {
				t.Fatalf("expected canceled %s, got stream=%v, err=%v", stage, client.busStream, err)
			}
			if time.Since(start) > time.Second {
				t.Fatalf("%s did not unblock on timeout", stage)
			}
			_ = proto.Close()
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Fatal("startup I/O did not stop")
			}
		})
	}
}

// startupPeer acknowledges transport authentication, then passes actual protocol
// packets to QUIC/KCP. It avoids process-wide server factories and cleanup hooks.
type startupPeer struct {
	net.PacketConn
	block cipher.Block
}

func (p *startupPeer) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		n, addr, err := p.PacketConn.ReadFrom(buf)
		if err != nil {
			return n, addr, err
		}

		data := aesDecrypt(&p.block, buf[:n])
		if len(data) == 16 {
			binary.BigEndian.PutUint64(data[:8], 42)

			// Authentication ACK is encrypted.
			if _, err := p.WriteTo(aesEncrypt(&p.block, data), addr); err != nil {
				return 0, nil, err
			}
			continue
		}

		// QUIC/KCP packets are not encrypted by the UDP proxy.
		return n, addr, nil
	}
}

func (p *startupPeer) SetReadBuffer(bytes int) error {
	return nil
}

func (p *startupPeer) SetWriteBuffer(bytes int) error {
	return nil
}

func newStartupServer(t *testing.T, mode string, handle func(Stream) error) (*UdpClientOptions, <-chan error) {
	t.Helper()
	conn := listenRandomUDP(t)
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	peer := &startupPeer{conn, block}
	info := &ServerInfo{ProtoVer: kTsshdProtocol, ProxyKey: strings.Repeat("00", 32), ServerID: 42, ClientID: 23}
	var accept func() (Stream, func(), error)
	var closeListener func() error
	if mode == kUdpModeQUIC {
		listener, _, err := listenQUIC(peer, info, 0)
		if err != nil {
			t.Fatal(err)
		}
		closeListener = listener.Close
		accept = func() (Stream, func(), error) {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return nil, nil, err
			}
			closeConn := func() { _ = conn.CloseWithError(0, "") }
			stream, err := conn.AcceptStream(context.Background())
			return &quicStream{stream, conn}, closeConn, err
		}
	} else {
		crypto, err := newKcpServerCrypto(info, false)
		if err != nil {
			t.Fatalf("newKcpServerCrypto failed: %v", err)
		}
		listener, err := listenKCP(peer, crypto)
		if err != nil {
			t.Fatal(err)
		}
		closeListener = func() error { crypto.Close(); return listener.Close() }
		accept = func() (Stream, func(), error) {
			conn, err := listener.AcceptKCP()
			if err != nil {
				return nil, nil, err
			}
			session, err := smux.Server(conn, &smuxConfig)
			if err != nil {
				_ = conn.Close()
				return nil, nil, err
			}
			closeConn := func() { _ = session.Close() }
			stream, err := session.AcceptStream()
			return &smuxStream{stream}, closeConn, err
		}
	}
	finished := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		defer close(finished)
		stream, closeConn, err := accept()
		if closeConn != nil {
			defer closeConn()
		}
		if err == nil {
			defer func() { _ = stream.Close() }()
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			err = handle(stream)
		}
		result <- err
	}()
	t.Cleanup(func() {
		_ = peer.Close()
		_ = closeListener()
		select {
		case <-finished:
		case <-time.After(4 * time.Second):
			t.Error("startup server did not stop")
		}
	})
	return &UdpClientOptions{TsshdAddr: conn.LocalAddr().String(), ServerInfo: info,
		ConnectTimeout: time.Second, HeartbeatTimeout: time.Hour,
		IntervalTime: 300 * time.Millisecond, AliveTimeout: time.Hour}, result
}

func TestBusStartupTimeout(t *testing.T) {
	for _, mode := range []string{kUdpModeQUIC, kUdpModeKCP} {
		for _, stage := range []string{"command", "response"} {
			t.Run(mode+"/"+stage, func(t *testing.T) {
				ready := make(chan struct{})
				opts, _ := newStartupServer(t, mode, func(stream Stream) error {
					cmd, err := recvCommand(stream)
					if err != nil || cmd != "bus" {
						return fmt.Errorf("expected bus command: %q, %v", cmd, err)
					}
					if stage == "response" {
						if err := sendSuccess(stream); err != nil {
							return err
						}
						var msg busMessage
						if err := recvMessage(stream, &msg); err != nil {
							return err
						}
					}
					close(ready)
					_, err = io.Copy(io.Discard, stream)
					return err
				})
				start := time.Now()
				client, err := NewSshUdpClient(opts)
				if client != nil {
					_ = client.Close()
					t.Fatal("startup unexpectedly succeeded")
				}
				select {
				case <-ready:
				default:
					t.Fatalf("did not reach %s: %v", stage, err)
				}
				if elapsed := time.Since(start); elapsed > 2*opts.ConnectTimeout {
					t.Fatalf("bus %s did not return promptly after timeout: %v (%v)", stage, elapsed, err)
				}
				if !isStartupTimeout(err) {
					t.Fatalf("expected startup timeout, got %v", err)
				}
			})
		}
	}
}

func TestBusStartupTimeoutCleared(t *testing.T) {
	for _, mode := range []string{kUdpModeQUIC, kUdpModeKCP} {
		t.Run(mode, func(t *testing.T) {
			opts, result := newStartupServer(t, mode, func(stream Stream) error {
				if _, err := recvCommand(stream); err != nil {
					return err
				}
				if err := sendSuccess(stream); err != nil {
					return err
				}
				var msg busMessage
				if err := recvMessage(stream, &msg); err != nil {
					return err
				}
				if err := sendResponse(stream, &busResponse{NextSessionID: 7}); err != nil {
					return err
				}
				// Exercise a bus event arriving before the constructor has returned.
				if err := sendCommandAndMessage(stream, "alive", aliveMessage{Time: 1}); err != nil {
					return err
				}
				for {
					cmd, err := recvCommand(stream)
					if err != nil || cmd == "close" {
						return err
					}
					if cmd == "rekey" {
						// This peer keeps using the initial key during the test.
						var rekey rekeyMessage
						if err := recvMessage(stream, &rekey); err != nil {
							return err
						}
						continue
					}
					if cmd != "alive" {
						return fmt.Errorf("unexpected bus command %q", cmd)
					}
					var alive aliveMessage
					if err := recvMessage(stream, &alive); err != nil {
						return err
					}
					if err := sendCommandAndMessage(stream, "alive", alive); err != nil {
						return err
					}
				}
			})
			alive := make(chan struct{}, 1)
			opts.RttCallback = func(int64) {
				select {
				case alive <- struct{}{}:
				default:
				}
			}
			client, err := NewSshUdpClient(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			if client.sessionID.Load() != 7 {
				t.Fatal("bus response was not applied")
			}
			select {
			case <-alive:
				// Initial bus event was processed.
			case <-time.After(time.Second):
				t.Fatal("initial bus event was not processed")
			}
			// Wait until the startup deadline has passed, then require a fresh
			// heartbeat round trip to prove the stream deadline was cleared.
			time.Sleep(opts.ConnectTimeout + opts.IntervalTime)
			for {
				select {
				case <-alive:
				default:
					goto drained
				}
			}
		drained:
			select {
			case <-alive:
			case err := <-result:
				t.Fatalf("server stopped before heartbeat: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("bus did not survive its startup timeout")
			}
			_ = client.Close()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("server did not observe client close")
			}
		})
	}
}

func TestQuicRemoteCloseCleanup(t *testing.T) {
	release := make(chan struct{})
	opts, _ := newStartupServer(t, kUdpModeQUIC, func(stream Stream) error {
		if _, err := recvCommand(stream); err != nil {
			return err
		}
		if err := sendSuccess(stream); err != nil {
			return err
		}
		var msg busMessage
		if err := recvMessage(stream, &msg); err != nil {
			return err
		}
		if err := sendResponse(stream, &busResponse{NextSessionID: 1}); err != nil {
			return err
		}
		<-release
		return nil
	})
	client, err := NewSshUdpClient(opts)
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	select {
	case <-client.protoClient.(*quicClient).closed:
	case <-time.After(time.Second):
		t.Fatal("remote QUIC closure did not stop the transport reader")
	}
	if !client.clientProxy.closed.Load() || client.clientProxy.backendConn.Load() != nil {
		t.Fatal("remote QUIC closure did not release the proxy")
	}
}

func TestBusStartupRekeyCanceled(t *testing.T) {
	client := &SshUdpClient{}
	crypto := &rotatingCrypto{client: client, stopCh: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- crypto.doRekey() }()
	crypto.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("expected canceled rekey, got %v", err)
		}
	case <-time.After(time.Second):
		// Unblock the old implementation before reporting its leaked startup wait.
		conn, peer := net.Pipe()
		_ = peer.Close()
		defer func() { _ = conn.Close() }()
		client.busMutex.Lock()
		client.busStream = startupPipeStream{conn}
		client.busMutex.Unlock()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("rekey did not stop even after publishing a closed bus")
		}
		t.Fatal("rekey kept waiting for the bus after startup cleanup")
	}
}

func TestBusStartupUsesSingleDeadline(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	proto := &startupProtocol{stream: startupPipeStream{conn}, closed: make(chan struct{})}
	defer func() { _ = proto.Close() }()

	const timeout = 200 * time.Millisecond
	delay := timeout * 6 / 10
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if _, err := recvCommand(peer); err != nil {
			return
		}
		time.Sleep(delay)
		if err := sendSuccess(startupPipeStream{peer}); err != nil {
			return
		}
		var msg busMessage
		if err := recvMessage(peer, &msg); err != nil {
			return
		}
		time.Sleep(delay)
		_ = sendResponse(startupPipeStream{peer}, &busResponse{})
	}()

	client := &SshUdpClient{protoClient: proto, connectTimeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	err := client.initBusStream(ctx, &UdpClientOptions{})
	if client.busStream != nil {
		_ = client.busStream.Close()
	}
	if err == nil {
		t.Fatal("startup succeeded even though its phases exceeded the shared deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected startup deadline error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("startup did not stop after the shared deadline: %v", elapsed)
	}
	_ = proto.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not stop after startup cancellation")
	}
}

func TestNewStreamClearsStartupDeadline(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	proto := &startupProtocol{stream: startupPipeStream{conn}, closed: make(chan struct{})}
	defer func() { _ = proto.Close() }()

	const timeout = 100 * time.Millisecond
	serverDone := make(chan error, 1)
	go func() {
		if _, err := recvCommand(peer); err != nil {
			serverDone <- err
			return
		}
		if err := sendSuccess(startupPipeStream{peer}); err != nil {
			serverDone <- err
			return
		}
		var b [1]byte
		_, err := io.ReadFull(peer, b[:])
		serverDone <- err
	}()

	client := &SshUdpClient{protoClient: proto, connectTimeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	stream, err := client.newStream(ctx, "session", nil)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()

	// The stream must remain usable after the startup deadline has elapsed.
	time.Sleep(timeout * 2)
	if _, err := stream.Write([]byte{1}); err != nil {
		t.Fatalf("stream retained its startup deadline: %v", err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive data after startup deadline")
	}
}

type startupResource struct {
	closed chan struct{}
	once   sync.Once
}

func (r *startupResource) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func TestDoWithContextClosesLateResource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	resource := &startupResource{closed: make(chan struct{})}

	done := make(chan error, 1)
	go func() {
		_, err := doWithContext(ctx, func() (*startupResource, error) {
			close(started)
			<-release
			return resource, nil
		})
		done <- err
	}()

	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	close(release)
	select {
	case <-resource.closed:
	case <-time.After(time.Second):
		t.Fatal("late resource was not closed")
	}
}

func TestStreamCommandAckDeadline(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	proto := &startupProtocol{stream: startupPipeStream{conn}, closed: make(chan struct{})}
	defer func() { _ = proto.Close() }()
	go func() {
		_, _ = recvCommand(peer)
		<-proto.closed // never acknowledge
	}()
	client := &SshUdpClient{protoClient: proto, connectTimeout: 100 * time.Millisecond}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), client.connectTimeout)
	if _, err := client.newStream(ctx, "session", nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected command ack deadline, got %v", err)
	}
	cancel()
	if time.Since(start) > time.Second {
		t.Fatal("command ack did not honor ConnectTimeout")
	}
}

func TestDialUsesSingleTimeoutBudget(t *testing.T) {
	const (
		timeout     = 800 * time.Millisecond
		setupDelay  = 250 * time.Millisecond
		maxDuration = timeout + setupDelay/2
	)

	conn, peer := net.Pipe()
	defer func() { _ = peer.Close() }()

	proto := &startupProtocol{
		stream: startupPipeStream{conn},
		closed: make(chan struct{}),
	}
	defer func() { _ = proto.Close() }()

	client := &SshUdpClient{
		protoClient:    proto,
		connectTimeout: timeout,
	}

	type serverResult struct {
		msg dialMessage
		err error
	}
	serverDone := make(chan serverResult, 1)

	go func() {
		stream := startupPipeStream{peer}

		cmd, err := recvCommand(stream)
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		if cmd != "dial" {
			serverDone <- serverResult{
				err: fmt.Errorf("unexpected command: %s", cmd),
			}
			return
		}

		// Consume part of the timeout while waiting for the command ACK.
		time.Sleep(setupDelay)

		if err := sendSuccess(stream); err != nil {
			serverDone <- serverResult{err: err}
			return
		}

		var msg dialMessage
		if err := recvMessage(stream, &msg); err != nil {
			serverDone <- serverResult{err: err}
			return
		}

		// Deliberately do not send a response. The client should time out
		// using the original deadline, not a renewed timeout.
		serverDone <- serverResult{msg: msg}
	}()

	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	_, err := client.dialContext("tcp", "example.com:22", ctx)
	cancel()

	elapsed := time.Since(start)

	if !isStartupTimeout(err) {
		t.Fatalf("expected dial timeout, got %v", err)
	}

	if elapsed > maxDuration {
		t.Fatalf("dial exceeded the original timeout: elapsed=%v, timeout=%v",
			elapsed, timeout)
	}

	select {
	case result := <-serverDone:
		if result.err != nil {
			t.Fatalf("server failed: %v", result.err)
		}

		if result.msg.Timeout <= 0 {
			t.Fatalf("expected positive remaining timeout, got %v",
				result.msg.Timeout)
		}

		if result.msg.Timeout >= timeout-setupDelay/2 {
			t.Fatalf("dial message did not use the remaining timeout: got %v, total=%v",
				result.msg.Timeout, timeout)
		}

	case <-time.After(time.Second):
		t.Fatal("server did not receive dial message")
	}
}
