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
			defer sink.Close()
			opts := &UdpClientOptions{
				TsshdAddr: sink.LocalAddr().String(), ConnectTimeout: 100 * time.Millisecond,
				ServerInfo: &ServerInfo{ProxyKey: strings.Repeat("00", 32),
					ServerCert: hex.EncodeToString(cert), ClientCert: hex.EncodeToString(cert), ClientKey: hex.EncodeToString(key)},
			}
			proxy, err := startClientProxy(&SshUdpClient{}, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
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
				_, err := newQuicClient(opts, proxy, proxy.remoteAddr)
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

func (p *startupProtocol) newStream(time.Duration) (Stream, error) {
	if p.opening {
		<-p.closed
		return nil, io.ErrClosedPipe
	}
	return p.stream, nil
}

func (p *startupProtocol) closeClient() error {
	p.once.Do(func() {
		_ = p.stream.Close()
		close(p.closed)
	})
	return nil
}

func TestBusStartupBlockedIO(t *testing.T) {
	for _, stage := range []string{"open", "command-write", "message-write", "response-body"} {
		t.Run(stage, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer peer.Close()
			proto := &startupProtocol{stream: startupPipeStream{conn}, opening: stage == "open", closed: make(chan struct{})}
			defer proto.closeClient()
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
			stream, _, err := client.initBusStream(&UdpClientOptions{ConnectTimeout: client.connectTimeout})
			if stream != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected canceled %s, got stream=%v, err=%v", stage, stream, err)
			}
			if time.Since(start) > time.Second {
				t.Fatalf("%s did not unblock on timeout", stage)
			}
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
		if data := aesDecrypt(&p.block, buf[:n]); len(data) == 16 {
			binary.BigEndian.PutUint64(data[:8], 42)
			if _, err := p.WriteTo(aesEncrypt(&p.block, data), addr); err != nil {
				return 0, nil, err
			}
			continue
		}
		return n, addr, nil
	}
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
		listener, crypto, err := listenKCP(peer, info, false)
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
			defer stream.Close()
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
		ConnectTimeout: 150 * time.Millisecond, HeartbeatTimeout: time.Hour,
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
				if time.Since(start) > time.Second {
					t.Fatalf("bus %s exceeded connection timeout: %v", stage, err)
				}
				if !errors.Is(err, context.DeadlineExceeded) {
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
			defer client.Close()
			if client.sessionID.Load() != 7 {
				t.Fatal("bus response was not applied")
			}
			select {
			case ack := <-client.activeAckChan:
				if ack != 1 {
					t.Fatalf("unexpected initial bus event: %d", ack)
				}
			case <-time.After(time.Second):
				t.Fatal("initial bus event blocked on an unpublished acknowledgement channel")
			}
			// The first heartbeat is sent after twice ConnectTimeout. Both directions
			// must still work, and the startup cancellation must no longer be armed.
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
	defer client.Close()
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
		defer conn.Close()
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

func TestBusStartupPhasesHaveSeparateBudgets(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	proto := &startupProtocol{stream: startupPipeStream{conn}, closed: make(chan struct{})}
	defer proto.closeClient()
	const timeout = 200 * time.Millisecond
	// Each phase takes ~60% of ConnectTimeout: together they exceed one budget.
	delay := timeout * 6 / 10
	go func() {
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
	stream, _, err := client.initBusStream(&UdpClientOptions{ConnectTimeout: timeout})
	if err != nil || stream == nil {
		t.Fatalf("expected startup within two per-phase budgets, got stream=%v, err=%v", stream, err)
	}
}

func TestStreamCommandAckDeadline(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	proto := &startupProtocol{stream: startupPipeStream{conn}, closed: make(chan struct{})}
	defer proto.closeClient()
	go func() {
		_, _ = recvCommand(peer)
		<-proto.closed // never acknowledge
	}()
	client := &SshUdpClient{protoClient: proto, connectTimeout: 100 * time.Millisecond}
	start := time.Now()
	if _, err := client.newStream("session"); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected command ack deadline, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("command ack did not honor ConnectTimeout")
	}
}

func TestDialResponseDeadline(t *testing.T) {
	for _, withTimeout := range []bool{true, false} {
		t.Run(fmt.Sprintf("timeout=%v", withTimeout), func(t *testing.T) {
			conn, peer := net.Pipe()
			defer peer.Close()
			client := &SshUdpClient{connectTimeout: 50 * time.Millisecond}
			go func() {
				var msg dialMessage
				_ = recvMessage(peer, &msg)
				// never respond
			}()
			stream := startupPipeStream{conn}
			dialTimeout := time.Duration(0)
			if withTimeout {
				dialTimeout = 50 * time.Millisecond
			}
			defer client.setDialDeadline(stream, dialTimeout)()
			_ = sendMessage(stream, &dialMessage{Net: "tcp", Addr: "x:1"})
			done := make(chan error, 1)
			go func() {
				var resp dialResponse
				done <- recvResponse(stream, &resp)
			}()
			select {
			case err := <-done:
				if !withTimeout || !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("unexpected dial response result: %v", err)
				}
			case <-time.After(500 * time.Millisecond):
				if withTimeout {
					t.Fatal("dial response did not honor dial timeout + ConnectTimeout")
				}
				_ = conn.Close()
			}
		})
	}
}
