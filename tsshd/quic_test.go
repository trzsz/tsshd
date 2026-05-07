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
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
	_ "unsafe"
)

//go:linkname estimateMaxPayloadSize github.com/quic-go/quic-go.estimateMaxPayloadSize
func estimateMaxPayloadSize(mtu int64) int64

type udpPacketConn struct {
	conn net.PacketConn
}

func (c *udpPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	return c.conn.ReadFrom(buf)
}

func (c *udpPacketConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	return c.conn.WriteTo(buf, addr)
}

func (c *udpPacketConn) Close() error {
	return c.conn.Close()
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *udpPacketConn) SetReadBuffer(bytes int) error {
	return nil
}

func (c *udpPacketConn) SetWriteBuffer(bytes int) error {
	return nil
}

func listenRandomUDP(t *testing.T) *udpPacketConn {
	const addr = "127.0.0.1:0"

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("failed to resolve UDP address %q: %v", addr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to listen on UDP address %q: %v", addr, err)
	}

	return &udpPacketConn{conn}
}

// TestQUIC_InitialPacketSize verifies that QUIC packet size selection clamps
// the requested MTU to the valid MTU range without mutating the shared base
// quicConfig.
func TestQUIC_InitialPacketSize(t *testing.T) {
	verifyInitialPacketSize := func(requestedMTU, expectedMTU uint16) {
		info := &ServerInfo{MTU: requestedMTU}
		svrConn := listenRandomUDP(t)
		defer func() { _ = svrConn.Close() }()
		cliConn := listenRandomUDP(t)
		defer func() { _ = cliConn.Close() }()

		// Server
		quicConfig.InitialPacketSize = 0
		listener, serverInitialPacketSize, err := listenQUIC(svrConn, info, requestedMTU)
		if err != nil {
			t.Fatalf("listenQUIC failed (mtu=%d): %v", requestedMTU, err)
		}

		if serverInitialPacketSize != expectedMTU {
			t.Fatalf("server initial packet size mismatch: requested=%d, expected=%d, got=%d", requestedMTU, expectedMTU, serverInitialPacketSize)
		}
		if got := quicConfig.InitialPacketSize; got != 0 {
			t.Fatalf("shared quicConfig should not be mutated by listenQUIC, got InitialPacketSize=%d", got)
		}

		acceptDone := make(chan struct{})
		go func() {
			defer func() { _ = listener.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			conn, err := listener.Accept(ctx)
			if err != nil {
				t.Errorf("server accept failed: %v", err)
			} else {
				_ = conn.CloseWithError(0, "")
			}
			close(acceptDone)
		}()

		// Client
		quicConfig.InitialPacketSize = 0
		client, err := newQuicClient(&UdpClientOptions{
			ServerInfo:     info,
			ProxyClient:    &SshUdpClient{},
			ConnectTimeout: 10 * time.Second,
		}, cliConn, svrConn.LocalAddr())
		if err != nil {
			t.Fatalf("newQuicClient failed (mtu=%d): %v", requestedMTU, err)
		}
		if got := client.forwarder.conn.GetMaxDatagramSize() + kQuicShortHeaderSize + kUdpForwardChannelIdSize; got != expectedMTU {
			t.Fatalf("client initial packet size mismatch: requested=%d, expected=%d, got=%d", requestedMTU, expectedMTU, got)
		}
		<-acceptDone
		_ = client.closeClient()

		if got := quicConfig.InitialPacketSize; got != 0 {
			t.Fatalf("shared quicConfig should not be mutated, got InitialPacketSize=%d", got)
		}
	}

	// MTU below min
	verifyInitialPacketSize(kQuicMinMTU-1, kQuicMinMTU)

	// Default MTU
	verifyInitialPacketSize(kDefaultMTU, kDefaultMTU)

	// MTU above max
	verifyInitialPacketSize(kQuicMaxMTU+1, kQuicMaxMTU)
}

// TestQUIC_ShortHeaderSize ensures that the constant kQuicShortHeaderSize
// correctly represents the size of a QUIC short header for all supported MTU values.
//
// NOTE: If this test fails, it means kQuicShortHeaderSize is incorrect and
// should be updated to match the actual short header size used by QUIC.
func TestQUIC_ShortHeaderSize(t *testing.T) {
	for mtu := int64(kQuicMinMTU); mtu <= kQuicMaxMTU; mtu++ {
		expected := mtu - kQuicShortHeaderSize
		if got := estimateMaxPayloadSize(mtu); got != expected {
			t.Fatalf(
				"kQuicShortHeaderSize mismatch: for MTU=%d, expected max payload=%d, got=%d. "+
					"Update kQuicShortHeaderSize to match QUIC short header size.",
				mtu,
				expected,
				got,
			)
		}
	}
}

type mtuTestConn struct {
	*udpPacketConn
	t   *testing.T
	mtu int
	cnt atomic.Int32
}

func (c *mtuTestConn) ReadFrom(buf []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.conn.ReadFrom(buf)
	if err != nil {
		return
	}
	if n > c.mtu {
		c.t.Fatalf("received datagram size %d exceeds MTU %d", n, c.mtu)
	}
	c.cnt.Add(1)
	return
}

func (c *mtuTestConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	if len(buf) > c.mtu {
		c.t.Fatalf("datagram size %d exceeds MTU %d", len(buf), c.mtu)
	}
	c.cnt.Add(1)
	return c.conn.WriteTo(buf, addr)
}

func TestQUIC_RespectMTU(t *testing.T) {
	const mtu = 1400
	const streamSize = mtu * 5

	info := &ServerInfo{MTU: mtu}
	svrConn := &mtuTestConn{udpPacketConn: listenRandomUDP(t), t: t, mtu: mtu}
	defer func() { _ = svrConn.Close() }()

	listener, _, err := listenQUIC(svrConn, info, mtu)
	if err != nil {
		t.Fatalf("listenQUIC failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverErrCh := make(chan error, 1)
	clientErrCh := make(chan error, 1)

	// ----------------- server -----------------
	go func() {
		defer close(serverErrCh)
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErrCh <- fmt.Errorf("server failed to accept QUIC connection: %w", err)
			return
		}
		defer func() { _ = conn.CloseWithError(0, "") }()

		// accept one stream
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErrCh <- fmt.Errorf("server failed to accept stream: %w", err)
			return
		}
		defer func() { _ = stream.Close() }()

		// stream echo loop
		streamErrCh := make(chan error, 1)
		go func() {
			defer close(streamErrCh)
			buf := make([]byte, 32*1024)
			for {
				n, err := stream.Read(buf)
				if err != nil {
					if isClosedError(err) {
						return
					}
					streamErrCh <- fmt.Errorf("server stream read error: %w", err)
					return
				}
				if _, err := stream.Write(buf[:n]); err != nil {
					streamErrCh <- fmt.Errorf("server stream write error: %w", err)
					return
				}
			}
		}()

		// datagram echo loop
		datagramErrCh := make(chan error, 1)
		go func() {
			defer close(datagramErrCh)
			for {
				buf, err := conn.ReceiveDatagram(ctx)
				if err != nil {
					if ctx.Err() != nil {
						datagramErrCh <- nil
					} else {
						datagramErrCh <- fmt.Errorf("server datagram receive error: %w", err)
					}
					return
				}
				if err := conn.SendDatagram(buf); err != nil {
					datagramErrCh <- fmt.Errorf("server datagram send error: %w", err)
					return
				}
			}
		}()

		// stream loop must terminate cleanly
		if err := <-streamErrCh; err != nil {
			serverErrCh <- err
			return
		}

		// datagram loop may end due to context done
		select {
		case err := <-datagramErrCh:
			if err != nil {
				serverErrCh <- err
			}
		case <-ctx.Done():
		}
	}()

	// ----------------- client -----------------
	go func() {
		defer close(clientErrCh)

		cliConn := listenRandomUDP(t)
		defer func() { _ = cliConn.Close() }()
		client, err := newQuicClient(&UdpClientOptions{
			ServerInfo:     info,
			ProxyClient:    &SshUdpClient{},
			ConnectTimeout: 3 * time.Second,
		}, cliConn, svrConn.LocalAddr())
		if err != nil {
			clientErrCh <- fmt.Errorf("client failed to dial QUIC server: %w", err)
			return
		}
		defer func() { _ = client.closeClient() }()

		data := make([]byte, streamSize)
		for i := range data {
			data[i] = byte(i)
		}

		// stream traffic
		streamErrCh := make(chan error, 1)
		go func() {
			defer close(streamErrCh)
			stream, err := client.conn.OpenStreamSync(ctx)
			if err != nil {
				streamErrCh <- fmt.Errorf("client failed to open stream: %w", err)
				return
			}
			defer func() { _ = stream.Close() }()

			if _, err := stream.Write(data); err != nil {
				streamErrCh <- fmt.Errorf("client stream write error: %w", err)
				return
			}

			echo := make([]byte, streamSize)
			if _, err := io.ReadFull(stream, echo); err != nil {
				streamErrCh <- fmt.Errorf("client stream read error: %w", err)
				return
			}
			if !bytes.Equal(data, echo) {
				streamErrCh <- fmt.Errorf("stream echo data mismatch")
				return
			}
		}()

		// datagram payload limit (excluding QUIC short header)
		size := mtu - kQuicShortHeaderSize

		// oversized datagram must be rejected by QUIC
		if err := client.conn.SendDatagram(data[:size+1]); err == nil {
			clientErrCh <- fmt.Errorf("expected oversized datagram to be rejected, but send succeeded")
			return
		}

		// valid datagrams must be echoed correctly
		for range 100 {
			packet := data[:size]
			if err := client.conn.SendDatagram(packet); err != nil {
				clientErrCh <- fmt.Errorf("client datagram send error: %w", err)
				return
			}
			resp, err := client.conn.ReceiveDatagram(ctx)
			if err != nil {
				clientErrCh <- fmt.Errorf("client datagram receive error: %w", err)
				return
			}
			if !bytes.Equal(packet, resp) {
				clientErrCh <- fmt.Errorf("datagram echo data mismatch")
				return
			}
		}

		// stream traffic must be echoed correctly
		if err := <-streamErrCh; err != nil {
			clientErrCh <- err
			return
		}

		clientErrCh <- nil
	}()

	// ----------------- wait for completion -----------------
	select {
	case err := <-serverErrCh:
		if err != nil {
			t.Fatalf("server failure: %v", err)
		}
	case err := <-clientErrCh:
		if err != nil {
			t.Fatalf("client failure: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("test timed out")
	}

	// sanity check: ensure UDP layer was exercised sufficiently.
	if got := svrConn.cnt.Load(); got < 300 {
		t.Fatalf("insufficient UDP traffic observed: cnt=%d", got)
	}
}

func TestQUIC_CertValidation(t *testing.T) {
	info := ServerInfo{}
	svrConn := listenRandomUDP(t)
	defer func() { _ = svrConn.Close() }()

	// Start QUIC server
	listener, _, err := listenQUIC(svrConn, &info, 0)
	if err != nil {
		t.Fatalf("listenQUIC failed: %v", err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		defer close(serverErrCh)
		defer func() { _ = listener.Close() }()

		// The server intentionally accepts ONLY ONCE.
		// If an invalid client is accepted here, the valid case must fail later.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErrCh <- fmt.Errorf("server failed to accept QUIC connection: %w", err)
			return
		}
		defer func() { _ = conn.CloseWithError(0, "") }()

		// Immediately close any additional accepted connections so that
		// only the intended connection is used in this test.
		go func() {
			for {
				if conn, err := listener.Accept(context.Background()); err == nil {
					_ = conn.CloseWithError(0, "")
				}
			}
		}()

		// accept one stream
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErrCh <- fmt.Errorf("server failed to accept stream: %w", err)
			return
		}
		defer func() { _ = stream.Close() }()

		// stream echo loop
		buf := make([]byte, 1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if isClosedError(err) {
					return
				}
				serverErrCh <- fmt.Errorf("server stream read error: %w", err)
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				serverErrCh <- fmt.Errorf("server stream write error: %w", err)
				return
			}
		}
	}()

	// Case 1: Invalid client certificate
	illegalInfo := info
	illegalCertPEM, illegalKeyPEM, err := generateCertKeyPair()
	if err != nil {
		t.Fatalf("generateCertKeyPair failed: %v", err)
	}
	illegalInfo.ClientCert = fmt.Sprintf("%x", illegalCertPEM)
	illegalInfo.ClientKey = fmt.Sprintf("%x", illegalKeyPEM)
	// The client does not know whether it failed, so we don't assert here.
	// If it happens to succeed, case 3 (valid certificates) will fail later.
	cliConn1 := listenRandomUDP(t)
	defer func() { _ = cliConn1.Close() }()
	_, _ = newQuicClient(&UdpClientOptions{ServerInfo: &illegalInfo, ConnectTimeout: 3 * time.Second}, cliConn1, svrConn.LocalAddr())

	// Case 2: Invalid server certificate
	illegalInfo = info
	illegalInfo.ServerCert = fmt.Sprintf("%x", illegalCertPEM)
	cliConn2 := listenRandomUDP(t)
	defer func() { _ = cliConn2.Close() }()
	_, err = newQuicClient(&UdpClientOptions{ServerInfo: &illegalInfo, ConnectTimeout: 3 * time.Second}, cliConn2, svrConn.LocalAddr())
	if err == nil {
		t.Fatalf("Client should not succeed with invalid server certificate")
	}

	// Case 3: Valid client and server certificates
	cliConn3 := listenRandomUDP(t)
	defer func() { _ = cliConn3.Close() }()
	client, err := newQuicClient(&UdpClientOptions{ServerInfo: &info, ConnectTimeout: 3 * time.Second}, cliConn3, svrConn.LocalAddr())
	if err != nil {
		// If this fails, it could be because case 1 succeeded with an invalid client certificate.
		t.Fatalf("Valid client certificate should succeed: %v", err)
	}
	defer func() { _ = client.closeClient() }()

	// Open a stream to ensure that:
	// 1. the QUIC handshake has completed successfully
	// 2. TLS certificate validation passed
	// 3. application data can be exchanged over the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("client failed to open stream: %v", err)
	}
	defer func() { _ = stream.Close() }()

	data := []byte("message from valid client")
	if _, err := stream.Write(data); err != nil {
		t.Fatalf("client stream write error: %v", err)
	}

	echo := make([]byte, len(data))
	if _, err := io.ReadFull(stream, echo); err != nil {
		t.Fatalf("client stream read error: %v", err)
	}
	if !bytes.Equal(data, echo) {
		t.Fatalf("stream echo data mismatch")
	}

	// Wait for completion
	_ = stream.Close()
	select {
	case err := <-serverErrCh:
		if err != nil {
			t.Fatalf("server failure: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("test timed out")
	}
}
