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

func listenRandomUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	const addr = "127.0.0.1:0"

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("failed to resolve UDP address %q: %v", addr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("failed to listen on UDP address %q: %v", addr, err)
	}

	return conn
}

// TestQUIC_InitialPacketSize verifies that listenQUIC clamps
// quicConfig.InitialPacketSize to the valid MTU range.
//
// NOTE: newQuicDatagramConn relies on quicConfig.InitialPacketSize being
// adjusted by quic during listener initialization. If quic does not perform
// this adjustment, newQuicDatagramConn must be updated accordingly.
func TestQUIC_InitialPacketSize(t *testing.T) {
	verifyInitialPacketSize := func(requestedMTU, expectedMTU uint16) {
		t.Helper()

		info := &ServerInfo{}
		conn := listenRandomUDP(t)
		defer func() { _ = conn.Close() }()

		// Server
		quicConfig.InitialPacketSize = 0
		listener, err := listenQUIC(conn, info, requestedMTU)
		if err != nil {
			t.Fatalf("listenQUIC failed (mtu=%d): %v", requestedMTU, err)
		}

		if got := quicConfig.InitialPacketSize; got != expectedMTU {
			t.Fatalf("InitialPacketSize mismatch: requested=%d, expected=%d, got=%d", requestedMTU, expectedMTU, got)
		}

		acceptDone := make(chan struct{})
		go func() {
			defer func() { _ = listener.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
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
		client, err := newQuicClient(conn.LocalAddr().String(), info, requestedMTU, time.Second)
		if err != nil {
			t.Fatalf("newQuicClient failed (mtu=%d): %v", requestedMTU, err)
		}
		_ = client.closeClient()

		<-acceptDone

		if got := quicConfig.InitialPacketSize; got != expectedMTU {
			t.Fatalf("InitialPacketSize mismatch: requested=%d, expected=%d, got=%d", requestedMTU, expectedMTU, got)
		}
	}

	// Default MTU
	verifyInitialPacketSize(kDefaultMTU, kDefaultMTU)

	// MTU above max
	verifyInitialPacketSize(kQuicMaxMTU+1, kQuicMaxMTU)

	// MTU below min
	verifyInitialPacketSize(kQuicMinMTU-1, kQuicMinMTU)
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

type udpTestConn struct {
	t    *testing.T
	conn net.PacketConn
	mtu  int
	cnt  atomic.Int32
}

func (u *udpTestConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = u.conn.ReadFrom(p)
	if err != nil {
		return
	}
	if n > u.mtu {
		u.t.Fatalf("received datagram size %d exceeds MTU %d", n, u.mtu)
	}
	u.cnt.Add(1)
	return
}

func (u *udpTestConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) > u.mtu {
		u.t.Fatalf("datagram size %d exceeds MTU %d", len(p), u.mtu)
	}
	u.cnt.Add(1)
	return u.conn.WriteTo(p, addr)
}

func (u *udpTestConn) Close() error                       { return u.conn.Close() }
func (u *udpTestConn) LocalAddr() net.Addr                { return u.conn.LocalAddr() }
func (u *udpTestConn) SetDeadline(t time.Time) error      { return u.conn.SetDeadline(t) }
func (u *udpTestConn) SetReadDeadline(t time.Time) error  { return u.conn.SetReadDeadline(t) }
func (u *udpTestConn) SetWriteDeadline(t time.Time) error { return u.conn.SetWriteDeadline(t) }
func (c *udpTestConn) SetReadBuffer(bytes int) error      { return nil }
func (c *udpTestConn) SetWriteBuffer(bytes int) error     { return nil }

func TestQUIC_RespectMTU(t *testing.T) {
	const mtu = 1400
	const streamSize = mtu * 5

	info := &ServerInfo{}
	conn := &udpTestConn{t: t, conn: listenRandomUDP(t), mtu: mtu}
	defer func() { _ = conn.Close() }()

	listener, err := listenQUIC(conn, info, mtu)
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
		client, err := newQuicClient(conn.LocalAddr().String(), info, mtu, time.Second)
		if err != nil {
			clientErrCh <- fmt.Errorf("client failed to dial QUIC server: %w", err)
			return
		}
		defer func() { _ = client.closeClient() }()
		c := client.(*quicClient).conn

		data := make([]byte, streamSize)
		for i := range data {
			data[i] = byte(i)
		}

		// stream traffic
		streamErrCh := make(chan error, 1)
		go func() {
			defer close(streamErrCh)
			stream, err := c.OpenStreamSync(ctx)
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
		if err := c.SendDatagram(data[:size+1]); err == nil {
			clientErrCh <- fmt.Errorf("expected oversized datagram to be rejected, but send succeeded")
			return
		}

		// valid datagrams must be echoed correctly
		for range 100 {
			packet := data[:size]
			if err := c.SendDatagram(packet); err != nil {
				clientErrCh <- fmt.Errorf("client datagram send error: %w", err)
				return
			}
			resp, err := c.ReceiveDatagram(ctx)
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
	if got := conn.cnt.Load(); got < 300 {
		t.Fatalf("insufficient UDP traffic observed: cnt=%d", got)
	}
}
