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
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trzsz/smux"
)

func TestKCP_PassSaltValidation(t *testing.T) {
	info := ServerInfo{}
	udpConn := listenRandomUDP(t)
	defer func() { _ = udpConn.Close() }()

	// Start KCP server
	listener, err := listenKCP(udpConn, &info, &tsshdArgs{})
	if err != nil {
		t.Fatalf("listenKCP failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverErrCh := make(chan error, 1)
	clientErrCh := make(chan error, 1)

	go func() {
		defer close(serverErrCh)

		// The server intentionally accepts ONLY ONCE.
		// If an invalid client is accepted here, the valid case must fail later.
		conn, err := listener.AcceptKCP()
		if err != nil {
			serverErrCh <- fmt.Errorf("server accept failed: %w", err)
			return
		}
		defer func() { _ = conn.Close() }()

		// build smux server
		session, err := smux.Server(conn, &smuxConfig)
		if err != nil {
			serverErrCh <- fmt.Errorf("smux server failed: %w", err)
			return
		}
		defer func() { _ = session.Close() }()

		// accept one stream
		stream, err := session.AcceptStream()
		if err != nil {
			serverErrCh <- fmt.Errorf("accept stream failed: %w", err)
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
				serverErrCh <- fmt.Errorf("server read failed: %w", err)
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				serverErrCh <- fmt.Errorf("server write failed: %w", err)
				return
			}
		}
	}()

	go func() {
		defer close(clientErrCh)

		// ---------- Case 1: invalid pass/salt (swap) ----------
		illegalInfo := info
		illegalInfo.Pass, illegalInfo.Salt = info.Salt, info.Pass

		// The client may believe it has connected successfully.
		// We intentionally do NOT assert failure here.
		illegalClient, err := newKcpClient(nil, &UdpClientOptions{ServerInfo: &illegalInfo}, udpConn.LocalAddr().String())
		if err == nil {
			defer func() { _ = illegalClient.closeClient() }()
			// Try to open a smux stream with a short timeout.
			// If this unexpectedly succeeds, it will consume the server's
			// single Accept slot and cause Case 2 to fail, exposing a bug.
			_, _ = doWithTimeout(func() (*smux.Stream, error) {
				return illegalClient.(*kcpClient).session.OpenStream()
			}, 200*time.Millisecond)
		}

		// ---------- Case 2: valid pass/salt ----------
		client, err := newKcpClient(nil, &UdpClientOptions{ServerInfo: &info}, udpConn.LocalAddr().String())
		if err != nil {
			clientErrCh <- fmt.Errorf("valid pass/salt should succeed: %v", err)
			return
		}
		defer func() { _ = client.closeClient() }()

		// open stream and verify echo
		stream, err := doWithTimeout(func() (*smux.Stream, error) {
			return client.(*kcpClient).session.OpenStream()
		}, 200*time.Millisecond)
		if err != nil {
			clientErrCh <- fmt.Errorf("client open stream failed: %v", err)
			return
		}
		defer func() { _ = stream.Close() }()

		data := []byte("hello kcp")
		if _, err := stream.Write(data); err != nil {
			clientErrCh <- fmt.Errorf("client write failed: %v", err)
			return
		}

		echo := make([]byte, len(data))
		if _, err := io.ReadFull(stream, echo); err != nil {
			clientErrCh <- fmt.Errorf("client read failed: %v", err)
			return
		}
		if !bytes.Equal(data, echo) {
			clientErrCh <- fmt.Errorf("echo mismatch")
			return
		}
	}()

	// The test should complete cleanly without unexpected errors.
	select {
	case err := <-serverErrCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case err := <-clientErrCh:
		if err != nil {
			t.Fatalf("client error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("test timeout")
	}
}

func TestKCP_OOB(t *testing.T) {
	info := ServerInfo{}
	udpConn := listenRandomUDP(t)
	defer func() { _ = udpConn.Close() }()

	// Start KCP server
	listener, err := listenKCP(udpConn, &info, &tsshdArgs{})
	if err != nil {
		t.Fatalf("listenKCP failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverErrCh := make(chan error, 1)

	go func() {
		defer close(serverErrCh)

		// accept one connection
		conn, err := listener.AcceptKCP()
		if err != nil {
			serverErrCh <- fmt.Errorf("server accept failed: %w", err)
			return
		}
		defer func() { _ = conn.Close() }()

		// register OOB callback, echo back received OOB data immediately
		err = conn.SetOOBHandler(func(buf []byte) {
			if err := conn.SendOOB(buf); err != nil {
				serverErrCh <- fmt.Errorf("server failed to echo OOB payload: %v", err)
			}
		})
		if err != nil {
			serverErrCh <- fmt.Errorf("set oob handler failed: %w", err)
			return
		}

		// build smux server
		session, err := smux.Server(conn, &smuxConfig)
		if err != nil {
			serverErrCh <- fmt.Errorf("smux server failed: %w", err)
			return
		}
		defer func() { _ = session.Close() }()

		// accept one stream
		stream, err := session.AcceptStream()
		if err != nil {
			serverErrCh <- fmt.Errorf("accept stream failed: %w", err)
			return
		}
		defer func() { _ = stream.Close() }()

		// stream echo loop
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if isClosedError(err) {
					return
				}
				serverErrCh <- fmt.Errorf("server read failed: %w", err)
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				serverErrCh <- fmt.Errorf("server write failed: %w", err)
				return
			}
		}
	}()

	var wg sync.WaitGroup
	client, err := newKcpClient(nil, &UdpClientOptions{ServerInfo: &info}, udpConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("new kcp client failed: %v", err)
	}

	client.(*kcpClient).crypto.bytesThreshold = 0

	conn := client.(*kcpClient).conn
	size := conn.GetOOBMaxSize()
	if size < 1000 {
		t.Fatalf("unexpectedly small max OOB size: %d", size)
	}

	sizePlus1 := size + 1
	counts := make([]atomic.Int32, sizePlus1)

	// registers OOB callback to validate echoed OOB data content and length
	err = conn.SetOOBHandler(func(buf []byte) {
		for i, b := range buf {
			if b != byte(i) {
				t.Fatalf(
					"OOB echo payload mismatch at offset %d: expected %d, got %d",
					i, byte(i), b,
				)
				break
			}
		}
		counts[len(buf)].Add(1)
	})
	if err != nil {
		t.Fatalf("set oob handler failed: %v", err)
	}

	data := make([]byte, size)
	for i := range len(data) {
		data[i] = byte(i)
	}

	var oobDone atomic.Bool

	wg.Go(func() {
		// stress test for normal data channel to ensure main channel does not affect OOB
		stream, err := client.(*kcpClient).session.OpenStream()
		if err != nil {
			t.Fatalf("client open stream failed: %v", err)
		}
		defer func() { _ = stream.Close() }()

		for !oobDone.Load() {
			if _, err := stream.Write(data); err != nil {
				t.Fatalf("client write failed: %v", err)
			}

			echo := make([]byte, len(data))
			if _, err := io.ReadFull(stream, echo); err != nil {
				t.Fatalf("client read failed: %v", err)
			}
			if !bytes.Equal(data, echo) {
				t.Fatalf("stream echo mismatch")
			}
		}
	})

	wg.Go(func() {
		// send OOB data of varying lengths in a loop, content is [0,1,2,...]
		for i := range 5 << 20 {
			if err := conn.SendOOB(data[:i%sizePlus1]); err != nil {
				t.Errorf("client failed to send OOB payload: %v", err)
			}
		}
		oobDone.Store(true)
	})

	wg.Wait()

	select {
	case err := <-serverErrCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("test timeout")
	}

	// check that all lengths of OOB data are correctly echoed back
	for i := range counts {
		if counts[i].Load() == 0 {
			t.Errorf("missing OOB echo for payload length %d", i)
		}
	}
}
