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

	_, output, err := initServer(args)
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
			proxy, err := startClientProxy(&SshUdpClient{activeChecker: newTimeoutChecker(0)}, opts)
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

			t.Run("ListenAll", func(t *testing.T) {
				_ = os.Unsetenv("SSH_CONNECTION")
				if v := os.Getenv("SSH_CONNECTION"); v != "" {
					t.Fatalf("SSH_CONNECTION should be unset, got %q", v)
				}

				runProxyEchoTest(t, args)
			})

			t.Run("ListenOne", func(t *testing.T) {
				const mockSshConn = "127.0.0.1 50818 127.0.0.1 22"
				t.Setenv("SSH_CONNECTION", mockSshConn)
				if v := os.Getenv("SSH_CONNECTION"); v != mockSshConn {
					t.Fatalf("SSH_CONNECTION mismatch: want %q, got %q", mockSshConn, v)
				}

				runProxyEchoTest(t, args)
			})
		})
	}
}
