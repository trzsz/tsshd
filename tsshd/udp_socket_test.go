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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// skipUnlessBindable skips the test if ip can't be bound, e.g. 127.0.0.2 on macOS.
func skipUnlessBindable(t *testing.T, ip string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Skipf("cannot bind %s: %v", ip, err)
	}
	_ = conn.Close()
}

// dialTestSocket connects a client to ip on conn's port. Reads time out, so a
// lost packet fails the test instead of hanging it.
func dialTestSocket(t *testing.T, conn *net.UDPConn, ip string) *net.UDPConn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	require.NoError(t, conn.SetReadDeadline(deadline))

	port := conn.LocalAddr().(*net.UDPAddr).Port
	client, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.SetReadDeadline(deadline))
	return client
}

// requireRoundTrip replies from the local address sock read. The client is
// connected, so it only gets replies from the address it sent to.
func requireRoundTrip(t *testing.T, sock udpSocket, client *net.UDPConn, wantLocal netip.Addr) {
	t.Helper()
	_, err := client.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 16)
	n, remote, local, err := sock.readFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))
	require.Equal(t, client.LocalAddr().String(), remote.String())
	require.Equal(t, wantLocal, local)

	require.NoError(t, sock.writeTo([]byte("pong"), remote, sock.replyOOB(local)))
	n, err = client.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "pong", string(buf[:n]))
}

func TestPlainSocket(t *testing.T) {
	sock, err := listenUdpSocket(netip.MustParseAddr("127.0.0.1"), 0, false)
	require.NoError(t, err)
	defer func() { _ = sock.Close() }()

	client := dialTestSocket(t, sock.(*plainSocket).conn, "127.0.0.1")
	requireRoundTrip(t, sock, client, netip.Addr{})
}

// readLoop stops on this error.
func TestUdpSocketReadAfterClose(t *testing.T) {
	for _, replySource := range []bool{false, true} {
		t.Run(fmt.Sprint("replySource=", replySource), func(t *testing.T) {
			if replySource && !replySourceSupported(false) {
				t.Skip("no IPv4 packet-info socket on " + runtime.GOOS)
			}
			sock, err := listenUdpSocket(netip.IPv4Unspecified(), 0, replySource)
			require.NoError(t, err)
			require.NoError(t, sock.Close())

			_, _, _, err = sock.readFrom(make([]byte, 16))
			require.True(t, errors.Is(err, net.ErrClosed), "got %v", err)
		})
	}
}

func TestReplySourceSupport(t *testing.T) {
	// Other systems support neither family.
	type support struct{ ipv4, ipv6 bool }
	want := map[string]support{
		"linux":   {ipv4: true, ipv6: true},
		"darwin":  {ipv4: true, ipv6: true},
		"freebsd": {ipv6: true},
	}[runtime.GOOS]

	require.Equal(t, want.ipv4, replySourceSupported(false))
	require.Equal(t, want.ipv4, canSelectReplySource("udp4"))
	require.Equal(t, want.ipv6, replySourceSupported(true))
	skipUnlessBindable(t, "::1")
	require.Equal(t, want.ipv6, canSelectReplySource("udp6"))
}
