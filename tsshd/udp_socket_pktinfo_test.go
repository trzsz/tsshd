//go:build linux || darwin || freebsd

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
	"net"
	"net/netip"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPktInfoSocketIPv4(t *testing.T) {
	if !replySourceSupported(false) {
		t.Skip("no IPv4 reply source selection on " + runtime.GOOS)
	}
	sock, err := listenUdpSocket(netip.IPv4Unspecified(), 0, true)
	require.NoError(t, err)
	defer func() { _ = sock.Close() }()

	client := dialTestSocket(t, sock.(*pktInfoSocket).conn, "127.0.0.1")
	requireRoundTrip(t, sock, client, netip.MustParseAddr("127.0.0.1"))
}

func TestPktInfoSocketIPv6(t *testing.T) {
	skipUnlessBindable(t, "::1")
	sock, err := listenUdpSocket(netip.IPv6Unspecified(), 0, true)
	require.NoError(t, err)
	defer func() { _ = sock.Close() }()

	client := dialTestSocket(t, sock.(*pktInfoSocket).conn, "::1")
	requireRoundTrip(t, sock, client, netip.IPv6Loopback())
}

// Without source selection both replies would come from 127.0.0.1, and the
// client connected to 127.0.0.2 would drop its reply.
func TestPktInfoSocketRepliesFromContactedAddress(t *testing.T) {
	if !replySourceSupported(false) {
		t.Skip("no IPv4 reply source selection on " + runtime.GOOS)
	}
	skipUnlessBindable(t, "127.0.0.2")
	sock, err := listenUdpSocket(netip.IPv4Unspecified(), 0, true)
	require.NoError(t, err)
	defer func() { _ = sock.Close() }()

	conn := sock.(*pktInfoSocket).conn
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		client := dialTestSocket(t, conn, ip)
		requireRoundTrip(t, sock, client, netip.MustParseAddr(ip))
	}
}

func TestPktInfoSocketWriteToDoesNotAllocate(t *testing.T) {
	for _, tc := range []struct{ wildcard, ip string }{{"0.0.0.0", "127.0.0.1"}, {"::", "::1"}} {
		t.Run(tc.ip, func(t *testing.T) {
			wildcard := netip.MustParseAddr(tc.wildcard)
			if !replySourceSupported(wildcard.Is6()) {
				t.Skip("no reply source selection for " + tc.ip + " on " + runtime.GOOS)
			}
			skipUnlessBindable(t, tc.ip)
			sock, err := listenUdpSocket(wildcard, 0, true)
			require.NoError(t, err)
			defer func() { _ = sock.Close() }()

			conn := sock.(*pktInfoSocket).conn
			client := dialTestSocket(t, conn, tc.ip)
			remote := client.LocalAddr().(*net.UDPAddr).AddrPort()
			oob := sock.replyOOB(netip.MustParseAddr(tc.ip))
			require.NotNil(t, oob)

			buf := []byte("pong")
			allocs := testing.AllocsPerRun(100, func() {
				if err := sock.writeTo(buf, remote, oob); err != nil {
					t.Fatal(err)
				}
			})
			require.Zero(t, allocs)
		})
	}
}
