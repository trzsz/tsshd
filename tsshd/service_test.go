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
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortRanges(t *testing.T) {
	assert := assert.New(t)
	assert.Equal([][2]uint16{{22, 22}}, parsePortRanges("22"))
	assert.Equal([][2]uint16{{100, 102}}, parsePortRanges("100-102"))
	assert.Equal([][2]uint16{{200, 202}}, parsePortRanges("200 - 202"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}, {30, 30}}, parsePortRanges("10 20 30"))
	assert.Equal([][2]uint16{{1, 3}, {5, 5}, {7, 9}, {11, 11}}, parsePortRanges("1-3 5,7 - 9 11"))
	assert.Equal([][2]uint16{{1, 2}, {3, 4}, {5, 5}}, parsePortRanges("1-2,3-4 5"))
	assert.Equal([][2]uint16{{10, 12}, {15, 15}}, parsePortRanges("  10\t-\t12  , 15 "))
	assert.Equal([][2]uint16{{50, 50}}, parsePortRanges("50-50"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}}, parsePortRanges("10,,20"))
	assert.Equal([][2]uint16(nil), parsePortRanges("0,70000,abc"))
	assert.Equal([][2]uint16(nil), parsePortRanges("100-50"))
	assert.Equal([][2]uint16(nil), parsePortRanges("-"))
	assert.Equal([][2]uint16(nil), parsePortRanges("- 10"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 -"))
	assert.Equal([][2]uint16{{1, 3}, {7, 7}}, parsePortRanges("1-3,abc,5 - 4,7"))
	assert.Equal([][2]uint16(nil), parsePortRanges(""))
	assert.Equal([][2]uint16(nil), parsePortRanges("8000-9000-10000"))
	assert.Equal([][2]uint16(nil), parsePortRanges("8000-"))
	assert.Equal([][2]uint16(nil), parsePortRanges("-9000"))
	assert.Equal([][2]uint16{{10, 12}}, parsePortRanges("10 - 12 - 15"))
	assert.Equal([][2]uint16{{1, 65535}}, parsePortRanges("1-65535"))
	assert.Equal([][2]uint16{{10, 10}, {10, 10}, {10, 10}}, parsePortRanges("10 10 10"))
	assert.Equal([][2]uint16{{20, 25}, {22, 23}}, parsePortRanges("20-25 22-23"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 - 0"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 - - 11"))
	assert.Equal([][2]uint16{{10, 11}}, parsePortRanges("10 - 11 -"))
}

// replaceListenProbes fakes the host the listen plan sees.
func replaceListenProbes(t *testing.T, replySource func(network string) bool, ifaceAddrs []netip.Addr,
	listenable func(args *tsshdArgs, ip netip.Addr) bool) {
	oriReplySource, oriInterfaceAddrs, oriCanListen := canSelectReplySource, getInterfaceAddrs, canListenOnIP
	t.Cleanup(func() {
		canSelectReplySource, getInterfaceAddrs, canListenOnIP = oriReplySource, oriInterfaceAddrs, oriCanListen
	})
	canSelectReplySource = replySource
	getInterfaceAddrs = func() []netip.Addr { return ifaceAddrs }
	canListenOnIP = listenable
}

func TestGetListenAddrs(t *testing.T) {
	ip4a, ip4b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")
	ip6a, ip6b := netip.MustParseAddr("2001:db8::1%eth0"), netip.MustParseAddr("fe80::1%eth0")
	ifaceAddrs := []netip.Addr{ip4a, ip6a, ip6b, ip4b}
	any4, any6 := netip.IPv4Unspecified(), netip.IPv6Unspecified()
	probes4, probes6 := []netip.Addr{ip4a, ip4b}, []netip.Addr{ip6a, ip6b}

	both := func(string) bool { return true }
	neither := func(string) bool { return false }
	ipv6Only := func(network string) bool { return network == "udp6" }
	listenAll := func(*tsshdArgs, netip.Addr) bool { return true }
	listenIPv4 := func(_ *tsshdArgs, ip netip.Addr) bool { return ip.Is4() }
	listenWildcard := func(_ *tsshdArgs, ip netip.Addr) bool { return ip.IsUnspecified() }

	tests := []struct {
		name        string
		args        tsshdArgs
		replySource func(string) bool
		ifaceAddrs  []netip.Addr
		listenable  func(*tsshdArgs, netip.Addr) bool
		want        []listenAddr
	}{
		{"WildcardPerFamily", tsshdArgs{}, both, ifaceAddrs, listenAll,
			[]listenAddr{{any4, true, nil}, {any6, true, nil}}},
		{"InterfaceAddrs", tsshdArgs{}, neither, ifaceAddrs, listenAll,
			[]listenAddr{{ip4a, false, nil}, {ip4b, false, nil}, {ip6a, false, nil}, {ip6b, false, nil}}},
		{"NoInterfaceAddr", tsshdArgs{}, neither, nil, listenAll,
			[]listenAddr{{any4, false, nil}, {any6, false, nil}}},
		{"NoListenableInterfaceAddr", tsshdArgs{}, neither, ifaceAddrs, listenWildcard,
			[]listenAddr{{any4, false, nil}, {any6, false, nil}}},
		{"IPv4Flag", tsshdArgs{IPv4: true}, both, ifaceAddrs, listenAll,
			[]listenAddr{{any4, true, nil}}},
		{"IPv6Flag", tsshdArgs{IPv6: true}, both, ifaceAddrs, listenAll,
			[]listenAddr{{any6, true, nil}}},
		{"IPv6FlagInterfaceAddrs", tsshdArgs{IPv6: true}, neither, ifaceAddrs, listenAll,
			[]listenAddr{{ip6a, false, nil}, {ip6b, false, nil}}},
		{"BothFlags", tsshdArgs{IPv4: true, IPv6: true}, both, ifaceAddrs, listenAll,
			[]listenAddr{{any4, true, nil}, {any6, true, nil}}},
		{"OnlyIPv6Capable", tsshdArgs{}, ipv6Only, ifaceAddrs, listenAll,
			[]listenAddr{{ip4a, false, nil}, {ip4b, false, nil}, {any6, true, nil}}},
		{"IPv6Unavailable", tsshdArgs{}, neither, ifaceAddrs, listenIPv4,
			[]listenAddr{{ip4a, false, nil}, {ip4b, false, nil}}},
		{"TCP", tsshdArgs{TCP: true}, both, ifaceAddrs, listenAll,
			[]listenAddr{{any4, false, probes4}, {any6, false, probes6}}},
		{"TCPNotCapable", tsshdArgs{TCP: true}, neither, ifaceAddrs, listenAll,
			[]listenAddr{{any4, false, probes4}, {any6, false, probes6}}},
		{"TCPIPv4Flag", tsshdArgs{TCP: true, IPv4: true}, both, ifaceAddrs, listenAll,
			[]listenAddr{{any4, false, probes4}}},
		{"TCPIPv6Unavailable", tsshdArgs{TCP: true}, both, ifaceAddrs, listenIPv4,
			[]listenAddr{{any4, false, probes4}}},
		{"TCPNoListenableInterfaceAddr", tsshdArgs{TCP: true}, both, ifaceAddrs, listenWildcard,
			[]listenAddr{{any4, false, nil}, {any6, false, nil}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			replaceListenProbes(t, tt.replySource, tt.ifaceAddrs, tt.listenable)
			addrs, err := getListenAddrs(&tt.args)
			require.NoError(t, err)
			require.Equal(t, tt.want, addrs)
		})
	}

	t.Run("NothingListenable", func(t *testing.T) {
		replaceListenProbes(t, neither, ifaceAddrs, func(*tsshdArgs, netip.Addr) bool { return false })
		for _, args := range []tsshdArgs{{}, {TCP: true}} {
			_, err := getListenAddrs(&args)
			require.ErrorContains(t, err, "listen")
		}
	})
}

func listenTestPorts(t *testing.T, args *tsshdArgs) ([]udpSocket, int) {
	conn, port, err := listenOnFreePort(args)
	require.NoError(t, err)
	sockets := conn.(*udpFrontendConn).sockets
	t.Cleanup(func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	})
	return sockets, port
}

func skipUnlessWildcardSockets(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("UDP listens on each interface address on " + runtime.GOOS)
	}
	skipUnlessBindable(t, "::1")
}

func TestUdpListenBothFamiliesOnOnePort(t *testing.T) {
	skipUnlessWildcardSockets(t)
	sockets, port := listenTestPorts(t, &tsshdArgs{Port: "31000-65000"})
	require.Len(t, sockets, 2)

	// Both wildcard addresses are taken on the port.
	for _, network := range []string{"udp4", "udp6"} {
		conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
		if err == nil {
			_ = conn.Close()
		}
		require.Error(t, err, network)
	}
}

func TestUdpListenPortTakenForOneFamily(t *testing.T) {
	skipUnlessWildcardSockets(t)

	isFree := func(network string, port int) bool {
		conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}

	// Take the port for IPv6 only. The next port is free for both.
	var taken *net.UDPConn
	var port int
	for range 100 {
		conn, err := net.ListenUDP("udp6", &net.UDPAddr{})
		require.NoError(t, err)
		port = conn.LocalAddr().(*net.UDPAddr).Port
		if port < 65535 && isFree("udp4", port+1) && isFree("udp6", port+1) {
			taken = conn
			break
		}
		_ = conn.Close()
	}
	require.NotNil(t, taken, "no port with a free next port")
	defer func() { _ = taken.Close() }()

	sockets, got := listenTestPorts(t, &tsshdArgs{Port: fmt.Sprintf("%d-%d", port, port+1)})
	require.Equal(t, port+1, got)
	require.Len(t, sockets, 2)
	// The IPv4 socket on the taken port was closed.
	require.True(t, isFree("udp4", port))
}

func TestServerStartsWithAvailableFamilies(t *testing.T) {
	oriReplySource, oriCanListen := canSelectReplySource, canListenOnIP
	replaceListenProbes(t,
		func(network string) bool { return network == "udp4" && oriReplySource(network) },
		getInterfaceAddrs(),
		func(args *tsshdArgs, ip netip.Addr) bool { return ip.Is4() && oriCanListen(args, ip) })

	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprint("TCP=", tcp), func(t *testing.T) {
			args := &tsshdArgs{TCP: tcp, Port: "31000-65000", ConnectTimeout: 3 * time.Second}
			addrs, err := getListenAddrs(args)
			require.NoError(t, err)
			for _, addr := range addrs {
				require.True(t, addr.ip.Is4(), addr.ip)
			}
			runProxyEchoTest(t, args, "127.0.0.1", kTsshdProtocol)

			args.IPv6 = true
			_, _, err = initServer(args)
			require.ErrorContains(t, err, "listen")
		})
	}
}

func TestTcpListenSkipsPortTakenOnOneAddress(t *testing.T) {
	taken, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()
	port := taken.Addr().(*net.TCPAddr).Port

	conn, _, err := listenOnFreePort(&tsshdArgs{TCP: true, IPv4: true, Port: strconv.Itoa(port)})
	if err == nil {
		for _, listener := range conn.(*tcpFrontendConn).listenerList {
			_ = listener.Close()
		}
	}
	require.Error(t, err)
}

func TestInterfaceAddrsZoneOnlyOnLinkLocal(t *testing.T) {
	for _, addr := range getInterfaceAddrs() {
		require.Equal(t, addr.Is6() && addr.IsLinkLocalUnicast(), addr.Zone() != "", addr)
	}
}
