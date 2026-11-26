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
	"syscall"
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

func testTCPAddr(ip netip.Addr, port int) *net.TCPAddr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
}

func testUDPAddr(ip netip.Addr, port int) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
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
	listenIPv6 := func(_ *tsshdArgs, ip netip.Addr) bool { return ip.Is6() }
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
		{"IPv4Unavailable", tsshdArgs{}, neither, ifaceAddrs, listenIPv6,
			[]listenAddr{{ip6a, false, nil}, {ip6b, false, nil}}},
		{"TCPIPv4Unavailable", tsshdArgs{TCP: true}, both, ifaceAddrs, listenIPv6,
			[]listenAddr{{any6, false, probes6}}},
		{"TCPIPv6Flag", tsshdArgs{TCP: true, IPv6: true}, both, ifaceAddrs, listenAll,
			[]listenAddr{{any6, false, probes6}}},
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
			require.ErrorContains(t, err, "no address can be listened on")
		}
	})
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

	conn, port, err := listenOnFreePort(&tsshdArgs{Port: "31000-65000"})
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.Close()
	})

	require.Len(t, conn.(*udpFrontendConn).sockets, 2)

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

	conn, got, err := listenOnFreePortWithRandom(
		&tsshdArgs{Port: fmt.Sprintf("%d-%d", port, port+1)},
		func(int) int { return 0 })
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.Close()
	})

	require.Equal(t, port+1, got)
	require.Len(t, conn.(*udpFrontendConn).sockets, 2)
	// The IPv4 socket on the taken port was closed.
	require.True(t, isFree("udp4", port))
}

func TestServerStartsWithAvailableFamilies(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		ipv4         bool
		replyNetwork string
	}{
		{
			name:         "IPv4Only",
			host:         "127.0.0.1",
			ipv4:         true,
			replyNetwork: "udp4",
		},
		{
			name:         "IPv6Only",
			host:         "::1",
			ipv4:         false,
			replyNetwork: "udp6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcpNetwork, udpNetwork := "tcp4", "udp4"
			loopback := netip.MustParseAddr("127.0.0.1")
			if !tt.ipv4 {
				tcpNetwork, udpNetwork = "tcp6", "udp6"
				loopback = netip.IPv6Loopback()
			}

			tcpProbe, err := net.ListenTCP(tcpNetwork, testTCPAddr(loopback, 0))
			if err != nil {
				t.Skipf("%s loopback unavailable: %v", tcpNetwork, err)
			}
			require.NoError(t, tcpProbe.Close())

			udpProbe, err := net.ListenUDP(udpNetwork, testUDPAddr(loopback, 0))
			if err != nil {
				t.Skipf("%s loopback unavailable: %v", udpNetwork, err)
			}
			require.NoError(t, udpProbe.Close())

			oriReplySource, oriCanListen := canSelectReplySource, canListenOnIP
			replaceListenProbes(t,
				func(network string) bool {
					return network == tt.replyNetwork && oriReplySource(network)
				},
				getInterfaceAddrs(),
				func(args *tsshdArgs, ip netip.Addr) bool {
					return ip.Is4() == tt.ipv4 && oriCanListen(args, ip)
				})

			for _, tcp := range []bool{false, true} {
				t.Run(fmt.Sprint("TCP=", tcp), func(t *testing.T) {
					// Neither address family is explicitly selected.
					// tsshd must automatically use the available family.
					args := &tsshdArgs{
						TCP:            tcp,
						Port:           "31000-65000",
						ConnectTimeout: 3 * time.Second,
					}

					addrs, err := getListenAddrs(args)
					require.NoError(t, err)
					require.NotEmpty(t, addrs)
					for _, addr := range addrs {
						require.Equal(t, tt.ipv4, addr.ip.Is4(), addr.ip)
					}

					// The server must actually start and forward data.
					runProxyEchoTest(t, args, tt.host, kTsshdProtocol)

					// Explicitly selecting the unavailable family must fail.
					unavailableArgs := &tsshdArgs{
						TCP:            tcp,
						IPv4:           !tt.ipv4,
						IPv6:           tt.ipv4,
						Port:           "31000-65000",
						ConnectTimeout: 3 * time.Second,
					}

					_, _, err = initServer(unavailableArgs)
					if err == nil {
						// Avoid leaving a server running if the assertion fails.
						cleanupOnExit()
					}
					require.ErrorContains(t, err, "no address can be listened on")
				})
			}
		})
	}
}

func TestTcpListenSkipsPortTakenOnOneAddress(t *testing.T) {
	tests := []struct {
		name    string
		network string
		ip      netip.Addr
		args    tsshdArgs
	}{
		{
			name:    "IPv4",
			network: "tcp4",
			ip:      netip.MustParseAddr("127.0.0.1"),
			args:    tsshdArgs{TCP: true, IPv4: true},
		},
		{
			name:    "IPv6",
			network: "tcp6",
			ip:      netip.IPv6Loopback(),
			args:    tsshdArgs{TCP: true, IPv6: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			taken, err := net.ListenTCP(tt.network, testTCPAddr(tt.ip, 0))
			if err != nil {
				t.Skipf("cannot bind %s: %v", tt.ip, err)
			}
			defer func() { _ = taken.Close() }()

			port := taken.Addr().(*net.TCPAddr).Port
			tt.args.Port = strconv.Itoa(port)

			addrs, err := getListenAddrs(&tt.args)
			require.NoError(t, err)

			probeFound := false
			specificAddr := tt.ip

			for _, addr := range addrs {
				for _, ip := range addr.probes {
					if ip == specificAddr {
						probeFound = true
					}
				}
			}
			require.True(t, probeFound, "occupied address %s not included in TCP probes", specificAddr)

			conn, _, err := listenOnFreePort(&tt.args)
			if conn != nil {
				conn.Close()
			}
			require.Error(t, err)
		})
	}
}

func TestInterfaceAddrsZoneOnlyOnLinkLocal(t *testing.T) {
	for _, addr := range getInterfaceAddrs() {
		require.Equal(t, addr.Is6() && addr.IsLinkLocalUnicast(), addr.Zone() != "", addr)
	}
}

func TestTcpListenClosesListenersOnPartialFailure(t *testing.T) {
	// Occupy an IPv6-specific address on an ephemeral port.
	taken, err := net.ListenTCP("tcp6", testTCPAddr(netip.IPv6Loopback(), 0))
	if err != nil {
		t.Skipf("cannot bind IPv6 loopback: %v", err)
	}
	defer func() { _ = taken.Close() }()

	port := taken.Addr().(*net.TCPAddr).Port

	// Ensure IPv4 wildcard can bind the same port.
	probe, err := net.ListenTCP("tcp4", testTCPAddr(netip.IPv4Unspecified(), port))
	if err != nil {
		t.Skipf("IPv4 wildcard cannot bind the same port: %v", err)
	}
	require.NoError(t, probe.Close())

	addrs := []listenAddr{
		{ip: netip.IPv4Unspecified()},
		{ip: netip.MustParseAddr("::1")},
	}

	// IPv4 listener should be created first, then IPv6 should fail.
	conn, err := tcpListenOnPort(addrs, port)
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err)
	require.Nil(t, conn)
	var opErr *net.OpError
	require.ErrorAs(t, err, &opErr)
	require.Equal(t, "tcp6", opErr.Net)

	// The IPv4 listener created before the IPv6 bind failed must be closed.
	ipv4, err := net.ListenTCP("tcp4", testTCPAddr(netip.IPv4Unspecified(), port))
	require.NoError(t, err, "IPv4 TCP listener was not closed after the IPv6 bind failed")
	_ = ipv4.Close()
}

func TestUdpListenClosesSocketsOnPartialFailure(t *testing.T) {
	taken, err := net.ListenUDP("udp6", testUDPAddr(netip.IPv6Unspecified(), 0))
	if err != nil {
		t.Skipf("cannot bind IPv6 UDP wildcard: %v", err)
	}
	defer func() { _ = taken.Close() }()

	port := taken.LocalAddr().(*net.UDPAddr).Port

	// Ensure IPv4 can bind the same port while IPv6 is occupied.
	probe, err := net.ListenUDP("udp4", testUDPAddr(netip.IPv4Unspecified(), port))
	if err != nil {
		t.Skipf("IPv6 wildcard also prevents IPv4 bind: %v", err)
	}
	require.NoError(t, probe.Close())

	addrs := []listenAddr{
		{ip: netip.IPv4Unspecified()},
		{ip: netip.IPv6Unspecified()},
	}

	conn, err := udpListenOnPort(addrs, port)
	if conn != nil {
		conn.Close()
	}
	require.Error(t, err)
	require.Nil(t, conn)

	var opErr *net.OpError
	require.ErrorAs(t, err, &opErr)
	require.Equal(t, "udp6", opErr.Net)

	// The IPv4 socket created before the IPv6 bind failed must be closed.
	ipv4, err := net.ListenUDP("udp4", testUDPAddr(netip.IPv4Unspecified(), port))
	require.NoError(t, err, "IPv4 UDP socket was not closed after the IPv6 bind failed")
	_ = ipv4.Close()
}

func TestUdpListenRejectsPortTakenOnSpecificAddress(t *testing.T) {
	tests := []struct {
		name         string
		network      string
		specificIP   netip.Addr
		wildcardIP   netip.Addr
		specificAddr netip.Addr
		ipv4         bool
		ipv6         bool
	}{
		{
			name:         "IPv4",
			network:      "udp4",
			specificIP:   netip.MustParseAddr("127.0.0.1"),
			wildcardIP:   netip.IPv4Unspecified(),
			specificAddr: netip.MustParseAddr("127.0.0.1"),
			ipv4:         true,
		},
		{
			name:         "IPv6",
			network:      "udp6",
			specificIP:   netip.IPv6Loopback(),
			wildcardIP:   netip.IPv6Unspecified(),
			specificAddr: netip.MustParseAddr("::1"),
			ipv6:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First occupy a specific address on an ephemeral port.
			specific, err := net.ListenUDP(tt.network, testUDPAddr(tt.specificIP, 0))
			if err != nil {
				t.Skipf("cannot bind %s: %v", tt.specificAddr, err)
			}
			defer func() { _ = specific.Close() }()

			port := specific.LocalAddr().(*net.UDPAddr).Port

			// Binding the wildcard address to the same port must fail.
			wildcard, wildcardErr := net.ListenUDP(tt.network, testUDPAddr(tt.wildcardIP, port))
			if wildcard != nil {
				_ = wildcard.Close()
			}

			if runtime.GOOS != "windows" {
				require.ErrorIs(t, wildcardErr, syscall.EADDRINUSE, "wildcard UDP socket should conflict with the specific address")
			}

			args := &tsshdArgs{
				IPv4: tt.ipv4,
				IPv6: tt.ipv6,
				Port: strconv.Itoa(port),
			}

			// Verify that tsshd's listen plan actually covers the occupied
			// address, either through a wildcard socket or a specific socket.
			addrs, err := getListenAddrs(args)
			require.NoError(t, err)
			require.NotEmpty(t, addrs)

			coversSpecificAddr := false
			for _, addr := range addrs {
				require.Equal(t, tt.specificAddr.Is4(), addr.ip.Is4(), "unexpected address family in listen plan: %s", addr.ip)

				if addr.ip.IsUnspecified() || addr.ip == tt.specificAddr {
					coversSpecificAddr = true
				}
			}
			require.True(t, coversSpecificAddr, "listen plan does not cover occupied address %s: %+v", tt.specificAddr, addrs)

			// tsshd must not select the occupied port.
			conn, gotPort, err := listenOnFreePort(args)
			if conn != nil {
				conn.Close()
			}
			require.Error(t, err)
			require.Nil(t, conn)
			require.Zero(t, gotPort)
		})
	}
}
