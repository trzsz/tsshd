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
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = conn.Close()
}

func TestListenerAddressFamily(t *testing.T) {
	for _, tc := range []struct{ ip, want string }{
		{"127.0.0.1", "inet"}, {"::ffff:127.0.0.1", "inet"},
		{"::1", "inet6"}, {"fe80::1", "inet6"},
		{"0.0.0.0", "inet"}, {"::", ""}, {"", ""},
	} {
		for _, addr := range []net.Addr{
			&net.UDPAddr{IP: net.ParseIP(tc.ip)}, &net.TCPAddr{IP: net.ParseIP(tc.ip)},
		} {
			if got := listenerAddressFamily(addr); got != tc.want {
				t.Errorf("%T %q: got %q, want %q", addr, tc.ip, got, tc.want)
			}
		}
	}
}

func TestSSHConnectionAddressFamily(t *testing.T) {
	requireIPv6Loopback(t)
	for _, tcp := range []bool{false, true} {
		for _, tc := range []struct {
			name, ssh, want string
			ipv4, ipv6      bool
		}{
			{"IPv4", "127.0.0.1 1234 127.0.0.1 22", "inet", false, false},
			{"IPv6", "::1 1234 ::1 22", "inet6", false, false},
			{"MappedIPv4", "::1 1234 ::ffff:127.0.0.1 22", "inet", false, false},
			{"MappedIPv4Hex", "::1 1234 ::ffff:7f00:1 22", "inet", false, false},
			{"IPv4Policy", "::1 1234 ::1 22", "inet", true, false},
			{"IPv6Policy", "127.0.0.1 1234 127.0.0.1 22", "inet6", false, true},
			{"BothFlags", "::1 1234 ::1 22", "inet6", true, true},
			{"Missing", "", "inet", true, false},
			{"Invalid", "invalid", "inet6", false, true},
		} {
			t.Run(tc.name+"/tcp="+strconv.FormatBool(tcp), func(t *testing.T) {
				t.Setenv("SSH_CONNECTION", tc.ssh)
				addrs, err := getUdpAddrs(&tsshdArgs{TCP: tcp, IPv4: tc.ipv4, IPv6: tc.ipv6})
				if err != nil {
					t.Fatal(err)
				}
				if len(addrs) == 0 {
					t.Fatal("no addresses")
				}
				for _, addr := range addrs {
					if got := listenerAddressFamily(addr); got != tc.want {
						t.Errorf("address %v: family %q, want %q", addr, got, tc.want)
					}
				}
			})
		}
	}
}

func TestServerInfoAddressFamilyCompatibility(t *testing.T) {
	var info ServerInfo
	if err := json.Unmarshal([]byte(`{"Port":1234,"Mode":"quic"}`), &info); err != nil {
		t.Fatal(err)
	}
	buf, err := json.Marshal(info)
	if err != nil || strings.Contains(string(buf), "AddressFamily") {
		t.Fatalf("old metadata round trip: %s, %v", buf, err)
	}
	info.AddressFamily = "inet6"
	buf, err = json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var oldInfo struct {
		Port int
		Mode string
	}
	if err := json.Unmarshal(buf, &oldInfo); err != nil || oldInfo.Port != 1234 || oldInfo.Mode != "quic" {
		t.Fatalf("old client decoding new metadata: %+v, %v", oldInfo, err)
	}
	var newInfo ServerInfo
	if err := json.Unmarshal(buf, &newInfo); err != nil || newInfo.AddressFamily != "inet6" {
		t.Fatalf("new metadata round trip: %+v, %v", newInfo, err)
	}
}

func TestAttachSelectedAddressFamily(t *testing.T) {
	requireIPv6Loopback(t)
	front, err := udpListenOnPort([]*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1)}, {IP: net.IPv6loopback}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := front.(*udpFrontendConn)
	for _, conn := range c.connList {
		defer conn.Close()
	}
	c.initCond = sync.NewCond(&c.initMutex)
	info := &ServerInfo{frontendConn: front}
	if got := info.snapshot().AddressFamily; got != "" {
		t.Fatalf("mixed listeners advertised %q", got)
	}

	// Read snapshots concurrently with UDP listener selection.
	var wg sync.WaitGroup
	wg.Go(func() { c.initConn(c.connList[1], nil, 0, 0) })
	for range 100 {
		_, _ = json.Marshal(info.snapshot())
	}
	wg.Wait()
	defer cleanupOnExit()
	if info.AddressFamily != "" || info.snapshot().AddressFamily != "inet6" {
		t.Fatalf("selected listener snapshot: %+v", info.snapshot())
	}

	saved := globalSocketInfo
	globalSocketInfo = &socketInfo{serverInfo: info}
	defer func() { globalSocketInfo = saved }()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { done <- handleAttachRequest(server) }()
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var attached ServerInfo
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "\a")), &attached); err != nil {
		t.Fatal(err)
	}
	if attached.AddressFamily != "inet6" || attached.ClientID != 1 || info.AddressFamily != "" {
		t.Fatalf("attach metadata: %+v", attached)
	}
}

func TestTCPFrontendAddressFamilyExpiry(t *testing.T) {
	requireIPv6Loopback(t)
	front, err := tcpListenOnPort([]*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1)}, {IP: net.IPv6loopback}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := front.(*tcpFrontendConn)
	listeners := append([]*net.TCPListener(nil), c.listenerList...)
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
		cleanupOnExit()
	}()
	if got := c.addressFamily(); got != "" {
		t.Fatalf("mixed TCP family: %q", got)
	}
	c.start(&serverProxy{args: &tsshdArgs{ConnectTimeout: 100 * time.Millisecond}})
	conn, err := net.DialTimeout("tcp6", listeners[1].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for c.addressFamily() != "inet6" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := c.addressFamily(); got != "inet6" {
		t.Fatalf("retained TCP listener family: %q", got)
	}
}

// Generic resolution selects IPv4 even when SSH starts an IPv6-only listener.
func TestAddressFamilyDualStackLoopback(t *testing.T) {
	requireIPv6Loopback(t)
	for _, tcp := range []bool{false, true} {
		t.Run("tcp="+strconv.FormatBool(tcp), func(t *testing.T) {
			t.Setenv("SSH_CONNECTION", "::1 1234 ::1 22")
			addrs, err := getUdpAddrs(&tsshdArgs{TCP: tcp})
			if err != nil {
				t.Fatal(err)
			}
			var front frontendConnection
			var port int
			if tcp {
				front, err = tcpListenOnPort(addrs, 0)
				if err != nil {
					t.Fatal(err)
				}
				listener := front.(*tcpFrontendConn).listenerList[0]
				defer listener.Close()
				port = listener.Addr().(*net.TCPAddr).Port
			} else {
				front, err = udpListenOnPort(addrs, 0)
				if err != nil {
					t.Fatal(err)
				}
				conn := front.(*udpFrontendConn).connList[0]
				defer conn.Close()
				port = conn.LocalAddr().(*net.UDPAddr).Port
				go func() {
					buf := make([]byte, 32)
					for {
						n, peer, err := conn.ReadFromUDP(buf)
						if err != nil {
							return
						}
						_, _ = conn.WriteToUDP(buf[:n], peer)
					}
				}()
			}
			addr := net.JoinHostPort("localhost", strconv.Itoa(port))
			generic, err := net.ResolveUDPAddr("udp", addr)
			if err != nil || generic.IP.To4() == nil {
				t.Skip("localhost needs an IPv4 record")
			}
			if _, err := net.ResolveUDPAddr("udp6", addr); err != nil {
				t.Skip("localhost needs an IPv6 record")
			}
			for _, advertised := range []bool{false, true} {
				info := &ServerInfo{ProxyKey: strings.Repeat("00", 32)}
				if tcp {
					info.ProxyMode = kProxyModeTCP
				}
				if advertised {
					info.AddressFamily = front.addressFamily()
				}
				proxy, err := startClientProxy(&SshUdpClient{}, &UdpClientOptions{ServerInfo: info, TsshdAddr: addr})
				if err != nil {
					t.Fatal(err)
				}
				for range 2 { // Reuse the selected network for subsequent dials.
					var conn net.Conn
					if tcp {
						a, e := net.ResolveTCPAddr(proxy.serverNet, proxy.serverAddr)
						if e != nil {
							t.Fatal(e)
						}
						var tcpConn *net.TCPConn
						tcpConn, err = net.DialTCP(proxy.serverNet, nil, a)
						if tcpConn != nil {
							conn = tcpConn
						}
					} else {
						a, e := net.ResolveUDPAddr(proxy.serverNet, proxy.serverAddr)
						if e != nil {
							t.Fatal(e)
						}
						conn, err = net.DialUDP(proxy.serverNet, nil, a)
						if err == nil {
							_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
							_, err = conn.Write([]byte("family"))
							if err == nil {
								_, err = conn.Read(make([]byte, 32))
							}
						}
					}
					if conn != nil {
						_ = conn.Close()
					}
					if advertised != (err == nil) {
						t.Fatalf("advertised=%v network=%s: %v", advertised, proxy.serverNet, err)
					}
				}
			}
		})
	}
}

func TestNoInterfacesFallsBackToSingleFamilyWildcard(t *testing.T) {
	orig := netInterfaces
	netInterfaces = func() ([]net.Interface, error) { return nil, errors.New("netlink permission denied") }
	defer func() { netInterfaces = orig }()
	t.Setenv("SSH_CONNECTION", "")

	for _, tc := range []struct {
		name       string
		ipv4, ipv6 bool
		want       string
		needIPv6   bool
	}{
		{"IPv4", true, false, "inet", false},
		{"IPv6", false, true, "inet6", true},
		{"Any", false, false, "", false},
	} {
		for _, tcp := range []bool{false, true} {
			t.Run(tc.name+"/tcp="+strconv.FormatBool(tcp), func(t *testing.T) {
				if tc.needIPv6 {
					requireIPv6Loopback(t)
				}
				addrs, err := getUdpAddrs(&tsshdArgs{TCP: tcp, IPv4: tc.ipv4, IPv6: tc.ipv6})
				if err != nil {
					t.Fatalf("expected wildcard fallback, got %v", err)
				}
				if len(addrs) != 1 || (addrs[0].IP != nil && !addrs[0].IP.IsUnspecified()) {
					t.Fatalf("expected one wildcard address, got %v", addrs)
				}
				var conn frontendConnection
				if tcp {
					conn, err = tcpListenOnPort(addrs, 0)
				} else {
					conn, err = udpListenOnPort(addrs, 0)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if c, ok := conn.(*udpFrontendConn); ok {
						for _, l := range c.connList {
							_ = l.Close()
						}
					} else if c, ok := conn.(*tcpFrontendConn); ok {
						for _, l := range c.listenerList {
							_ = l.Close()
						}
					}
				}()
				if got := conn.addressFamily(); got != tc.want {
					t.Fatalf("address family %q, want %q", got, tc.want)
				}
			})
		}
	}
}

func TestListenNetwork(t *testing.T) {
	for _, tc := range []struct {
		ip   net.IP
		want string
	}{
		{nil, "udp"},
		{net.IPv4zero, "udp4"},
		{net.IPv6unspecified, "udp6"},
		{net.ParseIP("127.0.0.1"), "udp"},
		{net.ParseIP("::1"), "udp"},
	} {
		if got := listenNetwork("udp", tc.ip); got != tc.want {
			t.Errorf("listenNetwork(%v) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}
