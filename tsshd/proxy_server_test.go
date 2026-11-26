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
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// udpFrontendTest drives a real UDP frontend with raw UDP clients.
type udpFrontendTest struct {
	t         *testing.T
	proxy     *serverProxy
	info      *ServerInfo
	port      int
	cipher    cipher.Block
	clientID  uint64
	delivered chan deliveredPacket // packets the frontend passes to QUIC
}

type deliveredPacket struct {
	clientID uint64
	data     []byte
}

func startUdpFrontendTest(t *testing.T, attachable bool) *udpFrontendTest {
	args := &tsshdArgs{Attachable: attachable, Port: "31000-65000", ConnectTimeout: 3 * time.Second}
	conn, port, err := listenOnFreePort(args)
	require.NoError(t, err)
	info := &ServerInfo{}
	proxy, err := startServerProxy(args, info, conn)
	require.NoError(t, err)
	t.Cleanup(cleanupOnExit)

	key, err := hex.DecodeString(info.ProxyKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	ft := &udpFrontendTest{t: t, proxy: proxy, info: info, port: port, cipher: block,
		clientID: info.ClientID, delivered: make(chan deliveredPacket, 16)}
	if attachable {
		ft.clientID = 0x1234
	}

	go func() {
		buf := make([]byte, 0xffff)
		for {
			n, addr, err := proxy.ReadFrom(buf)
			if err != nil {
				return
			}
			ft.delivered <- deliveredPacket{addr.(*proxyClientAddr).clientID, append([]byte(nil), buf[:n]...)}
		}
	}()
	return ft
}

// withClientID returns a view of ft that acts as another client.
func (ft *udpFrontendTest) withClientID(clientID uint64) *udpFrontendTest {
	other := *ft
	other.clientID = clientID
	return &other
}

func (ft *udpFrontendTest) serverAddr(ip string) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(ft.port))
}

// newClient opens a client socket bound to ip.
func (ft *udpFrontendTest) newClient(ip string) *net.UDPConn {
	ipAddr, err := netip.ParseAddr(ip)
	require.NoError(ft.t, err)
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ipAddr, 0)))
	require.NoError(ft.t, err)
	ft.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (ft *udpFrontendTest) send(conn *net.UDPConn, ip string, buf []byte) {
	_, err := conn.WriteToUDPAddrPort(buf, ft.serverAddr(ip))
	require.NoError(ft.t, err)
}

func (ft *udpFrontendTest) authPacket(serialNumber uint64) []byte {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], ft.clientID)
	binary.BigEndian.PutUint64(data[8:16], serialNumber)
	return aesEncrypt(&ft.cipher, data)
}

// dataPacket is a non-auth packet long enough to be delivered.
func (ft *udpFrontendTest) dataPacket(text string) []byte {
	return fmt.Appendf(nil, "%-32s", text)
}

// recv returns the next packet and its source.
func (ft *udpFrontendTest) recv(conn *net.UDPConn) ([]byte, netip.AddrPort) {
	require.NoError(ft.t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 256)
	n, from, err := conn.ReadFromUDPAddrPort(buf)
	require.NoError(ft.t, err)
	return buf[:n], from
}

func (ft *udpFrontendTest) requireNoReply(conn *net.UDPConn) {
	require.NoError(ft.t, conn.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	n, from, err := conn.ReadFromUDPAddrPort(make([]byte, 256))
	require.True(ft.t, errors.Is(err, os.ErrDeadlineExceeded), "got %d bytes from %v: %v", n, from, err)
}

// requireAuthReply returns the source of the auth reply for serialNumber.
func (ft *udpFrontendTest) requireAuthReply(conn *net.UDPConn, serialNumber uint64) netip.AddrPort {
	buf, from := ft.recv(conn)
	data := aesDecrypt(&ft.cipher, buf)
	require.Len(ft.t, data, 16)
	require.Equal(ft.t, ft.info.ServerID, binary.BigEndian.Uint64(data[0:8]))
	require.Equal(ft.t, serialNumber, binary.BigEndian.Uint64(data[8:16]))
	return from
}

func (ft *udpFrontendTest) requireDelivered(want []byte) {
	select {
	case got := <-ft.delivered:
		require.Equal(ft.t, deliveredPacket{ft.clientID, want}, got)
	case <-time.After(2 * time.Second):
		ft.t.Fatalf("packet %q not delivered", want)
	}
}

func (ft *udpFrontendTest) requireNotDelivered() {
	select {
	case got := <-ft.delivered:
		ft.t.Fatalf("packet %q delivered", got.data)
	case <-time.After(200 * time.Millisecond):
	}
}

// connect authenticates conn through ip and activates it.
func (ft *udpFrontendTest) connect(conn *net.UDPConn, ip string, serialNumber uint64) netip.AddrPort {
	ft.send(conn, ip, ft.authPacket(serialNumber))
	from := ft.requireAuthReply(conn, serialNumber)
	data := ft.dataPacket("activate")
	ft.send(conn, ip, data)
	ft.requireDelivered(data)
	return from
}

func (ft *udpFrontendTest) client() *clientState {
	client := ft.proxy.getClient(ft.clientID)
	require.NotNil(ft.t, client)
	return client
}

// requireServerSends checks that a server packet reaches conn from the address from.
func (ft *udpFrontendTest) requireServerSends(conn *net.UDPConn, from netip.AddrPort) {
	data := ft.dataPacket("from server")
	_, err := ft.proxy.WriteTo(data, &ft.client().proxyAddr)
	require.NoError(ft.t, err)
	got, gotFrom := ft.recv(conn)
	require.Equal(ft.t, data, got)
	require.Equal(ft.t, from, gotFrom)
}

func forEachAttachable(t *testing.T, f func(t *testing.T, attachable bool)) {
	for _, attachable := range []bool{false, true} {
		t.Run(fmt.Sprint("Attachable=", attachable), func(t *testing.T) { f(t, attachable) })
	}
}

// twoLocalAddrs returns two local addresses. A socket bound to the first can send to both.
func twoLocalAddrs(t *testing.T) (string, string) {
	for _, pair := range [][2]string{{"127.0.0.1", "127.0.0.2"}, {"::1", "fe80::1%lo0"}} {
		if canListenOnIP(&tsshdArgs{}, netip.MustParseAddr(pair[0])) &&
			canListenOnIP(&tsshdArgs{}, netip.MustParseAddr(pair[1])) {
			return pair[0], pair[1]
		}
	}
	t.Skip("no second local address")
	return "", ""
}

// forEachSocketKind runs f with a wildcard socket and with one socket per address.
func forEachSocketKind(t *testing.T, first, second string, f func(t *testing.T)) {
	ips := []netip.Addr{netip.MustParseAddr(first), netip.MustParseAddr(second)}
	t.Run("Wildcard", func(t *testing.T) {
		if !canSelectReplySource(ipNetwork("udp", ips[0])) {
			t.Skip("cannot select reply source addresses here")
		}
		f(t)
	})
	t.Run("PerAddress", func(t *testing.T) {
		replaceListenProbes(t, func(string) bool { return false }, ips, canListenOnIP)
		f(t)
	})
}

func TestUdpFrontendIgnoresUnknownSenders(t *testing.T) {
	forEachAttachable(t, func(t *testing.T, attachable bool) {
		ft := startUdpFrontendTest(t, attachable)
		for _, ip := range []string{"127.0.0.1", "::1"} {
			t.Run(ip, func(t *testing.T) {
				skipUnlessBindable(t, ip)
				conn := ft.newClient(ip)
				for _, size := range []int{1, kSafeToDropPacketLen, 32, 1200} {
					ft.send(conn, ip, make([]byte, size))
				}
				ft.send(conn, ip, ft.dataPacket("unknown"))
				ft.requireNoReply(conn)
				ft.requireNotDelivered()
			})
		}
	})
}

func TestUdpFrontendIgnoresReplayedAuth(t *testing.T) {
	forEachAttachable(t, func(t *testing.T, attachable bool) {
		ft := startUdpFrontendTest(t, attachable)
		client := ft.newClient("127.0.0.1")
		replayer := ft.newClient("127.0.0.1")
		remote := client.LocalAddr().(*net.UDPAddr).AddrPort()

		ft.send(client, "127.0.0.1", ft.authPacket(1))
		ft.requireAuthReply(client, 1)

		// Replayed while the client is authenticated but not yet active.
		ft.send(replayer, "127.0.0.1", ft.authPacket(1))
		ft.requireNoReply(replayer)
		require.Equal(t, remote, ft.client().authedPath.Load().key.remote)

		data := ft.dataPacket("activate")
		ft.send(client, "127.0.0.1", data)
		ft.requireDelivered(data)

		// Replayed while the client is active.
		ft.send(replayer, "127.0.0.1", ft.authPacket(1))
		ft.requireNoReply(replayer)
		require.Equal(t, remote, ft.client().clientPath.Load().key.remote)
		require.Nil(t, ft.client().authedPath.Load())

		ft.requireServerSends(client, netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", ft.port)))
		ft.requireNoReply(replayer)
	})
}

// A packet sent to another local address needs its own authentication.
func TestUdpFrontendReplySourceChangesOnlyOnAuth(t *testing.T) {
	first, second := twoLocalAddrs(t)
	forEachSocketKind(t, first, second, func(t *testing.T) {
		forEachAttachable(t, func(t *testing.T, attachable bool) {
			ft := startUdpFrontendTest(t, attachable)
			client := ft.newClient(first)
			oldAddr, newAddr := ft.serverAddr(second), ft.serverAddr(first)

			// The second address is not the one the system would reply from.
			require.Equal(t, oldAddr, ft.connect(client, second, 1))
			ft.requireServerSends(client, oldAddr)

			ft.send(client, first, ft.dataPacket("to another address"))
			ft.send(client, first, ft.authPacket(1))
			ft.requireNoReply(client)
			ft.requireNotDelivered()
			ft.requireServerSends(client, oldAddr)

			// The old path stays until the new one is activated.
			ft.send(client, first, ft.authPacket(2))
			require.Equal(t, newAddr, ft.requireAuthReply(client, 2))
			data := ft.dataPacket("on the old path")
			ft.send(client, second, data)
			ft.requireDelivered(data)
			ft.requireServerSends(client, oldAddr)

			data = ft.dataPacket("activate")
			ft.send(client, first, data)
			ft.requireDelivered(data)
			ft.requireServerSends(client, newAddr)

			ft.send(client, second, ft.dataPacket("on the old path"))
			ft.requireNotDelivered()
			ft.requireServerSends(client, newAddr)
		})
	})
}

// Two clients behind one remote address use different local addresses.
func TestUdpFrontendClientsShareRemoteAddress(t *testing.T) {
	first, second := twoLocalAddrs(t)
	forEachSocketKind(t, first, second, func(t *testing.T) {
		ft := startUdpFrontendTest(t, true)
		conn := ft.newClient(first)
		a, b := ft.withClientID(0xa), ft.withClientID(0xb)
		addrA, addrB := ft.serverAddr(first), ft.serverAddr(second)

		require.Equal(t, addrA, a.connect(conn, first, 1))
		require.Equal(t, addrB, b.connect(conn, second, 1))

		for range 2 {
			data := a.dataPacket("from a")
			a.send(conn, first, data)
			a.requireDelivered(data)
			data = b.dataPacket("from b")
			b.send(conn, second, data)
			b.requireDelivered(data)
		}
		a.requireServerSends(conn, addrA)
		b.requireServerSends(conn, addrB)

		// Closing one client keeps the path of the other.
		a.client().Close()
		a.send(conn, first, a.dataPacket("from a"))
		a.requireNotDelivered()
		data := b.dataPacket("from b")
		b.send(conn, second, data)
		b.requireDelivered(data)
		b.requireServerSends(conn, addrB)
	})
}

func TestUdpFrontendReadFromEndsWhenSocketsClose(t *testing.T) {
	socket, err := listenUdpSocket(netip.MustParseAddr("127.0.0.1"), 0, false)
	require.NoError(t, err)
	t.Cleanup(cleanupOnExit)
	frontend := &udpFrontendConn{sockets: []udpSocket{socket}}
	frontend.start(&serverProxy{args: &tsshdArgs{}})

	done := make(chan *clientState, 1)
	go func() {
		_, client := frontend.readFrom(make([]byte, 64))
		done <- client
	}()
	require.NoError(t, socket.Close())

	select {
	case client := <-done:
		require.Nil(t, client)
	case <-time.After(3 * time.Second):
		t.Fatal("readFrom did not return after the sockets closed")
	}
}

func TestUdpFrontendResendsAuthAck(t *testing.T) {
	forEachAttachable(t, func(t *testing.T, attachable bool) {
		ft := startUdpFrontendTest(t, attachable)
		client := ft.newClient("127.0.0.1")

		auth := ft.authPacket(1)

		// The first ACK is deliberately discarded to simulate packet loss
		// from the client's perspective.
		ft.send(client, "127.0.0.1", auth)
		firstFrom := ft.requireAuthReply(client, 1)

		state := ft.client()
		firstPath := state.authedPath.Load()
		require.NotNil(t, firstPath)
		require.Nil(t, state.clientPath.Load())

		// Retransmit the same authentication packet on the same UDP path.
		ft.send(client, "127.0.0.1", auth)
		secondFrom := ft.requireAuthReply(client, 1)

		// The server must resend the ACK on the accepted path without
		// creating a new authenticated path.
		require.Equal(t, firstFrom, secondFrom)
		require.Same(t, firstPath, state.authedPath.Load())
		require.Nil(t, state.clientPath.Load())

		// A non-auth packet activates the authenticated path.
		data := ft.dataPacket("activate")
		ft.send(client, "127.0.0.1", data)
		ft.requireDelivered(data)

		require.Same(t, firstPath, state.clientPath.Load())
		require.Nil(t, state.authedPath.Load())
	})
}
