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
)

// udpSocket is a listening socket of the UDP frontend. local is the address a
// packet was sent to, if the socket knows it.
type udpSocket interface {
	// readFrom must not be called concurrently.
	readFrom(buf []byte) (n int, remote netip.AddrPort, local netip.Addr, err error)

	// replyOOB returns the control data for sending from local, or nil. It allocates.
	replyOOB(local netip.Addr) []byte

	writeTo(buf []byte, remote netip.AddrPort, oob []byte) error

	Close() error
}

// plainSocket reports the address it is bound to as local. It may be a wildcard.
type plainSocket struct {
	conn  *net.UDPConn
	local netip.Addr
}

func (s *plainSocket) readFrom(buf []byte) (int, netip.AddrPort, netip.Addr, error) {
	n, remote, err := s.conn.ReadFromUDPAddrPort(buf)
	return n, remote, s.local, err
}

func (s *plainSocket) replyOOB(netip.Addr) []byte {
	return nil
}

func (s *plainSocket) writeTo(buf []byte, remote netip.AddrPort, _ []byte) error {
	_, err := s.conn.WriteToUDPAddrPort(buf, remote)
	return err
}

func (s *plainSocket) Close() error {
	return s.conn.Close()
}

// canSelectReplySource reports whether a wildcard socket of network can choose
// the reply source. It is a variable for tests.
var canSelectReplySource = func(network string) bool {
	ipv6 := network == "udp6"
	if !replySourceSupported(ipv6) {
		return false
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_, err = newPktInfoSocket(conn, ipv6)
	return err == nil
}

// listenUdpSocket opens a socket on addr. With replySource, addr must be a wildcard.
func listenUdpSocket(addr netip.Addr, port int, replySource bool) (udpSocket, error) {
	addr = addr.Unmap()
	conn, err := net.ListenUDP(ipNetwork("udp", addr), net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, uint16(port))))
	if err != nil {
		return nil, err
	}

	setDSCP(conn, kProxyDSCP)
	_ = conn.SetReadBuffer(kProxyBufferSize)
	_ = conn.SetWriteBuffer(kProxyBufferSize)

	if !replySource {
		return &plainSocket{conn, addr}, nil
	}
	sock, err := newPktInfoSocket(conn, addr.Is6())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return sock, nil
}
