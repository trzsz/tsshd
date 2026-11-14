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

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// replySourceSupported reports whether a wildcard socket can set the reply source.
// FreeBSD can only for IPv6.
func replySourceSupported(ipv6 bool) bool {
	return ipv6 || runtime.GOOS != "freebsd"
}

// pktInfoSocket is a wildcard socket of one family that sees each packet's
// destination address and can send from a chosen address.
type pktInfoSocket struct {
	conn *net.UDPConn
	ipv6 bool
	oob  []byte // used by readFrom only
}

func newPktInfoSocket(conn *net.UDPConn) (udpSocket, error) {
	s := &pktInfoSocket{conn: conn, ipv6: conn.LocalAddr().(*net.UDPAddr).IP.To4() == nil}
	if s.ipv6 {
		if err := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst, true); err != nil {
			return nil, err
		}
		s.oob = ipv6.NewControlMessage(ipv6.FlagDst)
	} else {
		if err := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst, true); err != nil {
			return nil, err
		}
		s.oob = ipv4.NewControlMessage(ipv4.FlagDst)
	}
	return s, nil
}

func (s *pktInfoSocket) readFrom(buf []byte) (int, netip.AddrPort, netip.Addr, error) {
	n, oobn, _, remote, err := s.conn.ReadMsgUDPAddrPort(buf, s.oob)
	if err != nil {
		return 0, remote, netip.Addr{}, err
	}

	var dst net.IP
	if s.ipv6 {
		var cm ipv6.ControlMessage
		if cm.Parse(s.oob[:oobn]) == nil {
			dst = cm.Dst
		}
	} else {
		var cm ipv4.ControlMessage
		if cm.Parse(s.oob[:oobn]) == nil {
			dst = cm.Dst
		}
	}
	local, _ := netip.AddrFromSlice(dst)
	return n, remote, local.Unmap(), nil
}

func (s *pktInfoSocket) replyOOB(local netip.Addr) []byte {
	if !local.IsValid() {
		return nil
	}
	if s.ipv6 {
		return (&ipv6.ControlMessage{Src: local.AsSlice()}).Marshal()
	}
	return (&ipv4.ControlMessage{Src: local.AsSlice()}).Marshal()
}

func (s *pktInfoSocket) writeTo(buf []byte, remote netip.AddrPort, oob []byte) error {
	_, _, err := s.conn.WriteMsgUDPAddrPort(buf, oob, remote)
	return err
}

func (s *pktInfoSocket) Close() error {
	return s.conn.Close()
}
