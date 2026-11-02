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
	"strings"
)

// An unspecified IPv6 address may also accept IPv4; report no restriction.
func listenerAddressFamily(addr net.Addr) string {
	var ip net.IP
	switch addr := addr.(type) {
	case *net.UDPAddr:
		ip = addr.IP
	case *net.TCPAddr:
		ip = addr.IP
	}
	if ip.To4() != nil {
		return "inet"
	}
	// "::" is reported as unrestricted: listeners use "udp"/"tcp", so a
	// wildcard IPv6 socket is dual-stack and also accepts IPv4.
	if ip.To16() != nil && !ip.IsUnspecified() {
		return "inet6"
	}
	return ""
}

func commonAddressFamily(families []string) string {
	if len(families) == 0 {
		return ""
	}
	family := families[0]
	for _, other := range families[1:] {
		if family != other {
			return ""
		}
	}
	return family
}

// listenNetwork restricts a wildcard listener to one family: "0.0.0.0" and
// "::" with a plain "udp"/"tcp" network would open a dual-stack socket.
// Specific addresses already select their family, and a nil IP stays
// unrestricted.
func listenNetwork(network string, ip net.IP) string {
	if ip == nil || !ip.IsUnspecified() {
		return network
	}
	if ip.To4() != nil {
		return network + "4"
	}
	return network + "6"
}

// socketAddressFamily reports the family of a listener opened on network,
// where a "udp6"/"tcp6" wildcard socket is IPv6-only rather than dual-stack.
func socketAddressFamily(network string, addr net.Addr) string {
	if strings.HasSuffix(network, "6") {
		return "inet6"
	}
	return listenerAddressFamily(addr)
}
