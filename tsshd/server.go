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
	"crypto/ecdsa"
	"crypto/elliptic"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	math_rand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
)

const (
	kUdpModeKCP  = "KCP"
	kUdpModeQUIC = "QUIC"
)

const (
	kProxyModeTCP = "TCP"
)

const kDefaultPortRange = "61001-61999"

const (
	kDefaultMTU = 1400

	kQuicMinMTU = 1200
	kQuicMaxMTU = 1452
	// 1 /* type byte */ + 20 /* maximum connection ID length */ + 16 /* tag size */
	kQuicShortHeaderSize = 37
)

var quicConfig = quic.Config{
	HandshakeIdleTimeout: 30 * time.Second,
	MaxIdleTimeout:       365 * 24 * time.Hour,
	EnableDatagrams:      true,
}

var globalProtoServer protocolServer

type protocolServer interface {
	getUdpForwarder() *udpForwarder
	handleRekeyEvent(msg *rekeyMessage) error
}

type kcpServer struct {
	crypto    *rotatingCrypto
	forwarder *udpForwarder
}

func (s *kcpServer) getUdpForwarder() *udpForwarder {
	return s.forwarder
}

func (s *kcpServer) handleRekeyEvent(msg *rekeyMessage) error {
	if err := s.crypto.handleServerRekey(msg); err != nil {
		return fmt.Errorf("rekey failed: %v", err)
	}
	return nil
}

type quicServer struct {
	forwarder *udpForwarder
}

func (s *quicServer) getUdpForwarder() *udpForwarder {
	return s.forwarder
}

func (s *quicServer) handleRekeyEvent(msg *rekeyMessage) error {
	// rekey is handled by QUIC internally
	return nil
}

func initServer(args *tsshdArgs) (*kcp.Listener, *quic.Listener, error) {
	connList, port, err := listenOnFreePort(args)
	if err != nil {
		return nil, nil, err
	}

	info := &ServerInfo{
		ServerVer: kTsshdVersion,
		Port:      port,
		MTU:       args.MTU,
	}

	udpConn, err := startServerProxy(args, info, connList)
	if err != nil {
		return nil, nil, err
	}

	var kcpListener *kcp.Listener
	var quicListener *quic.Listener
	if args.KCP {
		kcpListener, err = listenKCP(udpConn, info)
	} else {
		quicListener, err = listenQUIC(udpConn, info, args.MTU)
	}
	if err != nil {
		return nil, nil, err
	}

	infoStr, err := json.Marshal(info)
	if err != nil {
		if kcpListener != nil {
			_ = kcpListener.Close()
		}
		if quicListener != nil {
			_ = quicListener.Close()
		}
		return nil, nil, fmt.Errorf("json marshal failed: %v", err)
	}
	fmt.Printf("\a%s\r\n", string(infoStr))

	return kcpListener, quicListener, nil
}

func parsePortRanges(tsshdPort string) [][2]uint16 {
	var ranges [][2]uint16

	addPortRange := func(lowPort string, highPort *string) {
		low, err := strconv.ParseUint(lowPort, 10, 16)
		if err != nil || low == 0 {
			warning("tsshd port [%s] invalid: port [%s] is not a value in [1, 65535]", tsshdPort, lowPort)
			return
		}
		high := low
		if highPort != nil {
			high, err = strconv.ParseUint(*highPort, 10, 16)
			if err != nil || high == 0 {
				warning("tsshd port [%s] invalid: port [%s] is not a value in [1, 65535]", tsshdPort, *highPort)
				return
			}
		}
		if low > high {
			warning("tsshd port [%s] invalid: port range [%d-%d] is invalid (low > high)", tsshdPort, low, high)
			return
		}
		ranges = append(ranges, [2]uint16{uint16(low), uint16(high)})
	}

	for seg := range strings.SplitSeq(tsshdPort, ",") {
		tokens := strings.Fields(seg)
		k := -1
		for i := 0; i < len(tokens); i++ {
			token := tokens[i]
			// Case 1: combined form like "8000-9000"
			if strings.Contains(token, "-") && token != "-" {
				parts := strings.Split(token, "-")
				if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
					warning("tsshd port [%s] invalid: malformed port range [%s]", tsshdPort, token)
					continue
				}
				addPortRange(parts[0], &parts[1])
				continue
			}
			// Case 2: single "-"
			if token == "-" {
				if i == 0 || i+1 >= len(tokens) || i-1 <= k {
					warning("tsshd port [%s] invalid: '-' must appear between two ports", tsshdPort)
					i++
					continue
				}
				addPortRange(tokens[i-1], &tokens[i+1])
				k = i + 1
				i++ // skip high
				continue
			}
			// Case 3: part of a range: skip (handled by '-')
			if i+1 < len(tokens) && tokens[i+1] == "-" {
				continue
			}
			// Case 4: plain number
			if i > 0 && tokens[i-1] == "-" {
				warning("tsshd port [%s] invalid: malformed port range [- %s]", tsshdPort, token)
				continue
			}
			addPortRange(token, nil)
		}
	}

	return ranges
}

func canListenOnIP(args *tsshdArgs, udpAddr *net.UDPAddr) bool {
	var err error
	var conn io.Closer
	if args.TCP {
		conn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: udpAddr.IP, Zone: udpAddr.Zone})
	} else {
		conn, err = net.ListenUDP("udp", udpAddr)
	}
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func getUdpAddrs(args *tsshdArgs) ([]*net.UDPAddr, error) {
	if sshConnection := os.Getenv("SSH_CONNECTION"); sshConnection != "" {
		if tokens := strings.Fields(sshConnection); len(tokens) >= 3 {
			ip := tokens[2]
			if strings.HasPrefix(strings.ToLower(ip), "::ffff:") {
				ip = ip[7:]
			}
			var addr string
			if !strings.HasPrefix(ip, "[") && strings.ContainsRune(ip, ':') {
				addr = fmt.Sprintf("[%s]:0", ip)
			} else {
				addr = fmt.Sprintf("%s:0", ip)
			}
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err == nil && canListenOnIP(args, udpAddr) {
				return []*net.UDPAddr{udpAddr}, nil
			}
		}
	}

	var udpAddrs []*net.UDPAddr
	ipv4Only := args.IPv4 && !args.IPv6
	ipv6Only := !args.IPv4 && args.IPv6
	addListenableAddr := func(ip net.IP, zone string) {
		if ip.To4() != nil { // ipv4
			if ipv6Only {
				return
			}
			udpAddr := &net.UDPAddr{IP: ip}
			if canListenOnIP(args, udpAddr) {
				udpAddrs = append(udpAddrs, udpAddr)
			}
		} else if ip.To16() != nil { // ipv6
			if ipv4Only {
				return
			}
			udpAddr := &net.UDPAddr{IP: ip, Zone: zone}
			if canListenOnIP(args, udpAddr) {
				udpAddrs = append(udpAddrs, udpAddr)
			}
		}
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err == nil {
				for _, addr := range addrs {
					switch v := addr.(type) {
					case *net.IPNet:
						addListenableAddr(v.IP, iface.Name)
					case *net.IPAddr:
						addListenableAddr(v.IP, iface.Name)
					}
				}
			}
		}
	}

	if len(udpAddrs) == 0 {
		udpAddr, err := net.ResolveUDPAddr("udp", ":0")
		if err != nil {
			return nil, err
		}
		return []*net.UDPAddr{udpAddr}, nil
	}

	return udpAddrs, nil
}

func listenOnFreePort(args *tsshdArgs) ([]io.Closer, int, error) {
	tsshdPort := args.Port
	if tsshdPort == "" {
		tsshdPort = kDefaultPortRange
	}
	portRanges := parsePortRanges(tsshdPort)
	if len(portRanges) == 0 {
		return nil, 0, fmt.Errorf("no available port in [%s]", tsshdPort)
	}
	if len(portRanges) > 1 {
		math_rand.Shuffle(len(portRanges), func(i, j int) {
			portRanges[i], portRanges[j] = portRanges[j], portRanges[i]
		})
	}

	addrs, err := getUdpAddrs(args)
	if err != nil {
		return nil, 0, fmt.Errorf("get available udp address failed: %v", err)
	}

	var lastErr error
	for _, portRange := range portRanges {
		portRangeLow, portRangeHigh := int(portRange[0]), int(portRange[1])
		size := portRangeHigh - portRangeLow + 1
		port := portRangeLow + math_rand.Intn(size)
		for range size {
			var connList []io.Closer
			for _, addr := range addrs {
				conn, err := listenOnPort(args, addr, port)
				if err != nil {
					lastErr = err
					break
				}
				connList = append(connList, conn)
			}
			if len(connList) == len(addrs) {
				return connList, port, nil
			}
			for _, conn := range connList {
				_ = conn.Close()
			}
			port++
			if port > portRangeHigh {
				port = portRangeLow
			}
		}
	}

	if lastErr != nil {
		return nil, 0, fmt.Errorf("listen udp on [%s] failed: %v", tsshdPort, lastErr)
	}
	return nil, 0, fmt.Errorf("listen udp on [%s] failed", tsshdPort)
}

func listenOnPort(args *tsshdArgs, udpAddr *net.UDPAddr, port int) (conn io.Closer, err error) {
	if args.TCP {
		conn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: udpAddr.IP, Port: port, Zone: udpAddr.Zone})
	} else {
		udpAddr.Port = port
		conn, err = net.ListenUDP("udp", udpAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("listen on [%s] failed: %v", udpAddr.String(), err)
	}
	return conn, nil
}

func listenKCP(conn *net.UDPConn, info *ServerInfo) (*kcp.Listener, error) {
	pass := make([]byte, 48)
	if _, err := crypto_rand.Read(pass); err != nil {
		return nil, fmt.Errorf("rand pass failed: %v", err)
	}
	salt := make([]byte, 48)
	if _, err := crypto_rand.Read(salt); err != nil {
		return nil, fmt.Errorf("rand salt failed: %v", err)
	}

	crypto, err := newRotatingCrypto(nil, pass, salt, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("new rotating gcm failed: %w", err)
	}
	block := kcp.NewAEADCrypt(crypto)

	globalProtoServer = &kcpServer{crypto: crypto}

	listener, err := kcp.ServeConn(block, 1, 1, conn)
	if err != nil {
		return nil, fmt.Errorf("kcp serve conn failed: %v", err)
	}

	info.Mode = kUdpModeKCP
	info.Pass = fmt.Sprintf("%x", pass)
	info.Salt = fmt.Sprintf("%x", salt)
	return listener, nil
}

func listenQUIC(conn net.PacketConn, info *ServerInfo, mtu uint16) (*quic.Listener, error) {
	serverCertPEM, serverKeyPEM, err := generateCertKeyPair()
	if err != nil {
		return nil, err
	}
	clientCertPEM, clientKeyPEM, err := generateCertKeyPair()
	if err != nil {
		return nil, err
	}

	serverTlsCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("x509 key pair failed: %v", err)
	}

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCertPEM)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTlsCert},
		ClientCAs:    clientCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	if mtu > 0 {
		quicConfig.InitialPacketSize = mtu
		quicConfig.DisablePathMTUDiscovery = true
	} else {
		quicConfig.InitialPacketSize = kDefaultMTU
	}

	listener, err := (&quic.Transport{Conn: conn}).Listen(tlsConfig, &quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic listen failed: %v", err)
	}

	info.Mode = kUdpModeQUIC
	info.ServerCert = fmt.Sprintf("%x", serverCertPEM)
	info.ClientCert = fmt.Sprintf("%x", clientCertPEM)
	info.ClientKey = fmt.Sprintf("%x", clientKeyPEM)

	return listener, nil
}

func generateCertKeyPair() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa generate key failed: %v", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"tsshd"},
		NotBefore:    now.AddDate(0, 0, -1),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(crypto_rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("x509 create certificate failed: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("x509 marshal ec private key failed: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}
