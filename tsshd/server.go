/*
MIT License

Copyright (c) 2024-2025 The Trzsz SSH Authors.

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
	"crypto/sha1"
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
	"unicode"

	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

const (
	kUdpModeKCP  = "KCP"
	kUdpModeQUIC = "QUIC"
)

const (
	kProxyModeTCP = "TCP"
)

const (
	kDefaultPortRangeLow  = 61001
	kDefaultPortRangeHigh = 61999
)

var quicConfig = quic.Config{
	HandshakeIdleTimeout: 30 * time.Second,
	MaxIdleTimeout:       365 * 24 * time.Hour,
	EnableDatagrams:      true,
}

func initServer(args *tsshdArgs) (*kcp.Listener, *quic.Listener, error) {
	connList, port, err := listenOnFreePort(args)
	if err != nil {
		return nil, nil, err
	}

	info := &ServerInfo{
		ServerVer: kTsshdVersion,
		Port:      port,
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
		quicListener, err = listenQUIC(udpConn, info)
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

func getPortRange(args *tsshdArgs) (int, int) {
	if args.Port == "" {
		return kDefaultPortRangeLow, kDefaultPortRangeHigh
	}
	ports := strings.FieldsFunc(args.Port, func(c rune) bool {
		return unicode.IsSpace(c) || c == ',' || c == '-'
	})
	if len(ports) == 1 {
		if port, err := strconv.Atoi(ports[0]); err == nil {
			return port, port
		}
	} else if len(ports) == 2 {
		port0, err0 := strconv.Atoi(ports[0])
		port1, err1 := strconv.Atoi(ports[1])
		if err0 == nil && err1 == nil {
			return port0, port1
		}
	}
	return kDefaultPortRangeLow, kDefaultPortRangeHigh
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
	portRangeLow, portRangeHigh := getPortRange(args)
	if portRangeHigh < portRangeLow {
		return nil, 0, fmt.Errorf("no port in [%d,%d]", portRangeLow, portRangeHigh)
	}
	addrs, err := getUdpAddrs(args)
	if err != nil {
		return nil, 0, fmt.Errorf("get available udp address failed: %v", err)
	}
	var lastErr error
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
	if lastErr != nil {
		return nil, 0, fmt.Errorf("listen udp on [%d,%d] failed: %v", portRangeLow, portRangeHigh, lastErr)
	}
	return nil, 0, fmt.Errorf("listen udp on [%d,%d] failed", portRangeLow, portRangeHigh)
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
	pass := make([]byte, 32)
	if _, err := crypto_rand.Read(pass); err != nil {
		return nil, fmt.Errorf("rand pass failed: %v", err)
	}
	salt := make([]byte, 32)
	if _, err := crypto_rand.Read(salt); err != nil {
		return nil, fmt.Errorf("rand salt failed: %v", err)
	}
	key := pbkdf2.Key(pass, salt, 4096, 32, sha1.New)

	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("new aes block crypt failed: %v", err)
	}

	listener, err := kcp.ServeConn(block, 1, 1, conn)
	if err != nil {
		return nil, fmt.Errorf("kcp serve conn failed: %v", err)
	}

	info.Mode = kUdpModeKCP
	info.Pass = fmt.Sprintf("%x", pass)
	info.Salt = fmt.Sprintf("%x", salt)
	return listener, nil
}

func listenQUIC(conn *net.UDPConn, info *ServerInfo) (*quic.Listener, error) {
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
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
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
