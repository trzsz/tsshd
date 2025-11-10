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
	kModeKCP  = "KCP"
	kModeQUIC = "QUIC"
)

const (
	kDefaultPortRangeLow  = 61001
	kDefaultPortRangeHigh = 61999
)

var quicConfig = quic.Config{
	HandshakeIdleTimeout: 30 * time.Second,
	MaxIdleTimeout:       365 * 24 * time.Hour,
}

func initServer(args *tsshdArgs) (*kcp.Listener, *quic.Listener, error) {
	conn, port, err := listenUdpOnFreePort(args)
	if err != nil {
		return nil, nil, err
	}

	info := &ServerInfo{
		Ver:  kTsshdVersion,
		Port: port,
	}

	if args.Proxy {
		conn, err = startServerProxy(conn, info, args.ConnectTimeout)
		if err != nil {
			return nil, nil, err
		}
	}

	for i := 1; i < len(conn); i++ {
		_ = conn[i].Close()
	}

	var kcpListener *kcp.Listener
	var quicListener *quic.Listener
	if args.KCP {
		kcpListener, err = listenKCP(conn[0], info)
	} else {
		quicListener, err = listenQUIC(conn[0], info)
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

func canListenOnUDP(udpAddr *net.UDPAddr) bool {
	conn, err := net.ListenUDP("udp", udpAddr)
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
			udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", ip))
			if err == nil && canListenOnUDP(udpAddr) {
				return []*net.UDPAddr{udpAddr}, nil
			}
		}
	}

	var udpAddrs []*net.UDPAddr
	ifaceAddrs, err := net.InterfaceAddrs()
	if err == nil {
		ipv4Only := args.IPv4 && !args.IPv6
		ipv6Only := !args.IPv4 && args.IPv6
		for _, addr := range ifaceAddrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.IsLoopback() {
					continue
				}
				if ipNet.IP.To4() != nil && !ipv6Only {
					addr := &net.UDPAddr{IP: ipNet.IP}
					if canListenOnUDP(addr) {
						udpAddrs = append(udpAddrs, addr)
					}
				} else if ipNet.IP.To16() != nil && !ipv4Only {
					var zone string
					if ipAddr, ok := addr.(*net.IPAddr); ok {
						zone = ipAddr.Zone
					}
					addr := &net.UDPAddr{IP: ipNet.IP, Zone: zone}
					if canListenOnUDP(addr) {
						udpAddrs = append(udpAddrs, addr)
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

func listenUdpOnFreePort(args *tsshdArgs) ([]*net.UDPConn, int, error) {
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
		var connList []*net.UDPConn
		for _, addr := range addrs {
			conn, err := listenUdpOnPort(addr, port)
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

func listenUdpOnPort(udpAddr *net.UDPAddr, port int) (*net.UDPConn, error) {
	udpAddr.Port = port
	conn, err := net.ListenUDP("udp", udpAddr)
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

	listener, err := kcp.ServeConn(block, 10, 3, conn)
	if err != nil {
		return nil, fmt.Errorf("kcp serve conn failed: %v", err)
	}

	info.Mode = kModeKCP
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

	info.Mode = kModeQUIC
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
