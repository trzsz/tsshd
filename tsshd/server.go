/*
MIT License

Copyright (c) 2024 The Trzsz SSH Authors.

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
	crypto_rand "crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	math_rand "math/rand"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

const kDefaultPortRangeLow = 61001

const kDefaultPortRangeHigh = 61999

func initServer(args *tsshdArgs) (*kcp.Listener, error) {
	portRangeLow := kDefaultPortRangeLow
	portRangeHigh := kDefaultPortRangeHigh
	conn, port := listenOnFreePort(portRangeLow, portRangeHigh)
	if conn == nil {
		return nil, fmt.Errorf("no free udp port in [%d, %d]", portRangeLow, portRangeHigh)
	}

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

	svrInfo := ServerInfo{
		Ver:  kTsshdVersion,
		Pass: fmt.Sprintf("%x", pass),
		Salt: fmt.Sprintf("%x", salt),
		Port: port,
	}
	info, err := json.Marshal(svrInfo)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("json marshal failed: %v\n", err)
	}
	fmt.Printf("\a%s\r\n", string(info))

	return listener, nil
}

func listenOnFreePort(low, high int) (*net.UDPConn, int) {
	if high < low {
		return nil, -1
	}
	size := high - low + 1
	port := low + math_rand.Intn(size)
	for i := 0; i < size; i++ {
		if conn := listenOnPort(port); conn != nil {
			return conn, port
		}
		port++
		if port > high {
			port = low
		}
	}
	return nil, -1
}

func listenOnPort(port int) *net.UDPConn {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil
	}
	return conn
}
