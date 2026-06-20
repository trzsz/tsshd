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
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const kProxyBufferSize = 1024 * 1024

const kProxyDSCP = 46

// For QUIC/KCP encrypted packets, the authentication tag is 16 bytes.
// Packets with length <= 16 bytes cannot be valid and are safe to drop.
const kSafeToDropPacketLen = 16

func setDSCP(conn net.Conn, dscp int) {
	_ = ipv4.NewConn(conn).SetTOS(dscp << 2)
	_ = ipv6.NewConn(conn).SetTrafficClass(dscp)
}

func aesEncrypt(cipherBlock *cipher.Block, buf []byte) []byte {
	gcm, err := cipher.NewGCM(*cipherBlock)
	if err != nil {
		return nil
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := crypto_rand.Read(nonce); err != nil {
		return nil
	}
	return gcm.Seal(nonce, nonce, buf, nil)
}

func aesDecrypt(cipherBlock *cipher.Block, buf []byte) []byte {
	gcm, err := cipher.NewGCM(*cipherBlock)
	if err != nil {
		return nil
	}
	nonceSize := gcm.NonceSize()
	if len(buf) < nonceSize {
		return nil
	}
	nonce, cipherText := buf[:nonceSize], buf[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil
	}
	return plainText
}

func sendUdpPacket(conn io.Writer, data []byte) error {
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	copy(buf[2:], data)
	// Packet writes must be issued as a single Write call.
	// Retrying partial writes could interleave packets when
	// multiple goroutines send cached packets concurrently.
	n, err := conn.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}

func recvUdpPacket(conn io.Reader, data []byte) (int, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(buf))
	if n < 0 || n > len(data) {
		return 0, fmt.Errorf("decoded frame length out of range: length=%d, buffer=%d", n, len(data))
	}
	if _, err := io.ReadFull(conn, data[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

type trafficStats struct {
	recFlag   atomic.Bool
	sendCount atomic.Uint64
	sendBytes atomic.Uint64
	recvCount atomic.Uint64
	recvBytes atomic.Uint64
	lastMilli atomic.Int64
}

func (s *trafficStats) resetStats() {
	s.sendCount.Store(0)
	s.sendBytes.Store(0)
	s.recvCount.Store(0)
	s.recvBytes.Store(0)
	s.lastMilli.Store(time.Now().UnixMilli())
}

func (s *trafficStats) flushLog() string {
	sc := s.sendCount.Swap(0)
	sb := s.sendBytes.Swap(0)
	rc := s.recvCount.Swap(0)
	rb := s.recvBytes.Swap(0)

	if sc == 0 && rc == 0 {
		s.lastMilli.Store(time.Now().UnixMilli())
		return ""
	}

	now := time.Now().UnixMilli()
	last := s.lastMilli.Swap(now)

	return fmt.Sprintf("udp traffic: duration=%dms, send=%d(%dB), recv=%d(%dB)", now-last, sc, sb, rc, rb)
}
