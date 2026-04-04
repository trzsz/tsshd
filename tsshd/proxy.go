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
	"sync"

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
	return writeAll(conn, buf)
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

const kSampleCacheSize = 10
const kPacketCacheSize = 100

type packetCache struct {
	mutex      sync.Mutex
	firstBuf   [][]byte
	recentBuf  [][]byte
	recentIdx  int
	totalSize  int
	totalCount int
	sampleIdx  int
	sampleBuf  [kSampleCacheSize][]byte
}

func (p *packetCache) addSample(buf []byte) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	data := make([]byte, len(buf))
	copy(data, buf)

	p.sampleBuf[p.sampleIdx] = data
	p.sampleIdx = p.sampleIdx + 1
	if p.sampleIdx >= kSampleCacheSize {
		p.sampleIdx = 0
	}
}

func (p *packetCache) addPacket(buf []byte) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.totalSize += len(buf)
	p.totalCount++

	data := make([]byte, len(buf))
	copy(data, buf)

	if len(p.firstBuf) < kPacketCacheSize {
		if p.firstBuf == nil {
			p.firstBuf = make([][]byte, 0, kPacketCacheSize)
		}
		p.firstBuf = append(p.firstBuf, data)
		return
	}

	if len(p.recentBuf) < kPacketCacheSize {
		if p.recentBuf == nil {
			p.recentBuf = make([][]byte, 0, kPacketCacheSize)
		}
		p.recentBuf = append(p.recentBuf, data)
		return
	}

	p.recentBuf[p.recentIdx] = data
	p.recentIdx = p.recentIdx + 1
	if p.recentIdx >= kPacketCacheSize {
		p.recentIdx = 0
	}
}

func (p *packetCache) sendCache(writeFn func([]byte) error) (flushSize, flushCount int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var once sync.Once

	for i := range kSampleCacheSize {
		buf := p.sampleBuf[(p.sampleIdx+i)%kSampleCacheSize]
		if len(buf) == 0 {
			continue
		}
		if err := writeFn(buf); err != nil {
			once.Do(func() { debug("send cache failed: %v", err) })
		}
		flushSize += len(buf)
		flushCount++
	}

	for _, buf := range p.firstBuf {
		if err := writeFn(buf); err != nil {
			once.Do(func() { debug("send cache failed: %v", err) })
		}
		flushSize += len(buf)
		flushCount++
	}

	for i := range len(p.recentBuf) {
		buf := p.recentBuf[(p.recentIdx+i)%kPacketCacheSize]
		if err := writeFn(buf); err != nil {
			once.Do(func() { debug("send cache failed: %v", err) })
		}
		flushSize += len(buf)
		flushCount++
	}

	return flushSize, flushCount
}

func (p *packetCache) clearCache() (totalSize, totalCount int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i := range kSampleCacheSize {
		p.sampleBuf[i] = nil
	}

	p.firstBuf, p.recentBuf, p.recentIdx = nil, nil, 0

	totalSize, totalCount = p.totalSize, p.totalCount
	p.totalSize, p.totalCount = 0, 0
	return
}
