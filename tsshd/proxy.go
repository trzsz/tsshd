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

const kSampleCacheSize = 10
const kPacketCacheSize = 100

type packetGroup struct {
	buf [][]byte
	idx int
}

func (p *packetGroup) addPacket(data []byte) {
	if len(p.buf) < kPacketCacheSize {
		if p.buf == nil {
			p.buf = make([][]byte, 0, kPacketCacheSize)
		}
		p.buf = append(p.buf, data)
		return
	}

	p.buf[p.idx] = data
	p.idx = p.idx + 1
	if p.idx >= kPacketCacheSize {
		p.idx = 0
	}
}

func (p *packetGroup) sendCache(writeFn func([]byte) error) (size, count uint64, err error) {
	for i := range len(p.buf) {
		buf := p.buf[(p.idx+i)%kPacketCacheSize]
		if e := writeFn(buf); e != nil {
			err = e
		}
		size += uint64(len(buf))
		count++
		time.Sleep(time.Millisecond)
	}
	return
}

type packetCache struct {
	mutex      sync.Mutex
	totalSize  uint64
	totalCount uint64
	sampleIdx  int
	sampleBuf  [kSampleCacheSize][]byte
	reactive   packetGroup
	proactive  packetGroup
	peerCheck  atomic.Pointer[timeoutChecker]
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

	p.totalSize += uint64(len(buf))
	p.totalCount++

	data := make([]byte, len(buf))
	copy(data, buf)

	// ACK packets can dominate the cache during reconnection.
	//
	// A typical failure scenario is:
	//
	//   1. A heartbeat packet is cached but fails to reach the peer.
	//   2. After reconnecting, a large amount of buffered output arrives.
	//   3. KCP generates many ACK packets.
	//   4. The ACK packets fill the proxy cache and evict the heartbeat packet.
	//   5. On the next reconnect attempt, only cached ACK packets are resent.
	//   6. More output arrives, generating even more ACK packets.
	//
	// This cycle can continue until a non-ACK packet (such as a heartbeat)
	// happens to remain in the cache. Since heartbeat packet may be generated
	// only once every 60 seconds, recovery can be delayed significantly.
	//
	// To improve recovery speed, packets are separated into two groups:
	//
	//   - reactive: sent shortly after receiving peer traffic, likely ACKs
	//   - proactive: sent without recent peer activity, likely heartbeats
	//     or application-generated packets
	//
	// Proactive packets are kept separate so they are less likely to be
	// displaced by large bursts of ACK traffic.
	if c := p.peerCheck.Load(); c != nil && time.Now().UnixMilli()-c.lastAliveTime.Load() > 300 {
		p.proactive.addPacket(data)
	} else {
		p.reactive.addPacket(data)
	}
}

func (p *packetCache) sendCache(writeFn func([]byte) error) (uint64, uint64, uint64, uint64) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var once sync.Once
	var wg sync.WaitGroup

	var totalSize, sampleCount, reactiveCount, proactiveCount atomic.Uint64

	wg.Go(func() {
		size, count, err := p.proactive.sendCache(writeFn)
		if err != nil {
			once.Do(func() { debug("send cache failed: %v", err) })
		}
		totalSize.Add(size)
		proactiveCount.Store(count)
	})

	wg.Go(func() {
		size, count, err := p.reactive.sendCache(writeFn)
		if err != nil {
			once.Do(func() { debug("send cache failed: %v", err) })
		}
		totalSize.Add(size)
		reactiveCount.Store(count)
	})

	wg.Go(func() {
		for i := range kSampleCacheSize {
			buf := p.sampleBuf[(p.sampleIdx+i)%kSampleCacheSize]
			if len(buf) == 0 {
				continue
			}
			if err := writeFn(buf); err != nil {
				once.Do(func() { debug("send cache failed: %v", err) })
			}
			totalSize.Add(uint64(len(buf)))
			sampleCount.Add(1)
			time.Sleep(time.Millisecond)
		}
	})

	wg.Wait()

	return totalSize.Load(), sampleCount.Load(), reactiveCount.Load(), proactiveCount.Load()
}

func (p *packetCache) clearCache() (totalSize, totalCount uint64) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i := range kSampleCacheSize {
		p.sampleBuf[i] = nil
	}

	p.reactive.buf, p.reactive.idx = nil, 0

	p.proactive.buf, p.proactive.idx = nil, 0

	totalSize, totalCount = p.totalSize, p.totalCount
	p.totalSize, p.totalCount = 0, 0
	return
}
