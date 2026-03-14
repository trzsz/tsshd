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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	crypto_rand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
)

const kRekeyTimeThreshold = time.Hour

const kRekeyBytesThreshold = 1024 * 1024 * 1024 // 1G

const kcpMemLayoutUnexpected = "Unexpected KCP crypto memory layout detected"

type rotatingCrypto struct {
	mutex            sync.Mutex
	client           *SshUdpClient
	keyPass          []byte
	keySalt          []byte
	gcmList          []cipher.AEAD
	activeIdx        int
	bytesConsumed    uint64
	bytesThreshold   uint64
	bytesTriggered   bool
	rekeyInFlight    atomic.Bool
	clientPriKey     *ecdh.PrivateKey
	closed           atomic.Bool
	stopCh           chan struct{}
	delegatedToProxy bool
}

func (r *rotatingCrypto) NonceSize() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.gcmList[r.activeIdx].NonceSize()
}

func (r *rotatingCrypto) Overhead() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.gcmList[r.activeIdx].Overhead()
}

func (r *rotatingCrypto) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if r.delegatedToProxy {
		plainLen := len(plaintext)
		if plainLen == 0 {
			return dst
		}
		dstLen := len(dst)
		newLen := dstLen + plainLen
		if cap(dst) >= newLen && &dst[:newLen][dstLen] == &plaintext[0] {
			return dst[:newLen]
		}
		debug("%s", kcpMemLayoutUnexpected)
		return append(dst, plaintext...)
	}

	r.mutex.Lock()
	gcm := r.gcmList[r.activeIdx]
	r.mutex.Unlock()

	r.consumeBytes(uint64(len(plaintext)))

	return gcm.Seal(dst, nonce, plaintext, additionalData)
}

func (r *rotatingCrypto) sealPacket(buf []byte) ([]byte, error) {
	nonceSize := r.NonceSize()
	if len(buf) < nonceSize {
		return nil, io.ErrShortBuffer
	}
	dst := buf[:nonceSize]
	nonce := buf[:nonceSize]
	plaintext := buf[nonceSize:]
	buf = r.Seal(dst, nonce, plaintext, nil)
	return buf, nil
}

func (r *rotatingCrypto) Open(dst, nonce, ciphertext, additionalData []byte) (plaintext []byte, err error) {
	if r.delegatedToProxy {
		return ciphertext, nil
	}

	r.mutex.Lock()
	gcmList := r.gcmList[:]
	r.mutex.Unlock()

	lastIdx := len(gcmList) - 1
	for i, gcm := range gcmList {
		buf := dst
		if i != lastIdx {
			buf = nil
		}
		plaintext, err = gcm.Open(buf, nonce, ciphertext, additionalData)
		if err != nil {
			r.debug("gcm [%d/%d] open failed: %v", i+1, len(gcmList), err)
			continue
		}
		if i > 0 {
			r.promoteKey(i)
		} else {
			r.consumeBytes(uint64(len(plaintext)))
		}
		return plaintext, nil
	}

	if err == nil {
		return nil, fmt.Errorf("gcm open failed: no available keys")
	}
	return nil, fmt.Errorf("gcm open failed: %w", err)
}

func (r *rotatingCrypto) openPacket(buf []byte) (int, error) {
	overhead := r.Overhead()
	nonceSize := r.NonceSize()
	if len(buf) < nonceSize+overhead {
		return 0, io.ErrShortBuffer
	}

	nonce := buf[:nonceSize]
	ciphertext := buf[nonceSize:]
	plaintext, err := r.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	if len(plaintext) > 0 && &plaintext[0] != &ciphertext[0] {
		copy(ciphertext[:0], plaintext)
	}

	return nonceSize + len(plaintext), nil
}

func (r *rotatingCrypto) debug(format string, a ...any) {
	if r.client != nil {
		r.client.debug(format, a...)
	} else {
		debug(format, a...)
	}
}

func (r *rotatingCrypto) consumeBytes(n uint64) {
	if r.bytesThreshold == 0 {
		return
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.bytesConsumed += n

	if r.bytesConsumed > r.bytesThreshold && !r.bytesTriggered {
		r.bytesTriggered = true
		r.debug("byte-based rekey triggered: consumed [%d] threshold [%d]", r.bytesConsumed, r.bytesThreshold)
		go r.startRekey()
	}
}

func (r *rotatingCrypto) installKey(secret []byte, active bool) error {
	h := hkdf.New(sha512.New384, secret, r.keySalt, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return fmt.Errorf("hkdf read key failed: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes new cipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher new gcm failed: %w", err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.gcmList = append(r.gcmList, gcm)

	if active {
		r.activeIdx = len(r.gcmList) - 1
	}

	r.rekeyInFlight.Store(false)
	r.bytesConsumed, r.bytesTriggered = 0, false

	r.debug("traffic key installed: key count [%d] active index [%d]", len(r.gcmList), r.activeIdx)

	return nil
}

func (r *rotatingCrypto) promoteKey(idx int) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if idx >= len(r.gcmList) {
		return
	}

	r.debug("traffic key promoted: key count [%d] promote index [%d]", len(r.gcmList), idx)

	newLen := len(r.gcmList) - idx
	newList := make([]cipher.AEAD, newLen)
	copy(newList, r.gcmList[idx:])

	r.gcmList = newList
	r.activeIdx = 0
}

func (r *rotatingCrypto) startRekey() {
	if !r.rekeyInFlight.CompareAndSwap(false, true) {
		return
	}

	if r.closed.Load() {
		return
	}

	err := func() error {
		curve := ecdh.P256()
		clientPriKey, err := curve.GenerateKey(crypto_rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key failed: %v", err)
		}

		r.clientPriKey = clientPriKey

		for !r.client.isBusStreamInited() {
			time.Sleep(100 * time.Millisecond)
		}
		return r.client.sendBusMessage("rekey", rekeyMessage{clientPriKey.PublicKey().Bytes()})
	}()

	if err != nil {
		r.client.warning("rekey failed: %v", err)
	}
}

func (r *rotatingCrypto) handleClientRekey(msg *rekeyMessage) error {
	curve := ecdh.P256()
	serverPubKey, err := curve.NewPublicKey(msg.PubKey)
	if err != nil {
		return fmt.Errorf("new public key failed: %v", err)
	}

	secret, err := r.clientPriKey.ECDH(serverPubKey)
	if err != nil {
		return fmt.Errorf("ecdh failed: %v", err)
	}

	if err := r.installKey(secret, true); err != nil {
		return err
	}

	r.clientPriKey = nil
	return nil
}

func (r *rotatingCrypto) handleServerRekey(server *sshUdpServer, msg *rekeyMessage) error {
	curve := ecdh.P256()
	serverPriKey, err := curve.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key failed: %v", err)
	}
	clientPubKey, err := curve.NewPublicKey(msg.PubKey)
	if err != nil {
		return fmt.Errorf("new public key failed: %v", err)
	}

	secret, err := serverPriKey.ECDH(clientPubKey)
	if err != nil {
		return fmt.Errorf("ecdh failed: %v", err)
	}

	if err := r.installKey(secret, false); err != nil {
		return err
	}

	msg.PubKey = serverPriKey.PublicKey().Bytes()
	return server.sendBusMessage("rekey", msg)
}

func (r *rotatingCrypto) Close() {
	if !r.closed.CompareAndSwap(false, true) {
		return
	}

	if r.stopCh != nil {
		close(r.stopCh)
	}
}

func newRotatingCrypto(client *SshUdpClient, pass, salt []byte, bytesThreshold uint64, timeThreshold time.Duration) (*rotatingCrypto, error) {
	r := &rotatingCrypto{client: client, keyPass: pass, keySalt: salt, bytesThreshold: bytesThreshold}

	if err := r.installKey(pass, true); err != nil {
		return nil, err
	}

	if client != nil && timeThreshold > 0 {
		r.stopCh = make(chan struct{})
		go func() {
			ticker := time.NewTicker(timeThreshold)
			defer ticker.Stop()

			r.debug("time-based rekey triggered (initial)")
			r.startRekey()

			for {
				select {
				case <-ticker.C:
					r.debug("time-based rekey triggered: threshold [%v]", timeThreshold)
					r.startRekey()

				case <-r.stopCh:
					return
				}
			}
		}()
	}

	return r, nil
}
