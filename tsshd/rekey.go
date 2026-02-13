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

type rotatingCrypto struct {
	mutex                    sync.Mutex
	client                   *SshUdpClient
	keySalt                  []byte
	gcmList                  []cipher.AEAD
	key0                     cipher.AEAD
	retainKey0               bool
	pendingReconnectionReset atomic.Bool
	activeIdx                int
	bytesConsumed            uint64
	bytesThreshold           uint64
	bytesTriggered           bool
	rekeyInFlight            atomic.Bool
	clientPriKey             *ecdh.PrivateKey
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
	r.mutex.Lock()
	gcm := r.gcmList[r.activeIdx]
	r.mutex.Unlock()

	r.consumeBytes(uint64(len(plaintext)))

	return gcm.Seal(dst, nonce, plaintext, additionalData)
}

func (r *rotatingCrypto) Open(dst, nonce, ciphertext, additionalData []byte) (plaintext []byte, err error) {
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
		// After auth-layer reconnection detection (MarkPendingReconnection),
		// if the first packet decrypts with key0 while rekeyed keys exist,
		// the client restarted with original credentials. Reset crypto so
		// Seal() also uses key0 for responses. The flag is consumed on any
		// successful decryption to prevent late/replayed packets from
		// triggering a downgrade outside the reconnection window.
		if r.pendingReconnectionReset.Swap(false) && gcm == r.key0 && len(gcmList) > 1 {
			r.resetToKey0()
			return plaintext, nil
		}
		// Retained key0 at the tail is a read-only fallback for reconnection
		// detection. Don't promote it — that would drop the active rekeyed key
		// and effectively reset crypto without the auth-layer signal.
		if r.retainKey0 && gcm == r.key0 && i > 0 {
			return plaintext, nil
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

func (r *rotatingCrypto) debug(format string, a ...any) {
	if r.client != nil {
		r.client.debug(format, a...)
	} else {
		debug(format, a...)
	}
}

func (r *rotatingCrypto) resetToKey0() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.debug("reconnection detected: resetting crypto to initial key (had %d keys)", len(r.gcmList))
	r.gcmList = []cipher.AEAD{r.key0}
	r.activeIdx = 0
	r.rekeyInFlight.Store(false)
}

// EnableKey0Retention opts this crypto into preserving key0 across promotions.
// Only the server side needs this — it allows reconnecting clients that were
// restarted (and only have the original pass/salt credentials) to be decrypted.
func (r *rotatingCrypto) EnableKey0Retention() {
	r.retainKey0 = true
}

// MarkPendingReconnection signals that the auth layer detected a new client
// connection. The next successful Open() call checks whether the packet was
// encrypted with key0; if so (and rekeyed keys exist), crypto resets to key0
// so Seal() responses are also decryptable by the reconnecting client.
// If the first packet uses a rekeyed key instead (network-change reconnection),
// the flag is consumed harmlessly.
func (r *rotatingCrypto) MarkPendingReconnection() {
	r.pendingReconnectionReset.Store(true)
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
		r.debug("rekey triggered by bytes: consumed [%d] threshold [%d]", r.bytesConsumed, r.bytesThreshold)
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

	promoted := r.gcmList[idx:]

	if r.retainKey0 && r.key0 != nil {
		newList := make([]cipher.AEAD, 0, len(promoted)+1)
		newList = append(newList, promoted...)
		hasKey0 := false
		for _, g := range newList {
			if g == r.key0 {
				hasKey0 = true
				break
			}
		}
		if !hasKey0 {
			newList = append(newList, r.key0)
		}
		r.gcmList = newList
	} else {
		newList := make([]cipher.AEAD, len(promoted))
		copy(newList, promoted)
		r.gcmList = newList
	}

	r.activeIdx = 0
}

func (r *rotatingCrypto) startRekey() {
	if !r.rekeyInFlight.CompareAndSwap(false, true) {
		return
	}

	if r.client.IsClosed() {
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
			time.Sleep(10 * time.Millisecond)
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

func (r *rotatingCrypto) handleServerRekey(msg *rekeyMessage) error {
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
	return sendBusMessage("rekey", msg)
}

func newRotatingCrypto(client *SshUdpClient, secret, salt []byte, bytesThreshold uint64, timeThreshold time.Duration) (*rotatingCrypto, error) {
	r := &rotatingCrypto{client: client, keySalt: salt, bytesThreshold: bytesThreshold}

	if err := r.installKey(secret, true); err != nil {
		return nil, err
	}
	r.key0 = r.gcmList[0]

	if timeThreshold > 0 {
		ticker := time.NewTicker(timeThreshold)
		go func() {
			for range ticker.C {
				r.debug("rekey triggered by time: threshold [%v]", timeThreshold)
				r.startRekey()
			}
		}()
	}

	return r, nil
}
