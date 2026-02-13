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
	"bytes"
	"fmt"
	"testing"
)

func TestRotatingCrypto_MultiKeyOpenOverlap(t *testing.T) {
	// Simulate client and server rotatingCrypto
	clientCrypto, err := newRotatingCrypto(nil, []byte("secret1"), []byte("salt1"), 0, 0)
	if err != nil {
		t.Fatalf("client newRotatingCrypto failed: %v", err)
	}

	serverCrypto, err := newRotatingCrypto(nil, []byte("secret1"), []byte("salt1"), 0, 0)
	if err != nil {
		t.Fatalf("server newRotatingCrypto failed: %v", err)
	}
	serverCrypto.EnableKey0Retention()

	plaintext := []byte("hello rotating crypto!")

	// --- First key test ---
	nonce := make([]byte, clientCrypto.NonceSize())
	ciphertext := clientCrypto.Seal(nil, nonce, plaintext, nil)
	dec, err := serverCrypto.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt with first key: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("decrypted plaintext mismatch with first key")
	}

	// --- Install second key ---
	if err := clientCrypto.installKey([]byte("secret2"), true); err != nil {
		t.Fatalf("client install second key failed: %v", err)
	}
	if err := serverCrypto.installKey([]byte("secret2"), false); err != nil {
		t.Fatalf("server install second key failed: %v", err)
	}

	// Use new key to encrypt
	nonce2 := make([]byte, clientCrypto.NonceSize())
	ciphertext2 := clientCrypto.Seal(nil, nonce2, plaintext, nil)

	// --- KCP packetInput style decryption ---
	dst := ciphertext2[:0]
	dec2, err := serverCrypto.Open(dst, nonce2, ciphertext2, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt with second key: %v", err)
	}
	if !bytes.Equal(dec2, plaintext) {
		t.Fatalf("decrypted plaintext mismatch after second key")
	}

	// Server (with key0 retention) should have [Key1, Key0] after promotion
	serverCrypto.mutex.Lock()
	if len(serverCrypto.gcmList) != 2 {
		t.Fatalf("server should retain key0 after promoteKey, got %d keys", len(serverCrypto.gcmList))
	}
	serverCrypto.mutex.Unlock()

	// Client (without key0 retention) should still have 2 keys (hasn't promoted yet)
	clientCrypto.mutex.Lock()
	if len(clientCrypto.gcmList) != 2 {
		t.Fatalf("client should still have 2 keys, got %d", len(clientCrypto.gcmList))
	}
	clientCrypto.mutex.Unlock()

	// Server now encrypts with its active key
	nonce3 := make([]byte, serverCrypto.NonceSize())
	ciphertext3 := serverCrypto.Seal(nil, nonce3, plaintext, nil)

	// Client decrypts with Open (should traverse gcmList)
	dstClient := ciphertext3[:0]
	dec3, err := clientCrypto.Open(dstClient, nonce3, ciphertext3, nil)
	if err != nil {
		t.Fatalf("client failed to decrypt server-encrypted data: %v", err)
	}
	if !bytes.Equal(dec3, plaintext) {
		t.Fatalf("client decrypted plaintext mismatch")
	}

	// Client (without key0 retention) should have promoted and dropped old key
	clientCrypto.mutex.Lock()
	if len(clientCrypto.gcmList) != 1 {
		t.Fatalf("client should have promoted key, old key removed, keys left: %d", len(clientCrypto.gcmList))
	}
	clientCrypto.mutex.Unlock()
}

func TestRotatingCrypto_Key0RetainedAfterRekey(t *testing.T) {
	secret := []byte("original-secret")
	salt := []byte("salt")
	plaintext := []byte("hello from reconnecting client")

	// Create server (with key0 retention) and original client
	serverCrypto, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("server newRotatingCrypto failed: %v", err)
	}
	serverCrypto.EnableKey0Retention()

	clientCrypto, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("client newRotatingCrypto failed: %v", err)
	}

	// Install a second key (simulating rekey)
	rekeySecret := []byte("rekey-secret")
	if err := clientCrypto.installKey(rekeySecret, true); err != nil {
		t.Fatalf("client install rekey key failed: %v", err)
	}
	if err := serverCrypto.installKey(rekeySecret, false); err != nil {
		t.Fatalf("server install rekey key failed: %v", err)
	}

	// Client encrypts with rekeyed key, server decrypts and promotes
	nonce := make([]byte, clientCrypto.NonceSize())
	ciphertext := clientCrypto.Seal(nil, nonce, plaintext, nil)
	_, err = serverCrypto.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt rekeyed data: %v", err)
	}

	// Server should have [Key1, Key0] after promotion
	serverCrypto.mutex.Lock()
	if len(serverCrypto.gcmList) != 2 {
		t.Fatalf("server should have 2 keys after promote (Key1 + Key0), got %d", len(serverCrypto.gcmList))
	}
	if serverCrypto.gcmList[1] != serverCrypto.key0 {
		t.Fatalf("server gcmList[1] should be key0")
	}
	serverCrypto.mutex.Unlock()

	// --- Simulate app restart: new client with original credentials ---
	newClient, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("new client newRotatingCrypto failed: %v", err)
	}

	// Signal reconnection from auth layer (like setClientConn does)
	serverCrypto.MarkPendingReconnection()

	// New client encrypts with Key0
	nonce2 := make([]byte, newClient.NonceSize())
	ciphertext2 := newClient.Seal(nil, nonce2, plaintext, nil)

	// Server decrypts — should match Key0 and trigger resetToKey0
	dec, err := serverCrypto.Open(nil, nonce2, ciphertext2, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt reconnecting client data: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("decrypted plaintext mismatch")
	}

	// Server should now be reset to [Key0] only
	serverCrypto.mutex.Lock()
	if len(serverCrypto.gcmList) != 1 {
		t.Fatalf("server should be reset to 1 key after reconnection, got %d", len(serverCrypto.gcmList))
	}
	if serverCrypto.gcmList[0] != serverCrypto.key0 {
		t.Fatalf("server active key should be key0 after reset")
	}
	serverCrypto.mutex.Unlock()

	// Server encrypts response — new client should be able to decrypt
	nonce3 := make([]byte, serverCrypto.NonceSize())
	response := []byte("welcome back!")
	ciphertext3 := serverCrypto.Seal(nil, nonce3, response, nil)

	dec3, err := newClient.Open(nil, nonce3, ciphertext3, nil)
	if err != nil {
		t.Fatalf("new client failed to decrypt server response: %v", err)
	}
	if !bytes.Equal(dec3, response) {
		t.Fatalf("new client decrypted response mismatch")
	}
}

func TestRotatingCrypto_MultipleRekeysRetainKey0(t *testing.T) {
	secret := []byte("original-secret")
	salt := []byte("salt")
	plaintext := []byte("test data")

	serverCrypto, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("server newRotatingCrypto failed: %v", err)
	}
	serverCrypto.EnableKey0Retention()

	clientCrypto, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("client newRotatingCrypto failed: %v", err)
	}

	// Perform 3 rekey cycles
	for i := 0; i < 3; i++ {
		rekeySecret := []byte(fmt.Sprintf("rekey-secret-%d", i))
		if err := clientCrypto.installKey(rekeySecret, true); err != nil {
			t.Fatalf("client install rekey %d failed: %v", i, err)
		}
		if err := serverCrypto.installKey(rekeySecret, false); err != nil {
			t.Fatalf("server install rekey %d failed: %v", i, err)
		}

		// Client encrypts with latest key, server decrypts and promotes
		nonce := make([]byte, clientCrypto.NonceSize())
		ct := clientCrypto.Seal(nil, nonce, plaintext, nil)
		_, err = serverCrypto.Open(nil, nonce, ct, nil)
		if err != nil {
			t.Fatalf("server failed to decrypt rekey %d: %v", i, err)
		}
	}

	// After 3 rekeys + promotions, server should have [Key3, Key0]
	serverCrypto.mutex.Lock()
	keyCount := len(serverCrypto.gcmList)
	hasKey0 := false
	for _, g := range serverCrypto.gcmList {
		if g == serverCrypto.key0 {
			hasKey0 = true
			break
		}
	}
	serverCrypto.mutex.Unlock()

	if !hasKey0 {
		t.Fatalf("server should still have key0 after %d rekeys", 3)
	}
	if keyCount != 2 {
		t.Fatalf("server should have 2 keys (latest + key0) after promotions, got %d", keyCount)
	}

	// Signal reconnection from auth layer
	serverCrypto.MarkPendingReconnection()

	// Simulate reconnection with original credentials
	newClient, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("new client newRotatingCrypto failed: %v", err)
	}

	nonce := make([]byte, newClient.NonceSize())
	ct := newClient.Seal(nil, nonce, plaintext, nil)
	_, err = serverCrypto.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt reconnecting client after %d rekeys: %v", 3, err)
	}

	// Server should be reset to [Key0]
	serverCrypto.mutex.Lock()
	if len(serverCrypto.gcmList) != 1 {
		t.Fatalf("server should be reset to 1 key, got %d", len(serverCrypto.gcmList))
	}
	serverCrypto.mutex.Unlock()

	// Bidirectional communication should work
	nonce2 := make([]byte, serverCrypto.NonceSize())
	response := []byte("reconnected after 3 rekeys")
	ct2 := serverCrypto.Seal(nil, nonce2, response, nil)
	dec, err := newClient.Open(nil, nonce2, ct2, nil)
	if err != nil {
		t.Fatalf("new client failed to decrypt server response: %v", err)
	}
	if !bytes.Equal(dec, response) {
		t.Fatalf("response mismatch")
	}
}

// TestRotatingCrypto_Key0WithoutMarkDoesNotReset verifies that a key0 packet
// does NOT trigger resetToKey0 unless MarkPendingReconnection was called first.
// This prevents late/reordered UDP packets or replayed ciphertext from forcing
// a crypto downgrade.
func TestRotatingCrypto_Key0WithoutMarkDoesNotReset(t *testing.T) {
	secret := []byte("original-secret")
	salt := []byte("salt")
	plaintext := []byte("late packet")

	serverCrypto, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("server newRotatingCrypto failed: %v", err)
	}
	serverCrypto.EnableKey0Retention()

	clientCrypto, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("client newRotatingCrypto failed: %v", err)
	}

	// Capture a key0-encrypted packet before rekey
	nonce0 := make([]byte, clientCrypto.NonceSize())
	ciphertext0 := clientCrypto.Seal(nil, nonce0, plaintext, nil)

	// Perform rekey
	rekeySecret := []byte("rekey-secret")
	if err := clientCrypto.installKey(rekeySecret, true); err != nil {
		t.Fatalf("client install rekey failed: %v", err)
	}
	if err := serverCrypto.installKey(rekeySecret, false); err != nil {
		t.Fatalf("server install rekey failed: %v", err)
	}

	// Client sends rekeyed packet, server promotes
	nonce1 := make([]byte, clientCrypto.NonceSize())
	ciphertext1 := clientCrypto.Seal(nil, nonce1, plaintext, nil)
	_, err = serverCrypto.Open(nil, nonce1, ciphertext1, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt rekeyed packet: %v", err)
	}

	// Server should have [Key1, Key0]
	serverCrypto.mutex.Lock()
	if len(serverCrypto.gcmList) != 2 {
		t.Fatalf("expected 2 keys after promote, got %d", len(serverCrypto.gcmList))
	}
	serverCrypto.mutex.Unlock()

	// Now feed the old key0 packet WITHOUT calling MarkPendingReconnection.
	// This simulates a late/reordered packet or replay attack.
	_, err = serverCrypto.Open(nil, nonce0, ciphertext0, nil)
	if err != nil {
		t.Fatalf("server should still decrypt key0 packet (it's in gcmList): %v", err)
	}

	// Server should NOT have reset — should still have 2 keys
	// (key0 match promotes key0 to front, but doesn't wipe rekeyed keys)
	serverCrypto.mutex.Lock()
	keyCount := len(serverCrypto.gcmList)
	serverCrypto.mutex.Unlock()

	if keyCount == 1 {
		t.Fatalf("server should NOT reset on key0 packet without MarkPendingReconnection")
	}

	// Server Seal should still use the rekeyed key (not key0)
	nonce2 := make([]byte, serverCrypto.NonceSize())
	response := serverCrypto.Seal(nil, nonce2, plaintext, nil)

	// Original client (with rekeyed key) should be able to decrypt
	_, err = clientCrypto.Open(nil, nonce2, response, nil)
	if err != nil {
		t.Fatalf("original client should decrypt server response using rekeyed key: %v", err)
	}
}

// TestRotatingCrypto_NetworkChangeNoReset verifies that a reconnection from
// the same client (network change, not app restart) does not reset crypto.
// The client still has the rekeyed key, so after MarkPendingReconnection the
// first packet decrypts with the rekeyed key and the flag is consumed harmlessly.
func TestRotatingCrypto_NetworkChangeNoReset(t *testing.T) {
	secret := []byte("original-secret")
	salt := []byte("salt")
	plaintext := []byte("network change packet")

	serverCrypto, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("server newRotatingCrypto failed: %v", err)
	}
	serverCrypto.EnableKey0Retention()

	clientCrypto, err := newRotatingCrypto(nil, secret, salt, 0, 0)
	if err != nil {
		t.Fatalf("client newRotatingCrypto failed: %v", err)
	}

	// Rekey
	rekeySecret := []byte("rekey-secret")
	if err := clientCrypto.installKey(rekeySecret, true); err != nil {
		t.Fatalf("client install rekey failed: %v", err)
	}
	if err := serverCrypto.installKey(rekeySecret, false); err != nil {
		t.Fatalf("server install rekey failed: %v", err)
	}

	// Client sends rekeyed packet, server promotes
	nonce := make([]byte, clientCrypto.NonceSize())
	ct := clientCrypto.Seal(nil, nonce, plaintext, nil)
	_, err = serverCrypto.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt rekeyed packet: %v", err)
	}

	// Server has [Key1, Key0]
	serverCrypto.mutex.Lock()
	if len(serverCrypto.gcmList) != 2 {
		t.Fatalf("expected 2 keys after promote, got %d", len(serverCrypto.gcmList))
	}
	serverCrypto.mutex.Unlock()

	// Auth layer detects reconnection (same client, new IP)
	serverCrypto.MarkPendingReconnection()

	// Client sends packet with rekeyed key (same session, just network change)
	nonce2 := make([]byte, clientCrypto.NonceSize())
	ct2 := clientCrypto.Seal(nil, nonce2, plaintext, nil)
	_, err = serverCrypto.Open(nil, nonce2, ct2, nil)
	if err != nil {
		t.Fatalf("server failed to decrypt rekeyed packet after network change: %v", err)
	}

	// Server should NOT reset — first packet used rekeyed key, not key0
	serverCrypto.mutex.Lock()
	if len(serverCrypto.gcmList) != 2 {
		t.Fatalf("server should NOT reset on network change, expected 2 keys, got %d", len(serverCrypto.gcmList))
	}
	serverCrypto.mutex.Unlock()

	// Flag should be consumed — a subsequent key0 packet should NOT trigger reset
	serverCrypto.mutex.Lock()
	if serverCrypto.pendingReconnectionReset.Load() {
		t.Fatalf("pendingReconnectionReset should be consumed after first successful Open")
	}
	serverCrypto.mutex.Unlock()
}
