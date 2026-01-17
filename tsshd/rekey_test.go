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

	// Verify old key is removed on server
	serverCrypto.mutex.Lock()
	if len(serverCrypto.gcmList) != 1 {
		t.Fatalf("old key should be removed after promoteKey, got %d keys", len(serverCrypto.gcmList))
	}
	serverCrypto.mutex.Unlock()

	// Client should still retain old key
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

	// After successful decryption, client should promote new key and remove old key
	clientCrypto.mutex.Lock()
	if len(clientCrypto.gcmList) != 1 {
		t.Fatalf("client should have promoted key, old key removed, keys left: %d", len(clientCrypto.gcmList))
	}
	clientCrypto.mutex.Unlock()
}
