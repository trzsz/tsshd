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
	clientCrypto, err := newRotatingCrypto(nil, []byte("secret1"), []byte("salt1"), 0, 0, false)
	if err != nil {
		t.Fatalf("client newRotatingCrypto failed: %v", err)
	}

	serverCrypto, err := newRotatingCrypto(nil, []byte("secret1"), []byte("salt1"), 0, 0, false)
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

func TestRotatingCrypto_SealAndOpenPacket(t *testing.T) {
	// Initialize configuration
	pass1 := []byte("initial-secret-key-1")
	pass2 := []byte("rotated-secret-key-2")
	salt := []byte("common-salt")
	plaintext := []byte("sensitive-packet-data")

	// 1. Setup Client and Server
	client, _ := newRotatingCrypto(nil, pass1, salt, 0, 0, false)
	server, _ := newRotatingCrypto(nil, pass1, salt, 0, 0, false)

	nonceSize := client.NonceSize()
	overhead := client.Overhead()

	// Helper to create a buffer with enough space for Nonce + Data + GCM Overhead
	makePacketBuf := func(data []byte) []byte {
		b := make([]byte, nonceSize+len(data)+overhead)
		copy(b[nonceSize:], data)
		return b
	}

	// --- Phase 1: Server installs Key 2, Client has NOT installed yet ---
	if err := server.installKey(pass2, false); err != nil {
		t.Fatal(err)
	}

	t.Run("Phase1_InPlace", func(t *testing.T) {
		// Prepare a buffer with enough capacity for overhead
		clientBuf := makePacketBuf(plaintext)

		// sealPacket with inPlace = true: This writes directly into clientBuf.
		// We pass a slice containing exactly nonce + payload.
		sealed, err := client.sealPacket(clientBuf[:nonceSize+len(plaintext)], true)
		if err != nil {
			t.Fatal(err)
		}

		// Verify memory address: sealed should point to the same start as clientBuf
		if &sealed[0] != &clientBuf[0] {
			t.Error("Expected in-place modification, but buffer address differs")
		}

		// Server opens. Server gcmList is [Key 1, Key 2].
		// It will succeed with Key 1 (index 0) and NO promotion happens yet.
		n, err := server.openPacket(sealed)
		if err != nil {
			t.Fatalf("Server failed to open with Key 1: %v", err)
		}

		// Verify decrypted content
		if !bytes.Equal(sealed[nonceSize:n], plaintext) {
			t.Fatalf("Decrypted data mismatch, want %q, got %q", plaintext, sealed[nonceSize:n])
		}

		// Verify server still has 2 keys
		server.mutex.Lock()
		count := len(server.gcmList)
		server.mutex.Unlock()
		if count != 2 {
			t.Errorf("Server should still have 2 keys, got %d", count)
		}
	})

	// --- Phase 2: Client installs Key 2, Test Non-In-Place ---
	if err := client.installKey(pass2, true); err != nil {
		t.Fatal(err)
	}

	t.Run("Phase2_NonInPlace", func(t *testing.T) {
		// Prepare a buffer
		buf := makePacketBuf(plaintext)

		// sealPacket with inPlace = false: This returns a NEW slice/buffer
		// and leaves the original 'buf' payload intact.
		sealed, err := client.sealPacket(buf[:nonceSize+len(plaintext)], false)
		if err != nil {
			t.Fatalf("sealPacket failed: %v", err)
		}

		// Verify that the original buffer and the sealed buffer are different
		if &sealed[0] == &buf[0] {
			t.Error("Expected a new buffer allocation, but got the same memory address")
		}

		// Open the packet on the server
		n, err := server.openPacket(sealed)
		if err != nil {
			t.Fatalf("Server failed to promote and open: %v", err)
		}

		decrypted := sealed[nonceSize:n]
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("Decrypted data mismatch, want %q, got %q", plaintext, decrypted)
		}

		// Verify server promotion: Should now only have 1 key (Key 2)
		server.mutex.Lock()
		count := len(server.gcmList)
		server.mutex.Unlock()
		if count != 1 {
			t.Errorf("Server promotion failed, expected 1 key, got %d", count)
		}
	})
}
