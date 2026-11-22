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
	"crypto/aes"
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

const kTestClientID = 23

var kTestClientNonce = []byte("test client nonce")

// kTestProtoVersions covers the shared key used before protocol version 3
// and the directional keys used since.
var kTestProtoVersions = []int{2, kTsshdProtocol}

// newTestCryptoPair simulates the client and server rotatingCrypto of one connection.
func newTestCryptoPair(t *testing.T, protoVersion int, pass, salt []byte) (*rotatingCrypto, *rotatingCrypto) {
	t.Helper()

	return newTestCryptoPairFor(t, protoVersion, kTestClientID, kTestClientNonce, pass, salt)
}

func newTestCryptoPairFor(t *testing.T, protoVersion int, clientID uint64, clientNonce,
	pass, salt []byte) (*rotatingCrypto, *rotatingCrypto) {
	t.Helper()

	clientCrypto, err := newClientCrypto(nil, protoVersion, clientID, clientNonce, pass, salt)
	if err != nil {
		t.Fatalf("newClientCrypto failed: %v", err)
	}

	serverCrypto := newServerCrypto(pass, salt, false)
	if err := serverCrypto.setClientHello(protoVersion, clientID, clientNonce); err != nil {
		t.Fatalf("setClientHello failed: %v", err)
	}

	return clientCrypto, serverCrypto
}

// sealTestPacket returns a wire packet (nonce + ciphertext) like the one KCP sends.
func sealTestPacket(t *testing.T, crypto *rotatingCrypto, plaintext []byte) []byte {
	t.Helper()

	buf := make([]byte, crypto.NonceSize()+len(plaintext))
	if _, err := crypto_rand.Read(buf[:crypto.NonceSize()]); err != nil {
		t.Fatalf("rand nonce failed: %v", err)
	}
	copy(buf[crypto.NonceSize():], plaintext)

	packet, err := crypto.sealPacket(buf, false)
	if err != nil {
		t.Fatalf("sealPacket failed: %v", err)
	}
	return packet
}

// openTestPacket opens a copy of the wire packet, so that it can be delivered again.
func openTestPacket(crypto *rotatingCrypto, packet []byte) ([]byte, error) {
	buf := bytes.Clone(packet)
	n, err := crypto.openPacket(buf)
	if err != nil {
		return nil, err
	}
	return buf[crypto.NonceSize():n], nil
}

func TestRotatingCrypto_MultiKeyOpenOverlap(t *testing.T) {
	for _, protoVersion := range kTestProtoVersions {
		t.Run(fmt.Sprintf("ProtoVer%d", protoVersion), func(t *testing.T) {
			testRotatingCryptoMultiKeyOpenOverlap(t, protoVersion)
		})
	}
}

func testRotatingCryptoMultiKeyOpenOverlap(t *testing.T, protoVersion int) {
	clientCrypto, serverCrypto := newTestCryptoPair(t, protoVersion, []byte("secret1"), []byte("salt1"))

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
	if len(serverCrypto.keyList) != 1 {
		t.Fatalf("old key should be removed after promoteKey, got %d keys", len(serverCrypto.keyList))
	}
	serverCrypto.mutex.Unlock()

	// Client should still retain old key
	clientCrypto.mutex.Lock()
	if len(clientCrypto.keyList) != 2 {
		t.Fatalf("client should still have 2 keys, got %d", len(clientCrypto.keyList))
	}
	clientCrypto.mutex.Unlock()

	// Server now encrypts with its active key
	nonce3 := make([]byte, serverCrypto.NonceSize())
	ciphertext3 := serverCrypto.Seal(nil, nonce3, plaintext, nil)

	// Client decrypts with Open (should traverse keyList)
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
	if len(clientCrypto.keyList) != 1 {
		t.Fatalf("client should have promoted key, old key removed, keys left: %d", len(clientCrypto.keyList))
	}
	clientCrypto.mutex.Unlock()
}

func TestRotatingCrypto_SealAndOpenPacket(t *testing.T) {
	for _, protoVersion := range kTestProtoVersions {
		t.Run(fmt.Sprintf("ProtoVer%d", protoVersion), func(t *testing.T) {
			testRotatingCryptoSealAndOpenPacket(t, protoVersion)
		})
	}
}

func testRotatingCryptoSealAndOpenPacket(t *testing.T, protoVersion int) {
	// Initialize configuration
	pass1 := []byte("initial-secret-key-1")
	pass2 := []byte("rotated-secret-key-2")
	salt := []byte("common-salt")
	plaintext := []byte("sensitive-packet-data")

	// 1. Setup Client and Server
	client, server := newTestCryptoPair(t, protoVersion, pass1, salt)

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

		// Server opens. Server keyList is [Key 1, Key 2].
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
		count := len(server.keyList)
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
		count := len(server.keyList)
		server.mutex.Unlock()
		if count != 1 {
			t.Errorf("Server promotion failed, expected 1 key, got %d", count)
		}
	})
}

// A packet sent by one side must never be accepted by that same side, otherwise
// anyone able to spoof the client address could feed the server its own output.
func TestRotatingCrypto_RejectReflectedPacket(t *testing.T) {
	client, server := newTestCryptoPair(t, kTsshdProtocol, []byte("secret"), []byte("salt"))
	plaintext := []byte("cat note.txt")

	fromServer := sealTestPacket(t, server, plaintext)
	if _, err := openTestPacket(server, fromServer); err == nil {
		t.Fatal("server accepted its own packet")
	}
	if dec, err := openTestPacket(client, fromServer); err != nil || !bytes.Equal(dec, plaintext) {
		t.Fatalf("client failed to open the server packet: %v", err)
	}

	fromClient := sealTestPacket(t, client, plaintext)
	if _, err := openTestPacket(client, fromClient); err == nil {
		t.Fatal("client accepted its own packet")
	}
	if dec, err := openTestPacket(server, fromClient); err != nil || !bytes.Equal(dec, plaintext) {
		t.Fatalf("server failed to open the client packet: %v", err)
	}
}

func TestRotatingCrypto_RejectReplayedPacket(t *testing.T) {
	client, server := newTestCryptoPair(t, kTsshdProtocol, []byte("secret"), []byte("salt"))

	var packets [][]byte
	for i := range kReplayWindowSize + 10 {
		packets = append(packets, sealTestPacket(t, client, fmt.Appendf(nil, "packet %d", i)))
	}

	open := func(idx int) error {
		dec, err := openTestPacket(server, packets[idx])
		if err == nil && !bytes.Equal(dec, fmt.Appendf(nil, "packet %d", idx)) {
			t.Fatalf("packet [%d] plaintext mismatch", idx)
		}
		return err
	}

	// Reordered packets are accepted exactly once.
	for _, idx := range []int{2, 0, 3, 1} {
		if err := open(idx); err != nil {
			t.Fatalf("packet [%d] rejected: %v", idx, err)
		}
	}
	for idx := range 4 {
		if err := open(idx); !errors.Is(err, errPacketReplayed) {
			t.Fatalf("replayed packet [%d] should be rejected, got: %v", idx, err)
		}
	}

	// A packet that fell out of the window is rejected, even if it was never received.
	last := len(packets) - 1
	if err := open(last); err != nil {
		t.Fatalf("packet [%d] rejected: %v", last, err)
	}
	if err := open(4); !errors.Is(err, errPacketReplayed) {
		t.Fatalf("packet [4] is too old and should be rejected, got: %v", err)
	}

	// A packet at the edge of the window is still accepted exactly once.
	edge := last - kReplayWindowSize + 1
	if err := open(edge); err != nil {
		t.Fatalf("packet [%d] rejected: %v", edge, err)
	}
	if err := open(edge); !errors.Is(err, errPacketReplayed) {
		t.Fatalf("replayed packet [%d] should be rejected, got: %v", edge, err)
	}

	// A tampered packet number must not be accepted, nor poison the window.
	tampered := bytes.Clone(packets[last-1])
	tampered[server.NonceSize()-1] ^= 0x80
	if _, err := openTestPacket(server, tampered); err == nil {
		t.Fatal("packet with tampered packet number accepted")
	}
	if err := open(last - 1); err != nil {
		t.Fatalf("packet [%d] rejected: %v", last-1, err)
	}
}

// Packets replayed after a rekey are rejected, whichever key they were sent with.
func TestRotatingCrypto_RejectReplayAcrossRekey(t *testing.T) {
	client, server := newTestCryptoPair(t, kTsshdProtocol, []byte("secret1"), []byte("salt"))

	oldPacket := sealTestPacket(t, client, []byte("old key"))
	if _, err := openTestPacket(server, oldPacket); err != nil {
		t.Fatalf("server failed to open with the first key: %v", err)
	}

	if err := server.installKey([]byte("secret2"), false); err != nil {
		t.Fatal(err)
	}
	if err := client.installKey([]byte("secret2"), true); err != nil {
		t.Fatal(err)
	}

	// The old key is retained until the new one is used, along with its replay window.
	if _, err := openTestPacket(server, oldPacket); err == nil {
		t.Fatal("replayed packet accepted before key promotion")
	}

	// Packet numbers restart with each key.
	newPacket := sealTestPacket(t, client, []byte("new key"))
	if !bytes.Equal(newPacket[:server.NonceSize()], oldPacket[:server.NonceSize()]) {
		t.Fatal("packet numbers should restart after rekey")
	}
	if _, err := openTestPacket(server, newPacket); err != nil {
		t.Fatalf("server failed to open with the second key: %v", err)
	}

	for _, packet := range [][]byte{oldPacket, newPacket} {
		if _, err := openTestPacket(server, packet); err == nil {
			t.Fatal("replayed packet accepted after key promotion")
		}
	}

	// The server must not accept its own packets after the rekey either.
	if _, err := openTestPacket(server, sealTestPacket(t, server, []byte("reflected"))); err == nil {
		t.Fatal("server accepted its own packet after rekey")
	}
}

// The keys are bound to the client ID and to the fresh nonce that every client
// announces. Clients attached to the same server share the initial secret, and
// so do clients started again with the same server info, yet none of them may
// ever reuse the keys and the packet numbers of another one.
func TestRotatingCrypto_FreshKeysPerClient(t *testing.T) {
	pass, salt := []byte("secret"), []byte("salt")
	plaintext := []byte("hello")

	tests := []struct {
		name        string
		clientID    uint64
		clientNonce []byte
	}{
		// A client started again with the same server info.
		{"SameClientID", kTestClientID, []byte("other client nonce")},
		// Another attached client, which should never announce the same nonce.
		{"SameClientNonce", kTestClientID + 1, kTestClientNonce},
		{"NoneInCommon", kTestClientID + 1, []byte("other client nonce")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := newTestCryptoPair(t, kTsshdProtocol, pass, salt)
			otherClient, otherServer := newTestCryptoPairFor(t, kTsshdProtocol, tt.clientID, tt.clientNonce, pass, salt)

			packet, otherPacket := sealTestPacket(t, client, plaintext), sealTestPacket(t, otherClient, plaintext)

			// Both packets carry the first packet number, but are sealed with different keys.
			nonceSize := client.NonceSize()
			if !bytes.Equal(packet[:nonceSize], otherPacket[:nonceSize]) {
				t.Fatal("both clients should start with the same packet number")
			}
			if bytes.Equal(packet[nonceSize:], otherPacket[nonceSize:]) {
				t.Fatal("different clients sealed with the same key")
			}

			if _, err := openTestPacket(otherServer, packet); err == nil {
				t.Fatal("packet accepted on the connection of another client")
			}
			if _, err := openTestPacket(server, otherPacket); err == nil {
				t.Fatal("packet of another client accepted")
			}
			if _, err := openTestPacket(client, sealTestPacket(t, otherServer, plaintext)); err == nil {
				t.Fatal("packet sent to another client accepted")
			}
			if _, err := openTestPacket(server, packet); err != nil {
				t.Fatalf("server failed to open the client packet: %v", err)
			}
			if _, err := openTestPacket(otherServer, otherPacket); err != nil {
				t.Fatalf("server failed to open the client packet: %v", err)
			}
		})
	}
}

// The server has no traffic key until the client has authenticated.
func TestRotatingCrypto_NoKeyBeforeClientHello(t *testing.T) {
	pass, salt := []byte("secret"), []byte("salt")
	server := newServerCrypto(pass, salt, false)

	client, err := newClientCrypto(nil, kTsshdProtocol, 0, nil, pass, salt)
	if err != nil {
		t.Fatalf("newClientCrypto failed: %v", err)
	}
	if _, err := openTestPacket(server, sealTestPacket(t, client, []byte("hello"))); err == nil {
		t.Fatal("packet accepted before the client authenticated")
	}

	plaintext := []byte("must never be sent in plaintext")
	packet := sealTestPacket(t, server, plaintext)
	if len(packet) != server.NonceSize()+len(plaintext)+server.Overhead() {
		t.Fatalf("unexpected packet length: %d", len(packet))
	}
	if bytes.Contains(packet, plaintext) {
		t.Fatal("plaintext sent before the client authenticated")
	}
}

// The liveness of the peer is only refreshed by packets that are authentic
// and, since protocol version 3, have not been received before.
func TestRotatingCrypto_PacketAcceptedCallback(t *testing.T) {
	client, server := newTestCryptoPair(t, kTsshdProtocol, []byte("secret"), []byte("salt"))

	accepted := 0
	client.onPacketAccepted = func() { accepted++ }

	packet := sealTestPacket(t, server, []byte("hello"))
	if _, err := openTestPacket(client, packet); err != nil || accepted != 1 {
		t.Fatalf("packet should be accepted once: %v, accepted=%d", err, accepted)
	}

	// replayed
	if _, err := openTestPacket(client, packet); err == nil || accepted != 1 {
		t.Fatalf("replayed packet should not be accepted: %v, accepted=%d", err, accepted)
	}

	// forged
	forged := bytes.Clone(sealTestPacket(t, server, []byte("hello")))
	forged[len(forged)-1] ^= 1
	if _, err := openTestPacket(client, forged); err == nil || accepted != 1 {
		t.Fatalf("forged packet should not be accepted: %v, accepted=%d", err, accepted)
	}

	// reflected
	if _, err := openTestPacket(client, sealTestPacket(t, client, []byte("hello"))); err == nil || accepted != 1 {
		t.Fatalf("reflected packet should not be accepted: %v, accepted=%d", err, accepted)
	}

	if _, err := openTestPacket(client, sealTestPacket(t, server, []byte("hello"))); err != nil || accepted != 2 {
		t.Fatalf("packet should be accepted: %v, accepted=%d", err, accepted)
	}
}

// Clients older than protocol version 3 keep working with the key derivation
// and random nonces they have always used.
func TestRotatingCrypto_LegacyClient(t *testing.T) {
	pass, salt := []byte("secret"), []byte("salt")

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New384, pass, salt, nil), key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	server := newServerCrypto(pass, salt, false)

	plaintext := []byte("hello")
	nonce := make([]byte, legacy.NonceSize())
	if _, err := crypto_rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	fromClient := legacy.Seal(bytes.Clone(nonce), nonce, plaintext, nil)

	if _, err := openTestPacket(server, fromClient); err == nil {
		t.Fatal("legacy packet accepted before the client authenticated")
	}

	// Legacy clients announce neither a protocol version nor a nonce.
	if err := server.setClientHello(0, kTestClientID, nil); err != nil {
		t.Fatalf("setClientHello failed: %v", err)
	}
	if dec, err := openTestPacket(server, fromClient); err != nil || !bytes.Equal(dec, plaintext) {
		t.Fatalf("server failed to open the legacy client packet: %v", err)
	}

	fromServer := sealTestPacket(t, server, plaintext)
	nonceSize := legacy.NonceSize()
	if dec, err := legacy.Open(nil, fromServer[:nonceSize], fromServer[nonceSize:], nil); err != nil || !bytes.Equal(dec, plaintext) {
		t.Fatalf("legacy client failed to open the server packet: %v", err)
	}
}

// The initial key is installed by the first authentication only, so the
// packet protection of an established connection cannot be changed afterwards.
func TestRotatingCrypto_ClientHelloOnlyOnce(t *testing.T) {
	client, server := newTestCryptoPair(t, kTsshdProtocol, []byte("secret"), []byte("salt"))

	if err := server.setClientHello(2, kTestClientID, nil); err == nil {
		t.Fatal("client hello accepted twice")
	}
	if err := server.setClientHello(kTsshdProtocol, kTestClientID, []byte("other client nonce")); err == nil {
		t.Fatal("client hello accepted twice")
	}

	if _, err := openTestPacket(server, sealTestPacket(t, client, []byte("hello"))); err != nil {
		t.Fatalf("server failed to open the client packet: %v", err)
	}
	if _, err := openTestPacket(server, sealTestPacket(t, server, []byte("hello"))); err == nil {
		t.Fatal("server accepted its own packet after a downgrade attempt")
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow

	if w.check(0) || w.update(0) {
		t.Fatal("packet number 0 is never valid")
	}

	accept := func(number uint64) {
		t.Helper()
		if !w.check(number) || !w.update(number) {
			t.Fatalf("packet number [%d] should be accepted", number)
		}
		if w.check(number) || w.update(number) {
			t.Fatalf("packet number [%d] should be accepted only once", number)
		}
	}
	reject := func(number uint64) {
		t.Helper()
		if w.check(number) || w.update(number) {
			t.Fatalf("packet number [%d] should be rejected", number)
		}
	}

	accept(1)
	accept(3)
	accept(2)
	accept(64)
	accept(63)

	// Advancing by less than the window keeps the older numbers usable.
	accept(kReplayWindowSize)
	accept(5)
	reject(3)

	// The oldest number inside the window, and the first one outside of it.
	accept(kReplayWindowSize + 100)
	accept(101)
	reject(100)
	reject(4)

	// Jumping far ahead clears the whole bitmap.
	const far = 1 << 40
	accept(far)
	accept(far - kReplayWindowSize + 1)
	reject(far - kReplayWindowSize)
	reject(kReplayWindowSize + 100)

	// Every number in a full window is tracked individually.
	for number := uint64(far + 1); number <= far+2*kReplayWindowSize; number++ {
		accept(number)
	}
	for number := uint64(far + kReplayWindowSize + 1); number <= far+2*kReplayWindowSize; number++ {
		reject(number)
	}

	accept(^uint64(0))
	reject(^uint64(0))
}
