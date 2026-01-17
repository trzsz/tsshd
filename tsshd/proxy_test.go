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
	"testing"
)

func TestPacketCache_Basic(t *testing.T) {
	var p packetCache

	for i := range 10 {
		p.addPacket([]byte{byte(i)})
	}

	var got []byte
	p.sendCache(func(b []byte) error {
		got = append(got, b[0])
		return nil
	})

	// first 10
	for i := range 10 {
		if got[i] != byte(i) {
			t.Fatalf("expect %d got %d", i, got[i])
		}
	}
}

func TestPacketCache_FirstAndRecent(t *testing.T) {
	var p packetCache

	total := kPacketCacheSize * 3
	for i := range total {
		p.addPacket([]byte{byte(i)})
	}

	var got []byte
	p.sendCache(func(b []byte) error {
		got = append(got, b[0])
		return nil
	})

	// first 100
	for i := range kPacketCacheSize {
		if got[i] != byte(i) {
			t.Fatalf("first mismatch at %d, got[%d]", i, got[i])
		}
	}

	// last 100
	start := total - kPacketCacheSize
	for i := range kPacketCacheSize {
		if got[kPacketCacheSize+i] != byte(start+i) {
			t.Logf("%v", got)
			t.Fatalf("recent mismatch at %d, got [%d]", kPacketCacheSize+i, got[kPacketCacheSize+i])
		}
	}
}

func TestPacketCache_RecentPartial(t *testing.T) {
	var p packetCache

	for i := range kPacketCacheSize {
		p.addPacket([]byte{byte(i)})
	}

	for i := range kPacketCacheSize / 2 {
		p.addPacket([]byte{byte(100 + i)})
	}

	var got []byte
	p.sendCache(func(b []byte) error {
		got = append(got, b[0])
		return nil
	})

	// first 100
	for i := range kPacketCacheSize {
		if got[i] != byte(i) {
			t.Fatalf("first mismatch at %d, got %d", i, got[i])
		}
	}

	// last 50
	for i := range kPacketCacheSize / 2 {
		if got[kPacketCacheSize+i] != byte(100+i) {
			t.Fatalf("recent partial mismatch at %d, got %d", i, got[kPacketCacheSize+i])
		}
	}
}

func TestPacketCache_ClearAndReuse(t *testing.T) {
	var p packetCache

	for i := range kPacketCacheSize * 2 {
		p.addPacket([]byte{byte(i)})
	}

	p.clearCache()

	for i := 100; i < 110; i++ {
		p.addPacket([]byte{byte(i)})
	}

	var got []byte
	p.sendCache(func(b []byte) error {
		got = append(got, b[0])
		return nil
	})

	// first 10
	for i := range 10 {
		if got[i] != byte(100+i) {
			t.Fatalf("reuse mismatch at %d, got %d", i, got[i])
		}
	}
}
