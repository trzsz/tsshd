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
	"fmt"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// kCompressionZstd is the Zstandard compression algorithm used for session output.
const kCompressionZstd = "zstd"

// kZstdCompressWindow is the maximum window size used by the Zstd encoder and decoder.
const kZstdCompressWindow = 1 << 20

// selectCompression selects the session output compression algorithm based on
// the requested algorithm and negotiated protocol version.
func selectCompression(protoVersion int, requested string) (string, error) {
	switch {
	case requested == "", strings.EqualFold(requested, "zstd"):
		if protoVersion >= 2 {
			return kCompressionZstd, nil
		}
		return "", nil
	case strings.EqualFold(requested, "none"):
		return "", nil
	default:
		return "", fmt.Errorf("invalid compression algorithm: %q", requested)
	}
}

// compressOutput returns the stream used to write session output.
// Each client gets a separate encoder so attaching a new client starts a fresh
// compression stream. The encoder must wrap the underlying stream rather than
// the replaceable session stream, which may retry a write on a different client
// stream and mix two compression contexts.
func compressOutput(compression string, stream Stream) (Stream, error) {
	switch compression {
	case "":
		return stream, nil
	case kCompressionZstd:
		return newZstdWriteStream(stream)
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %q", compression)
	}
}

// zstdWriteStream compresses writes while passing reads through unchanged.
type zstdWriteStream struct {
	Stream
	mu      sync.Mutex
	enc     *zstd.Encoder
	finOnce sync.Once
	finErr  error
}

func newZstdWriteStream(stream Stream) (*zstdWriteStream, error) {
	enc, err := zstd.NewWriter(stream, zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithWindowSize(kZstdCompressWindow), zstd.WithEncoderConcurrency(1), zstd.WithLowerEncoderMem(true))
	if err != nil {
		return nil, err
	}
	return &zstdWriteStream{Stream: stream, enc: enc}, nil
}

func (s *zstdWriteStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.enc.Write(p)
	if err != nil {
		return n, err
	}
	if err := s.enc.Flush(); err != nil {
		return n, err
	}
	return n, nil
}

func (s *zstdWriteStream) finish() error {
	s.finOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.finErr = s.enc.Close()
	})
	return s.finErr
}

func (s *zstdWriteStream) CloseWrite() error {
	err := s.finish()
	closeErr := s.Stream.CloseWrite()
	if err != nil {
		return err
	}
	return closeErr
}

// Close aborts the compressed stream by closing the underlying stream first,
// unblocking any pending write before releasing the encoder.
// Use CloseWrite to finish the compressed stream normally.
func (s *zstdWriteStream) Close() error {
	err := s.Stream.Close()
	_ = s.finish()
	return err
}

// decompressOutput returns the stream used to read session output.
func decompressOutput(compression string, stream Stream) (Stream, error) {
	switch compression {
	case "":
		return stream, nil
	case kCompressionZstd:
		return newZstdReadStream(stream)
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %q", compression)
	}
}

// zstdReadStream decompresses reads while passing writes through unchanged.
//
// Close is left to the embedded stream. Closing the decoder while another
// goroutine is blocked in Read is unsafe. Instead, closing the underlying
// stream unblocks Read, allowing the decoder to be reclaimed by the garbage collector.
type zstdReadStream struct {
	Stream
	dec *zstd.Decoder
}

func newZstdReadStream(stream Stream) (*zstdReadStream, error) {
	dec, err := zstd.NewReader(stream, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxWindow(kZstdCompressWindow))
	if err != nil {
		return nil, err
	}
	return &zstdReadStream{Stream: stream, dec: dec}, nil
}

func (s *zstdReadStream) Read(p []byte) (int, error) {
	return s.dec.Read(p)
}
