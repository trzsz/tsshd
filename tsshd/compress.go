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
	"errors"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// kCompressZstd compresses the session output (server to client) with one zstd stream per session.
// The stream is flushed on every write, so the client can show the output at once.
const kCompressZstd = "zstd"

const kCompressWindow = 1 << 20

// compressionWanted reports whether the client asks for compressed output: the client
// must request it and the server must support it, older servers do not set ServerInfo.Compress.
func compressionWanted(info *ServerInfo, requested string) bool {
	return requested == kCompressZstd && info.Compress == kCompressZstd
}

// requestCompression asks the server to compress the output of a session, also when
// attaching to one.
func requestCompression(msg *startMessage, wanted bool) {
	if wanted {
		msg.Compress = kCompressZstd
	}
}

// compressOutput returns the stream the server writes the session output to. Every client
// gets its own encoder on its own stream: attaching swaps the client stream of a session,
// the encoder of the previous client goes away with it and the new client starts fresh.
// The encoder must not wrap the replaceable stream, which retries an interrupted write on
// the new stream and would mix the output of two compression contexts.
func compressOutput(msg *startMessage, stream Stream) (Stream, error) {
	if msg.Compress != kCompressZstd {
		return stream, nil
	}
	zs, err := newZstdWriteStream(stream)
	if err != nil {
		return stream, err
	}
	return zs, nil
}

// zstdWriteStream compresses what is written to the session stream, reads pass through.
type zstdWriteStream struct {
	Stream
	mu  sync.Mutex
	enc *zstd.Encoder
}

func newZstdWriteStream(stream Stream) (*zstdWriteStream, error) {
	enc, err := zstd.NewWriter(stream, zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithWindowSize(kCompressWindow), zstd.WithEncoderConcurrency(1), zstd.WithLowerEncoderMem(true))
	if err != nil {
		return nil, err
	}
	return &zstdWriteStream{Stream: stream, enc: enc}, nil
}

func (s *zstdWriteStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.enc.Write(p); err != nil {
		return 0, err
	}
	if err := s.enc.Flush(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *zstdWriteStream) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Close()
}

func (s *zstdWriteStream) CloseWrite() error {
	s.finish()
	return s.Stream.CloseWrite()
}

// Close closes the stream before it finishes the encoder: a write blocked on a client that is
// gone holds the encoder until the stream is closed. The output ends with CloseWrite instead.
func (s *zstdWriteStream) Close() error {
	err := s.Stream.Close()
	s.finish()
	return err
}

// zstdReadStream decompresses what is read from the session stream, writes pass through.
//
// Close is left to the embedded stream. The decoder is not safe to close while another
// goroutine is blocked in Read, which is what happens when a session is closed while its
// output forwarder is still running. With decoder concurrency 1 there are no goroutines
// behind it, so the garbage collector reclaims it once the forwarder returns.
type zstdReadStream struct {
	Stream
	dec *zstd.Decoder
}

func newZstdReadStream(stream Stream) (*zstdReadStream, error) {
	dec, err := zstd.NewReader(stream, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxWindow(kCompressWindow))
	if err != nil {
		return nil, err
	}
	return &zstdReadStream{Stream: stream, dec: dec}, nil
}

func (s *zstdReadStream) Read(p []byte) (int, error) {
	n, err := s.dec.Read(p)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	return n, err
}
