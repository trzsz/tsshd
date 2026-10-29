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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pipeStream is one end of an in-memory connection used as a session stream; it counts
// the bytes that go over the wire.
type pipeStream struct {
	net.Conn
	wire atomic.Int64
}

func (s *pipeStream) Write(p []byte) (int, error) {
	n, err := s.Conn.Write(p)
	s.wire.Add(int64(n))
	return n, err
}

func (s *pipeStream) CloseRead() error { return nil }

func (s *pipeStream) CloseWrite() error { return s.Conn.Close() }

// newCompressedPair returns the server end writing compressed output, the client end
// reading it, and the raw server stream to count the bytes on the wire.
func newCompressedPair(t *testing.T) (*zstdWriteStream, *zstdReadStream, *pipeStream) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	serverRaw, clientRaw := &pipeStream{Conn: serverConn}, &pipeStream{Conn: clientConn}
	server, err := newZstdWriteStream(serverRaw)
	require.NoError(t, err)
	client, err := newZstdReadStream(clientRaw)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	return server, client, serverRaw
}

func readFullWithTimeout(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatalf("%d bytes were not delivered without more input", n)
	}
	return buf
}

// drain reads the client end until EOF in the background.
func drain(r io.Reader) <-chan []byte {
	out := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r)
		out <- data
	}()
	return out
}

// redrawFrame renders a full 200x50 screen like a TUI that repaints everything on each update.
func redrawFrame(tick int) []byte {
	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[3J\x1b[H")
	for row := range 48 {
		fmt.Fprintf(&b, "\x1b[38;2;137;180;250m%3d\x1b[0m %s\r\n", row, strings.Repeat("the client retries while the server keeps state ", 4))
	}
	fmt.Fprintf(&b, "\x1b[1m%c Thinking…\x1b[0m (esc to cancel, %ds)", "|/-\\"[tick%4], tick/12)
	return []byte(b.String())
}

func TestZstdStream_EveryWriteIsDeliveredAtOnce(t *testing.T) {
	server, client, _ := newCompressedPair(t)

	// a prompt, a keystroke echo, a large burst and a single byte: none may wait for more output
	chunks := [][]byte{[]byte("$ "), []byte("l"), bytes.Repeat([]byte("log line with some text\n"), 2000), []byte("x")}
	for _, chunk := range chunks {
		go func() { _, _ = server.Write(chunk) }()
		assert.Equal(t, chunk, readFullWithTimeout(t, client, len(chunk)))
	}
}

func TestZstdStream_CompressesRepeatedRedraws(t *testing.T) {
	server, client, wire := newCompressedPair(t)
	received := drain(client)

	var raw bytes.Buffer
	for tick := range 50 {
		frame := redrawFrame(tick)
		raw.Write(frame)
		_, err := server.Write(frame)
		require.NoError(t, err)
	}
	require.NoError(t, server.CloseWrite())

	assert.Equal(t, raw.Bytes(), <-received)
	assert.Less(t, wire.wire.Load()*20, int64(raw.Len()),
		"50 nearly identical frames of %d bytes took %d bytes on the wire", raw.Len()/50, wire.wire.Load())
}

func TestZstdStream_IncompressibleOutputDoesNotGrow(t *testing.T) {
	server, client, wire := newCompressedPair(t)
	received := drain(client)

	// already compressed data, e.g. a binary file transfer
	raw := make([]byte, 256*1024)
	_, _ = rand.Read(raw)
	for off := 0; off < len(raw); off += 32 * 1024 {
		_, err := server.Write(raw[off : off+32*1024])
		require.NoError(t, err)
	}
	require.NoError(t, server.CloseWrite())

	assert.Equal(t, raw, <-received)
	assert.LessOrEqual(t, wire.wire.Load(), int64(len(raw))+int64(len(raw))/100)
}

func TestZstdStream_CloseWriteEndsWithEOF(t *testing.T) {
	server, client, _ := newCompressedPair(t)
	received := drain(client)

	_, err := server.Write([]byte("logout\r\n"))
	require.NoError(t, err)
	require.NoError(t, server.CloseWrite())

	assert.Equal(t, "logout\r\n", string(<-received))
}

func TestZstdStream_CutOffStreamEndsWithEOF(t *testing.T) {
	server, client, wire := newCompressedPair(t)

	go func() { _, _ = server.Write([]byte("partial output")) }()
	assert.Equal(t, "partial output", string(readFullWithTimeout(t, client, len("partial output"))))

	// the stream goes away without the end of the zstd frame
	_ = wire.Conn.Close()
	n, err := client.Read(make([]byte, 16))
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, io.EOF)
}

func TestZstdStream_InputStaysUncompressed(t *testing.T) {
	server, client, _ := newCompressedPair(t)

	// stdin goes from the client to the server as it is
	go func() { _, _ = client.Write([]byte("ls -la\r")) }()
	assert.Equal(t, "ls -la\r", string(readFullWithTimeout(t, server, len("ls -la\r"))))
}

func TestZstdStream_ConcurrentWrites(t *testing.T) {
	server, client, _ := newCompressedPair(t)
	received := drain(client)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 50 {
				_, _ = fmt.Fprintf(server, "writer-%d line-%d\n", g, i)
			}
		})
	}
	wg.Wait()
	require.NoError(t, server.CloseWrite())

	lines := strings.Split(strings.TrimSuffix(string(<-received), "\n"), "\n")
	require.Len(t, lines, 8*50)
	seen := make(map[string]bool)
	for _, line := range lines {
		assert.False(t, seen[line], "duplicate line %q", line)
		seen[line] = true
	}
	for g := range 8 {
		for i := range 50 {
			assert.True(t, seen[fmt.Sprintf("writer-%d line-%d", g, i)])
		}
	}
}

func TestZstdStream_CloseWhileRead(t *testing.T) {
	// SshUdpSession.Close closes the stream while the output forwarder is still blocked in Read
	_, client, _ := newCompressedPair(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, client.Close())
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Read did not return after Close")
	}
}

func TestCompressionNegotiation(t *testing.T) {
	newServer := &ServerInfo{ServerVer: kTsshdVersion, Compress: kCompressZstd}
	oldServer := &ServerInfo{ServerVer: "0.1.10"}

	assert.False(t, compressionWanted(newServer, ""), "off unless the client asks for it")
	assert.True(t, compressionWanted(newServer, kCompressZstd))
	assert.False(t, compressionWanted(oldServer, kCompressZstd), "an old server cannot compress")

	msg := &startMessage{ID: 1, Pty: true}
	requestCompression(msg, true)
	assert.Equal(t, kCompressZstd, msg.Compress)

	msg = &startMessage{ID: 2, Attach: true}
	requestCompression(msg, true)
	assert.Empty(t, msg.Compress, "attaching replaces the stream, it is never compressed")

	msg = &startMessage{ID: 3}
	requestCompression(msg, false)
	assert.Empty(t, msg.Compress)
}

func TestCompressOutput(t *testing.T) {
	stream := &pipeStream{}

	out, err := compressOutput(&startMessage{Compress: kCompressZstd}, false, stream)
	require.NoError(t, err)
	assert.IsType(t, &zstdWriteStream{}, out)

	out, err = compressOutput(&startMessage{Compress: kCompressZstd}, true, stream)
	require.NoError(t, err)
	assert.Same(t, stream, out, "an attachable server does not compress")

	out, err = compressOutput(&startMessage{}, false, stream)
	require.NoError(t, err)
	assert.Same(t, stream, out, "a client that did not ask gets the plain stream")
}

func TestCompressionFieldsAreCompatible(t *testing.T) {
	// a client that does not compress sends exactly what it sent before
	data, err := json.Marshal(&startMessage{ID: 1, Pty: true})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "Compress")

	// an old server ignores the field, so it never sees a request it cannot serve
	data, err = json.Marshal(&startMessage{ID: 1, Pty: true, Compress: kCompressZstd})
	require.NoError(t, err)
	var old struct {
		ID  uint64
		Pty bool
	}
	require.NoError(t, json.Unmarshal(data, &old))
	assert.Equal(t, uint64(1), old.ID)

	// an old server's info has no Compress field
	var info ServerInfo
	require.NoError(t, json.Unmarshal([]byte(`{"ServerVer":"0.1.10","ProtoVer":1}`), &info))
	assert.False(t, compressionWanted(&info, kCompressZstd))

	// an old server's bare ack means no compression, an old client reads the new ack as a bare one
	var resp startResponse
	require.NoError(t, json.Unmarshal([]byte(`{"Msg":"`+kNoErrorMsg+`"}`), &resp))
	assert.Empty(t, resp.Compress)
	data, err = json.Marshal(&startResponse{errorMessage{Msg: kNoErrorMsg}, kCompressZstd})
	require.NoError(t, err)
	var oldAck errorMessage
	require.NoError(t, json.Unmarshal(data, &oldAck))
	assert.Equal(t, kNoErrorMsg, oldAck.Msg)
}
