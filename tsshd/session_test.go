/*
MIT License

Copyright (c) 2024-2025 The Trzsz SSH Authors.

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
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockStream struct {
	buf   bytes.Buffer
	err   error
	first bool
}

func newMockStream() *mockStream {
	return &mockStream{first: true}
}

func (s *mockStream) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (s *mockStream) Write(p []byte) (int, error) {
	if s.first {
		time.Sleep(10 * time.Millisecond)
		s.first = false
	}
	if s.err != nil {
		return 0, s.err
	}
	return s.buf.Write(p)
}

func (s *mockStream) Close() error {
	return nil
}

func (s *mockStream) CloseRead() error {
	return nil
}

func (s *mockStream) CloseWrite() error {
	return nil
}

func (s *mockStream) LocalAddr() net.Addr {
	return nil
}

func (s *mockStream) RemoteAddr() net.Addr {
	return nil
}

func (s *mockStream) SetDeadline(t time.Time) error {
	return nil
}

func (s *mockStream) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *mockStream) SetWriteDeadline(t time.Time) error {
	return nil
}

func (s *mockStream) String() string {
	return s.buf.String()
}

type chunkReader struct {
	data    [][]byte
	signal  []chan struct{}
	chunk   int
	offset  int // offset within current segment
	segment int // current segment index
}

func (r *chunkReader) Read(p []byte) (n int, err error) {
	for {
		// no more segments
		if r.segment >= len(r.data) {
			return 0, io.EOF
		}

		// wait when entering a new segment (except the first)
		if r.offset == 0 && r.segment > 0 && r.segment-1 < len(r.signal) {
			if ch := r.signal[r.segment-1]; ch != nil {
				<-ch
			}
		}

		current := r.data[r.segment]

		// current segment exhausted → next
		if r.offset >= len(current) {
			r.segment++
			r.offset = 0
			continue
		}

		end := min(r.offset+r.chunk, len(current))
		n = copy(p, current[r.offset:end])
		r.offset += n
		return n, nil
	}
}

func newTestSessionContext(keepPending, timeout bool, maxLines int) (*sessionContext, func()) {
	oriServerProxy, orieStting, oriMaxLines := globalServerProxy, globalSetting, maxPendingOutputLines

	globalServerProxy = &serverProxy{
		clientChecker: newTimeoutChecker(0),
	}

	globalSetting.keepPendingOutput.Store(keepPending)
	globalServerProxy.clientChecker.timeoutFlag.Store(timeout)
	maxPendingOutputLines = maxLines

	return &sessionContext{rows: 0}, func() {
		globalServerProxy, globalSetting, maxPendingOutputLines = oriServerProxy, orieStting, oriMaxLines
	}
}

func TestForwardOutput_Normal(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, false, 10)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("a\nb\nc\n")}, chunk: 1}

	s.forwardOutput("stdout", reader, stream)

	assert.Equal("a\nb\nc\n", stream.String())
}

func TestForwardOutput_TimeoutDiscard(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("a\nb\nc\nd\n")}, chunk: 1}

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "a\n"), output)
	assert.Contains(output, "Warning: tsshd discarded")
	assert.NotContains(output, "b\n")
	assert.True(strings.HasSuffix(output, "c\nd\n"), output)
}

func TestForwardOutput_WriteError(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, false, 10)
	defer reset()

	stream := newMockStream()
	stream.err = errors.New("mock write error")
	reader := &chunkReader{data: [][]byte{[]byte("a\nb\nc\n")}, chunk: 1}

	s.forwardOutput("stdout", reader, stream)

	assert.Equal("", stream.String())
}

func TestForwardOutput_TimeoutAndEOF(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("A1\nB2\nC3\nD4\nE5\n")}, chunk: 1}

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "A1\n"), output)
	assert.Contains(output, "Warning: tsshd discarded")
	assert.NotContains(output, "B2\n")
	assert.NotContains(output, "C3\n")
	assert.True(strings.HasSuffix(output, "D4\nE5\n"), output)
}

func TestForwardOutput_VoidedCapacity(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()

	var buf bytes.Buffer
	for i := range 1000 {
		buf.WriteString(fmt.Sprintf("|%d\r\n", i))
	}
	reader := &chunkReader{data: [][]byte{buf.Bytes()}, chunk: 1}

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "|0\r\n"), output)
	assert.Contains(output, "Warning: tsshd discarded")
	assert.True(strings.HasSuffix(output, "|998\r\n|999\r\n"), output)
	for i := 1; i < 998; i++ {
		require.NotContains(output, fmt.Sprintf("|%d\r\n", i))
	}
}

func TestForwardOutput_FlushCacheBranch(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 3)
	defer reset()

	stream := newMockStream()

	signal := make(chan struct{})
	reader := &chunkReader{
		data: [][]byte{
			[]byte("a\nb\nc\nd\ne\nf\n"),
			[]byte("1\r\n2\r\n"),
		},
		signal: []chan struct{}{signal},
		chunk:  1,
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		globalServerProxy.clientChecker.timeoutFlag.Store(false)
		close(signal)
	}()

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "a\n"), output)
	assert.Contains(output, "Warning: tsshd discarded")
	assert.NotContains(output, "b\n")
	assert.NotContains(output, "c\n")
	assert.NotContains(output, "d\n")
	assert.True(strings.HasSuffix(output, "e\nf\n1\r\n2\r\n"), output)
}

func TestForwardOutput_FlushWriteError(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 3)
	defer reset()

	stream := newMockStream()

	signal := make(chan struct{})
	reader := &chunkReader{
		data: [][]byte{
			[]byte("a\nb\nc\nd\ne\nf\n"),
			[]byte("1\r\n2\r\n"),
		},
		signal: []chan struct{}{signal},
		chunk:  1,
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		globalServerProxy.clientChecker.timeoutFlag.Store(false)
		stream.err = errors.New("mock write error")
		close(signal)
	}()

	s.forwardOutput("stdout", reader, stream)

	assert.Equal("a\n", stream.String())
}

func TestForwardOutput_TimeoutCacheLeft(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("123a\nb\nc\nd\n1\r\n2\r\n3\r\n")}, chunk: 3}

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "123a\n"), output)
	assert.Contains(output, "Warning: tsshd discarded", output)
	assert.NotContains(output, "b\n")
	assert.NotContains(output, "c\n")
	assert.NotContains(output, "d\n")
	assert.NotContains(output, "1\r\n")
	assert.True(strings.HasSuffix(output, "2\r\n3\r\n"), output)
}

func TestForwardOutput_KeepPendingOutput(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(true, true, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("a\nb\nc\nd\n")}, chunk: 1}

	s.forwardOutput("stdout", reader, stream)

	assert.Equal("a\nb\nc\nd\n", stream.String())
}

func TestForwardOutput_KeepPendingWaitFail(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(true, true, 2)
	defer reset()

	globalServerProxy.clientChecker.reconnectedCh = make(chan struct{})
	globalServerProxy.clientChecker.Close()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("a\nb\nc\nd\n")}, chunk: 1}

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "a"), output)
}

func TestForwardOutput_WaitFailAfterEOF(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	globalServerProxy.clientChecker.reconnectedCh = make(chan struct{})
	globalServerProxy.clientChecker.Close()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("a\nb\nc\nd\n")}, chunk: 1}

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "a"), output)
}

func TestForwardOutput_DiscardTmuxOutput(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()
	var buf bytes.Buffer
	for i := range 10 {
		buf.WriteString(fmt.Sprintf("%%output %%56 %d\r\n", i))
	}
	reader := &chunkReader{data: [][]byte{buf.Bytes()}, chunk: 10}

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "%output %56 0\r\n"), output)
	assert.Contains(output, "%output %56 \\015\\033[0;33mWarning: tsshd discarded")
	assert.True(strings.HasSuffix(output, "%output %56 9\r\n"), output)
}

func TestForwardOutput_DiscardExtendedOutput(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 20)
	defer reset()

	stream := newMockStream()
	var buf bytes.Buffer
	for i := range 100 {
		buf.WriteString(fmt.Sprintf("%%extended-output %%123 0 : %d\r\n", i))
	}
	reader := &chunkReader{data: [][]byte{buf.Bytes()}, chunk: 10}

	s.forwardOutput("stdout", reader, stream)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "%extended-output %123 0 : 0\r\n"), output)
	assert.Contains(output, "%output %123 \\015\\033[0;33mWarning: tsshd discarded")
	assert.True(strings.HasSuffix(output, "%extended-output %123 0 : 99\r\n"), output)
}
