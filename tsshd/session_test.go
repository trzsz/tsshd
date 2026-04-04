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
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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
	oriMaxLines := maxPendingOutputLines
	maxPendingOutputLines = maxLines

	var clientChecker *timeoutChecker
	if timeout {
		clientChecker = newTimeoutChecker(time.Minute)
		clientChecker.lastAliveTime.Store(time.Now().UnixMilli() - 61*1000)
		select {
		case clientChecker.timeoutEventChan <- struct{}{}:
		default:
		}
		for !clientChecker.isTimeout() {
			time.Sleep(time.Millisecond)
		}
	} else {
		clientChecker = newTimeoutChecker(0)
	}

	server := &sshUdpServer{}
	server.keepPendingOutput.Store(keepPending)

	sess := &sessionContext{rows: 0, clientChecker: newReplaceableTimeoutChecker(clientChecker)}
	sess.server.Store(server)

	return sess, func() { maxPendingOutputLines = oriMaxLines }
}

func runForwardOutputAndReconnect(s *sessionContext, reader *chunkReader, stream *mockStream, callback func()) {
	var wg sync.WaitGroup

	wg.Go(func() {
		s.forwardOutput("stdout", reader, stream)
	})

	go func() {
		if callback != nil {
			time.Sleep(50 * time.Millisecond)
			callback()
		}
		time.Sleep(50 * time.Millisecond)
		s.clientChecker.checker.updateNow()
	}()

	wg.Wait()
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

	runForwardOutputAndReconnect(s, reader, stream, nil)

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

	runForwardOutputAndReconnect(s, reader, stream, nil)

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
		fmt.Fprintf(&buf, "|%d\n", i)
	}
	reader := &chunkReader{data: [][]byte{buf.Bytes()}, chunk: 1}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "|0\n"), output)
	assert.Contains(output, "Warning: tsshd discarded")
	assert.True(strings.HasSuffix(output, "|998\n|999\n"), output)
	for i := 1; i < 998; i++ {
		require.NotContains(output, fmt.Sprintf("|%d\n", i))
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

	runForwardOutputAndReconnect(s, reader, stream, func() { close(signal) })

	output := stream.String()
	assert.True(strings.HasPrefix(output, "a\n"), output)
	assert.Contains(output, "Warning: tsshd discarded")
	assert.NotContains(output, "b\n")
	assert.NotContains(output, "c\n")
	assert.NotContains(output, "d\n")
	assert.True(strings.HasSuffix(output, "f\n1\r\n2\r\n"), output)
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

	runForwardOutputAndReconnect(s, reader, stream, func() {
		stream.err = errors.New("mock write error")
		close(signal)
	})

	assert.Equal("a\n", stream.String())
}

func TestForwardOutput_TimeoutCacheLeft(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("123a\nb\nc\nd\n1\r\n2\r\n3\r\n")}, chunk: 3}

	runForwardOutputAndReconnect(s, reader, stream, nil)

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

	runForwardOutputAndReconnect(s, reader, stream, nil)

	assert.Equal("a\nb\nc\nd\n", stream.String())
}

func TestForwardOutput_KeepPendingWaitFail(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(true, true, 2)
	defer reset()

	s.clientChecker.checker.Close()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("a\nb\nc\nd\n")}, chunk: 1}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "a"), output)
}

func TestForwardOutput_WaitFailAfterEOF(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	s.clientChecker.checker.Close()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("a\nb\nc\nd\n")}, chunk: 1}

	runForwardOutputAndReconnect(s, reader, stream, nil)

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
		fmt.Fprintf(&buf, "%%output %%56 %d\r\n", i)
	}
	reader := &chunkReader{data: [][]byte{buf.Bytes()}, chunk: 10}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "%output %56 0\r\n"), output)
	assert.Contains(output, "%output %56 \\015\\033[0;33mWarning: tsshd discarded")
	assert.NotContains(output, "%%output")
	assert.True(strings.HasSuffix(output, "%output %56 9\r\n"), output)
}

func TestForwardOutput_DiscardExtendedOutput(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 20)
	defer reset()

	stream := newMockStream()
	var buf bytes.Buffer
	for i := range 100 {
		fmt.Fprintf(&buf, "%%extended-output %%123 0 : %d\r\n", i)
	}
	reader := &chunkReader{data: [][]byte{buf.Bytes()}, chunk: 10}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "%extended-output %123 0 : 0\r\n"), output)
	assert.Contains(output, "%output %123 \\015\\033[0;33mWarning: tsshd discarded")
	assert.True(strings.HasSuffix(output, "%extended-output %123 0 : 99\r\n"), output)
}

func TestForwardOutput_FilterAllESC6n(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 10)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{
		data: [][]byte{
			[]byte("X\n\x1b[6nY\n\x1b[6nZ\x1b[6n"),
		},
		chunk: 1,
	}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	assert.Equal("X\nY\nZ", stream.String())
}

func TestForwardOutput_KeepPendingESC6n(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(true, true, 10)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{
		data: [][]byte{
			[]byte("X\n\x1b[6nY\n\x1b[6nZ\x1b[6n"),
		},
		chunk: 1,
	}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	assert.Equal("X\n\x1b[6nY\n\x1b[6nZ\x1b[6n", stream.String())
}

func TestForwardOutput_KeepESC6nAfterReconnect(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()

	signal := make(chan struct{})
	reader := &chunkReader{
		data: [][]byte{
			[]byte("X\n\x1b[6nY\n\x1b[6nZ\x1b[6n"),
			[]byte("1\x1b[6n\n\x1b[6n"),
		},
		signal: []chan struct{}{signal},
		chunk:  1,
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		close(signal)
	}()

	runForwardOutputAndReconnect(s, reader, stream, nil)

	assert.Equal("X\nY\nZ1\x1b[6n\n\x1b[6n", stream.String())
}

func TestForwardOutput_MultiLinesAtOnce(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{
		data: [][]byte{
			[]byte("1\n2\n3\n4\n5\n"),
		},
		chunk: 100,
	}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "1\n"), output)
	assert.Contains(output, "Warning: tsshd discarded")
	assert.NotContains(output, "2\n")
	assert.NotContains(output, "3\n")
	assert.True(strings.HasSuffix(output, "4\n5\n"), output)
}

func TestForwardOutput_KeepMultiLines(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(true, true, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{
		data: [][]byte{
			[]byte("1\n2\n3\n4\n5\n"),
		},
		chunk: 100,
	}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	assert.Equal("1\n2\n3\n4\n5\n", stream.String())
}

func TestForwardOutput_NormalMultiLines(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, false, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{
		data: [][]byte{
			[]byte("1\n2\n3\n4\n5\n"),
		},
		chunk: 100,
	}

	s.forwardOutput("stdout", reader, stream)

	assert.Equal("1\n2\n3\n4\n5\n", stream.String())
}

func TestForwardOutput_ReconnectWhileReadBlocked(t *testing.T) {
	assert := assert.New(t)

	s, reset := newTestSessionContext(false, true, 10)
	defer reset()

	stream := newMockStream()

	block := make(chan struct{})

	reader := &chunkReader{
		data: [][]byte{
			[]byte("a\nb\nc\n"),
			[]byte("d\n"),
		},
		signal: []chan struct{}{block},
		chunk:  1,
	}

	go func() {
		runForwardOutputAndReconnect(s, reader, stream, nil)
	}()

	time.Sleep(100 * time.Millisecond)
	assert.Equal("a\nb\nc\n", stream.String())

	close(block)
}

func TestForwardOutput_TimeoutWithoutNewLine(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, true, 2)
	defer reset()

	stream := newMockStream()
	reader := &chunkReader{data: [][]byte{[]byte("a\rb\rc\rd\re\rf\r")}, chunk: 1}

	runForwardOutputAndReconnect(s, reader, stream, nil)

	output := stream.String()
	assert.True(strings.HasPrefix(output, "a\r"), output)
	assert.Contains(output, "Warning: tsshd discarded")
	assert.NotContains(output, "\r\n")
	assert.NotContains(output, "c\r")
	assert.True(strings.HasSuffix(output, "e\rf\r"), output)
}

func TestParsePortRanges(t *testing.T) {
	enableWarning := enableWarningLogging
	enableWarningLogging = false
	defer func() { enableWarningLogging = enableWarning }()

	assert := assert.New(t)
	assert.Equal([][2]uint16{{22, 22}}, parsePortRanges("22"))
	assert.Equal([][2]uint16{{100, 102}}, parsePortRanges("100-102"))
	assert.Equal([][2]uint16{{200, 202}}, parsePortRanges("200 - 202"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}, {30, 30}}, parsePortRanges("10 20 30"))
	assert.Equal([][2]uint16{{1, 3}, {5, 5}, {7, 9}, {11, 11}}, parsePortRanges("1-3 5,7 - 9 11"))
	assert.Equal([][2]uint16{{1, 2}, {3, 4}, {5, 5}}, parsePortRanges("1-2,3-4 5"))
	assert.Equal([][2]uint16{{10, 12}, {15, 15}}, parsePortRanges("  10\t-\t12  , 15 "))
	assert.Equal([][2]uint16{{50, 50}}, parsePortRanges("50-50"))
	assert.Equal([][2]uint16{{10, 10}, {20, 20}}, parsePortRanges("10,,20"))
	assert.Equal([][2]uint16(nil), parsePortRanges("0,70000,abc"))
	assert.Equal([][2]uint16(nil), parsePortRanges("100-50"))
	assert.Equal([][2]uint16(nil), parsePortRanges("-"))
	assert.Equal([][2]uint16(nil), parsePortRanges("- 10"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 -"))
	assert.Equal([][2]uint16{{1, 3}, {7, 7}}, parsePortRanges("1-3,abc,5 - 4,7"))
	assert.Equal([][2]uint16(nil), parsePortRanges(""))
	assert.Equal([][2]uint16(nil), parsePortRanges("8000-9000-10000"))
	assert.Equal([][2]uint16(nil), parsePortRanges("8000-"))
	assert.Equal([][2]uint16(nil), parsePortRanges("-9000"))
	assert.Equal([][2]uint16{{10, 12}}, parsePortRanges("10 - 12 - 15"))
	assert.Equal([][2]uint16{{1, 65535}}, parsePortRanges("1-65535"))
	assert.Equal([][2]uint16{{10, 10}, {10, 10}, {10, 10}}, parsePortRanges("10 10 10"))
	assert.Equal([][2]uint16{{20, 25}, {22, 23}}, parsePortRanges("20-25 22-23"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 - 0"))
	assert.Equal([][2]uint16(nil), parsePortRanges("10 - - 11"))
	assert.Equal([][2]uint16{{10, 11}}, parsePortRanges("10 - 11 -"))
}
