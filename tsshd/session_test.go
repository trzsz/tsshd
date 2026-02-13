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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockStream struct {
	mutex sync.RWMutex
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
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.first {
		time.Sleep(10 * time.Millisecond)
		s.first = false
	}
	if s.err != nil {
		return 0, s.err
	}
	return s.buf.Write(p)
}

func (s *mockStream) setErr(err error) {
	s.mutex.Lock()
	s.err = err
	s.mutex.Unlock()
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
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.buf.String()
}

type chunkReader struct {
	data    [][]byte
	signal  []chan struct{}
	chunk   int
	offset  int // offset within current segment
	segment int // current segment index
}

type blockingReader struct {
	entered chan struct{}
	once    sync.Once
	dataCh  chan []byte
}

func (r *blockingReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	data, ok := <-r.dataCh
	if !ok {
		return 0, io.EOF
	}
	return copy(p, data), nil
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

	return &sessionContext{rows: 0, stdoutForwardToken: make(chan struct{}, 1)}, func() {
		globalServerProxy, globalSetting, maxPendingOutputLines = oriServerProxy, orieStting, oriMaxLines
	}
}

func TestDiscardPendingInputMarkerCopyAndClear(t *testing.T) {
	clearDiscardPendingInputMarker()
	defer clearDiscardPendingInputMarker()

	marker := []byte{0x01, 0x02, 0x03}
	setDiscardPendingInputMarker(marker)
	marker[0] = 0xFF

	got := getDiscardPendingInputMarker()
	if len(got) != 3 {
		t.Fatalf("unexpected marker length: %d", len(got))
	}
	if got[0] != 0x01 {
		t.Fatalf("marker must be copied on set, got first byte: %#x", got[0])
	}

	clearDiscardPendingInputMarker()
	if got := getDiscardPendingInputMarker(); got != nil {
		t.Fatalf("marker should be nil after clear")
	}
	if discardPendingInputFlag.Load() {
		t.Fatalf("discard pending flag should be false after clear")
	}
}

func TestForwardOutput_NonPtyResumeUnblocksRead(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, false, 10)
	defer reset()
	s.resumeChan = make(chan struct{})

	// Use a real os.Pipe to exercise the SetReadDeadline path,
	// simulating what cmd.StdoutPipe() returns for non-PTY sessions.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	// s.pty is nil (non-PTY), s.stdout is the pipe read end.
	s.stdout = pr

	oldStream := newMockStream()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.forwardOutput("stdout", pr, oldStream)
	}()

	// Give the forwarder time to enter reader.Read() which blocks on the pipe.
	time.Sleep(50 * time.Millisecond)

	// Write some data before resume so it gets read and buffered.
	_, _ = pw.Write([]byte("before-resume\n"))
	time.Sleep(50 * time.Millisecond)

	// Resume: interruptStdoutRead sets a past deadline, unblocking the Read.
	s.signalResume()

	// The old forwarder should exit promptly (not hang for 30s).
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("old stdout forwarder did not exit after resume")
	}

	// Write more data after resume — this will be picked up by the new forwarder.
	_, _ = pw.Write([]byte("after-resume\n"))

	// New forwarder should acquire the token and read from the pipe.
	newStream := newMockStream()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		s.forwardOutput("stdout", pr, newStream)
	}()

	// Give the new forwarder time to start and read.
	time.Sleep(100 * time.Millisecond)

	// Close write end to make the new forwarder's Read return EOF.
	pw.Close()

	select {
	case <-done2:
	case <-time.After(5 * time.Second):
		t.Fatalf("new stdout forwarder did not complete")
	}

	// The new forwarder should have received the pending output from
	// the old forwarder plus data written after resume.
	output := newStream.String()
	assert.Contains(output, "after-resume\n")
}

func TestForwardOutput_ResumeStoresPendingOutput(t *testing.T) {
	assert := assert.New(t)
	s, reset := newTestSessionContext(false, false, 10)
	defer reset()
	s.resumeChan = make(chan struct{})

	oldStream := newMockStream()
	reader := &blockingReader{
		entered: make(chan struct{}),
		dataCh:  make(chan []byte, 1),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.forwardOutput("stdout", reader, oldStream)
	}()

	<-reader.entered
	s.signalResume()
	reader.dataCh <- []byte("resume-data")
	close(reader.dataCh)
	<-done

	assert.Equal("", oldStream.String())

	newStream := newMockStream()
	eofReader := &chunkReader{}
	s.forwardOutput("stdout", eofReader, newStream)
	assert.Equal("resume-data", newStream.String())
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
	stream.setErr(errors.New("mock write error"))
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
		stream.setErr(errors.New("mock write error"))
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

	s.forwardOutput("stdout", reader, stream)

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

	s.forwardOutput("stdout", reader, stream)

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
		globalServerProxy.clientChecker.timeoutFlag.Store(false)
		close(signal)
	}()

	s.forwardOutput("stdout", reader, stream)

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

	s.forwardOutput("stdout", reader, stream)

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

	s.forwardOutput("stdout", reader, stream)

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
