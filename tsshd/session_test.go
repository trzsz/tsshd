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
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatedStream blocks the output forwarder on the first write until the gate is
// released, so that the output is still being forwarded when the session ends.
type gatedStream struct {
	mu        sync.Mutex
	buf       []byte
	gate      chan struct{}
	started   chan struct{}
	blocked   bool
	closed    atomic.Bool
	fullClose atomic.Bool
}

func newGatedStream(gate chan struct{}) *gatedStream {
	return &gatedStream{gate: gate, started: make(chan struct{})}
}

func (s *gatedStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	first := !s.blocked
	s.blocked = true
	s.mu.Unlock()

	if first {
		close(s.started)
		<-s.gate
	}

	if s.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	return len(p), nil
}

func (s *gatedStream) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf)
}

func (s *gatedStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *gatedStream) Close() error {
	s.closed.Store(true)
	s.fullClose.Store(true)
	return nil
}

func (s *gatedStream) CloseRead() error                 { return nil }
func (s *gatedStream) CloseWrite() error                { s.closed.Store(true); return nil }
func (s *gatedStream) LocalAddr() net.Addr              { return nil }
func (s *gatedStream) RemoteAddr() net.Addr             { return nil }
func (s *gatedStream) SetDeadline(time.Time) error      { return nil }
func (s *gatedStream) SetReadDeadline(time.Time) error  { return nil }
func (s *gatedStream) SetWriteDeadline(time.Time) error { return nil }

// newCmdTestSession starts a session running the given shell command, the output
// pipes are created by StartCmd, but nothing is forwarding the output yet.
func newCmdTestSession(t *testing.T, script string) *sessionContext {
	t.Helper()

	sess, cleanup := newTestSessionContext(false, false, maxPendingOutputLines)
	t.Cleanup(cleanup)

	sess.id = 1
	sess.cmd = exec.Command("sh", "-c", script)
	sess.outDone = make(chan struct{})
	require.NoError(t, sess.StartCmd())

	return sess
}

// shortOutputDrain makes Wait return quickly, the output is forwarded in the
// background no matter how long the drain waits.
func shortOutputDrain(t *testing.T, drain time.Duration) {
	t.Helper()

	oriDrain := outputDrainTimeout
	outputDrainTimeout = drain
	t.Cleanup(func() { outputDrainTimeout = oriDrain })
}

// TestSessionOutputPipesAfterWait verifies that the output pipes created by
// tsshd are still readable after waiting for the child process, so that the
// output that is still buffered in the pipes is not discarded.
func TestSessionOutputPipesAfterWait(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test uses a unix shell command")
	}

	shortOutputDrain(t, 100*time.Millisecond)

	sess := newCmdTestSession(t, "head -c 32768 /dev/zero; head -c 4096 /dev/zero >&2; exit 7")
	sess.Wait()

	stdout, err := io.ReadAll(sess.stdout)
	require.NoError(t, err)
	assert.Len(t, stdout, 32768)

	stderr, err := io.ReadAll(sess.stderr)
	require.NoError(t, err)
	assert.Len(t, stderr, 4096)

	assert.Equal(t, 7, sess.cmd.ProcessState.ExitCode())
}

// TestSessionOutputForwardedBeforeClose verifies that the output streams are not
// closed while the output is still being forwarded, even if the session ends
// before the output could be forwarded completely.
func TestSessionOutputForwardedBeforeClose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test uses a unix shell command")
	}

	shortOutputDrain(t, 100*time.Millisecond)

	gate := make(chan struct{})
	stream := newGatedStream(gate)

	sess := newCmdTestSession(t, "head -c 32768 /dev/zero")
	sess.forwardIO(&sshUdpServer{args: &tsshdArgs{Attachable: true}}, stream, &discardStream{})

	// The forwarder is blocked on the first write, the output is still pending.
	<-stream.started
	require.Zero(t, stream.size())

	sess.Wait()
	assert.False(t, stream.closed.Load(), "the session closed the stream before forwarding the output")

	sess.Close()
	assert.False(t, stream.closed.Load(), "the session closed the stream before forwarding the output")

	// The output is forwarded in the background after the session has ended, and
	// the stream is closed only after the output has been forwarded completely.
	close(gate)
	require.Eventually(t, func() bool { return stream.size() == 32768 }, 5*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return stream.closed.Load() }, 5*time.Second, 5*time.Millisecond)

	// Wait for the session to close the output stream, so that the session does
	// not touch the output after the test has been completed.
	require.Eventually(t, func() bool { return stream.fullClose.Load() }, 5*time.Second, 5*time.Millisecond)
}

// TestSessionOutputDescendantHoldsPipes verifies that the output pipes are
// closed to unblock the output forwarders, even if a descendant process that
// inherited the pipes keeps them open after the child process has exited.
func TestSessionOutputDescendantHoldsPipes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test uses a unix shell command")
	}

	shortOutputDrain(t, 100*time.Millisecond)

	oriGrace := outputCloseGrace
	outputCloseGrace = 200 * time.Millisecond
	t.Cleanup(func() { outputCloseGrace = oriGrace })

	sess := newCmdTestSession(t, "sleep 10 & exit 0")
	sess.forwardIO(&sshUdpServer{args: &tsshdArgs{}}, &mockStream{}, &discardStream{})

	sess.Wait()
	select {
	case <-sess.outDone:
		require.Fail(t, "the descendant process should keep the output pipes open")
	default:
	}

	sess.Close()

	// The pipes are closed after the grace period, the forwarders return and the
	// session does not leak the file descriptors or the goroutines.
	select {
	case <-sess.outDone:
	case <-time.After(5 * time.Second):
		require.Fail(t, "the output forwarders did not return after the session was closed")
	}

	assert.Equal(t, ^uintptr(0), sess.stdout.(*os.File).Fd(), "the stdout pipe should have been closed")
	assert.Equal(t, ^uintptr(0), sess.stderr.(*os.File).Fd(), "the stderr pipe should have been closed")
}
