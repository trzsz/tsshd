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
	startOnce sync.Once
	closeCh   chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool
	fullClose atomic.Bool
}

func newGatedStream(gate chan struct{}) *gatedStream {
	return &gatedStream{
		gate:    gate,
		started: make(chan struct{}),
		closeCh: make(chan struct{}),
	}
}

func (s *gatedStream) Write(p []byte) (int, error) {
	s.startOnce.Do(func() {
		close(s.started)
	})

	select {
	case <-s.gate:
	case <-s.closeCh:
		return 0, fmt.Errorf("stream closed")
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
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
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

func TestSessionOutputPipesAfterWait(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test uses a unix shell command")
	}

	sess := newCmdTestSession(t, "echo stdout-marker; echo stderr-marker >&2; exit 7")
	t.Cleanup(func() {
		if sess.stdout != nil {
			_ = sess.stdout.Close()
		}
		if sess.stderr != nil {
			_ = sess.stderr.Close()
		}
	})

	_ = sess.cmd.Wait()

	stdout, err := io.ReadAll(sess.stdout)
	require.NoError(t, err)
	assert.Equal(t, "stdout-marker\n", string(stdout))

	stderr, err := io.ReadAll(sess.stderr)
	require.NoError(t, err)
	assert.Equal(t, "stderr-marker\n", string(stderr))

	assert.Equal(t, 7, sess.cmd.ProcessState.ExitCode())
}

func setSessionOutputTimeouts(t *testing.T, idle, limit time.Duration) {
	t.Helper()
	oldIdle, oldLimit := outputIdleTimeout, outputDrainLimit
	outputIdleTimeout, outputDrainLimit = idle, limit
	t.Cleanup(func() { outputIdleTimeout, outputDrainLimit = oldIdle, oldLimit })
}

func TestSessionOutputForwardedBeforeClose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test uses a unix shell command")
	}

	tests := []struct {
		name       string
		attachable bool
		middleware bool
	}{
		{"attachable", true, false},
		{"non-attachable", false, false},
		{"middleware", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSessionOutputTimeouts(t, 30*time.Millisecond, 2*time.Second)

			gate := make(chan struct{})
			stream := newGatedStream(gate)

			var sess *sessionContext
			if tt.middleware {
				var cleanup func()
				sess, cleanup = newTestSessionContext(false, false, maxPendingOutputLines)
				t.Cleanup(cleanup)
				reader, writer := io.Pipe()
				sess.stdout = reader
				sess.outDone = make(chan struct{})
				sess.started = true
				sess.mwSess = &middlewareSession{stdout: writer, waitCh: make(chan struct{})}
				go func() {
					_, _ = writer.Write(make([]byte, 32768))
					_ = sess.mwSess.Exit(0)
				}()
			} else {
				sess = newCmdTestSession(t, "head -c 32768 /dev/zero")
			}
			sess.forwardIO(&sshUdpServer{args: &tsshdArgs{Attachable: tt.attachable}}, stream, &discardStream{})

			// The forwarder is blocked on the first write, the output is still pending.
			<-stream.started
			require.Zero(t, stream.size())

			waitDone := make(chan struct{})
			go func() {
				sess.Wait()
				sess.Close()
				close(waitDone)
			}()

			// Hold backpressure for at least 100ms (longer than idle timeout 30ms)
			time.Sleep(120 * time.Millisecond)
			assert.False(t, stream.fullClose.Load(), "the session closed the stream before forwarding the output")

			// Release the gate to let output complete
			close(gate)

			select {
			case <-waitDone:
			case <-time.After(5 * time.Second):
				t.Fatal("session Wait/Close did not return in time")
			}

			assert.Equal(t, 32768, stream.size(), "output should be completely forwarded")
			assert.True(t, stream.closed.Load(), "stream should be half-closed (CloseWrite)")
			assert.False(t, stream.fullClose.Load(), "stream should not have full Close called")
		})
	}
}

// newPipeTestSession leaves the parent writer open to model inherited output.
func newPipeTestSession(t *testing.T) (*sessionContext, *os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	sess, cleanup := newTestSessionContext(false, false, maxPendingOutputLines)
	t.Cleanup(cleanup)
	sess.id = 1
	sess.cmd = exec.Command("true")
	if runtime.GOOS == "windows" {
		sess.cmd = exec.Command("cmd", "/c", "exit 0")
	}
	require.NoError(t, sess.cmd.Start())
	sess.started = true
	sess.stdout = newSessionOutputPipe(reader)
	sess.outDone = make(chan struct{})
	return sess, reader, writer
}

func TestSessionOutputDescendantHoldsPipes(t *testing.T) {
	setSessionOutputTimeouts(t, 50*time.Millisecond, 2*time.Second)

	sess, stdoutReader, _ := newPipeTestSession(t)

	stderrReader, stderrWriter, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = stderrWriter.Close() })

	sess.stderr = newSessionOutputPipe(stderrReader)

	stream := &mockStream{}
	sess.forwardIO(&sshUdpServer{args: &tsshdArgs{}}, stream, &discardStream{})

	start := time.Now()
	sess.Wait()
	sess.Close()
	elapsed := time.Since(start)

	select {
	case <-sess.outDone:
	case <-time.After(2 * time.Second):
		require.Fail(t, "the output forwarders did not return after idle timeout")
	}

	assert.GreaterOrEqual(t, elapsed, 40*time.Millisecond)
	assert.Less(t, elapsed, 1*time.Second)

	assert.Equal(t, ^uintptr(0), stdoutReader.Fd(), "the stdout pipe should have been closed")
	assert.Equal(t, ^uintptr(0), stderrReader.Fd(), "the stderr pipe should have been closed")
}

func TestSessionOutputDrainPolicy(t *testing.T) {
	t.Run("SustainedOutputExceedingIdle", func(t *testing.T) {
		setSessionOutputTimeouts(t, 60*time.Millisecond, 2*time.Second)

		sess, _, stdoutWriter := newPipeTestSession(t)

		stream := &mockStream{}
		sess.forwardIO(&sshUdpServer{args: &tsshdArgs{}}, stream, &discardStream{})

		var expected bytes.Buffer
		writerDone := make(chan struct{})
		go func() {
			defer close(writerDone)
			defer func() { _ = stdoutWriter.Close() }()
			for i := range 8 {
				time.Sleep(30 * time.Millisecond)
				chunk := fmt.Sprintf("chunk-%d\n", i)
				expected.WriteString(chunk)
				_, _ = stdoutWriter.Write([]byte(chunk))
			}
		}()

		start := time.Now()
		sess.Wait()
		sess.Close()
		<-writerDone
		elapsed := time.Since(start)

		select {
		case <-sess.outDone:
		case <-time.After(2 * time.Second):
			t.Fatal("outDone did not close in time")
		}

		assert.GreaterOrEqual(t, elapsed, 200*time.Millisecond, "total drain should span multiple idle periods")
		assert.Equal(t, expected.String(), stream.String(), "all sustained output should be received")
	})

	t.Run("BlockedOutputAbortsAtDrainLimit", func(t *testing.T) {
		for _, disconnected := range []bool{false, true} {
			name := "connected"
			if disconnected {
				name = "disconnected"
			}
			t.Run(name, func(t *testing.T) {
				setSessionOutputTimeouts(t, 50*time.Millisecond, 150*time.Millisecond)

				gate := make(chan struct{})
				stream := newGatedStream(gate)

				sess, _, stdoutWriter := newPipeTestSession(t)

				server := &sshUdpServer{args: &tsshdArgs{Attachable: true}}
				server.keepPendingOutput.Store(disconnected)
				sess.server.Store(server)
				sess.forwardIO(server, stream, &discardStream{})

				// Keep the writer blocked while a disconnected forwarder has
				// cached output to flush after EOF.
				_, _ = stdoutWriter.Write([]byte("blocked data\n"))
				<-stream.started
				sess.outForwarder.handleBuffer([]byte("queued line\n"))
				if disconnected {
					sess.clientChecker.checker.timeoutFlag.Store(true)
					waitDone := make(chan struct{})
					go func() {
						sess.outForwarder.handleBuffer([]byte("cached line\n"))
						close(waitDone)
					}()
					require.Eventually(t, func() bool {
						if sess.outForwarder.handleMutex.TryLock() {
							sess.outForwarder.handleMutex.Unlock()
							return false
						}
						return true
					}, time.Second, time.Millisecond)
					defer func() {
						select {
						case <-waitDone:
						case <-time.After(time.Second):
							t.Fatal("disconnected output handler did not cancel")
						}
					}()
				}

				start := time.Now()
				sess.Wait()
				sess.Close()
				elapsed := time.Since(start)

				select {
				case <-sess.outDone:
				case <-time.After(1 * time.Second):
					t.Fatal("outDone should close within 1 second after abort")
				}

				assert.GreaterOrEqual(t, elapsed, 120*time.Millisecond)
				assert.Less(t, elapsed, 1*time.Second)
			})
		}
	})
}

type recordingStream struct {
	mu          sync.Mutex
	closedRead  bool
	closedWrite bool
	closedFull  bool
}

func (s *recordingStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *recordingStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closedWrite || s.closedFull {
		return 0, fmt.Errorf("write to closed stream")
	}
	return len(p), nil
}
func (s *recordingStream) CloseRead() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closedRead = true
	return nil
}
func (s *recordingStream) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closedWrite = true
	return nil
}
func (s *recordingStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closedFull = true
	return nil
}
func (s *recordingStream) LocalAddr() net.Addr              { return nil }
func (s *recordingStream) RemoteAddr() net.Addr             { return nil }
func (s *recordingStream) SetDeadline(time.Time) error      { return nil }
func (s *recordingStream) SetReadDeadline(time.Time) error  { return nil }
func (s *recordingStream) SetWriteDeadline(time.Time) error { return nil }

func TestReplaceableStreamFinish(t *testing.T) {
	for _, tt := range []struct {
		name   string
		stderr bool
		abort  bool
	}{
		{"finish", false, false},
		{"abort", false, true},
		{"stderr-finish", true, false},
		{"stderr-abort", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := &recordingStream{}
			var stream Stream = raw
			var stderr *stderrStream
			if tt.stderr {
				server := &sshUdpServer{stderrMap: make(map[uint64]*stderrStream)}
				var err error
				stderr, err = server.newStderrStream(10, raw)
				require.NoError(t, err)
				stream = stderr
			}
			rep := newReplaceableStream(stream)
			n, err := rep.Write([]byte("hello"))
			require.NoError(t, err)
			assert.Equal(t, 5, n)
			if tt.abort {
				require.NoError(t, rep.Close())
			} else {
				require.NoError(t, rep.finish())
			}
			if stderr != nil {
				waitDone := make(chan struct{})
				go func() { stderr.Wait(); close(waitDone) }()
				select {
				case <-waitDone:
				case <-time.After(time.Second):
					t.Fatal("stderrStream.Wait did not return")
				}
			}
			raw.mu.Lock()
			assert.Equal(t, tt.abort, raw.closedFull)
			assert.Equal(t, !tt.abort, raw.closedRead)
			assert.Equal(t, !tt.abort || tt.stderr, raw.closedWrite)
			raw.mu.Unlock()
			_, err = rep.Write([]byte("after close"))
			assert.Error(t, err)
		})
	}
}
