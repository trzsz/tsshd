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
	"io"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCmdTestSession starts a session running the given shell command, the output
// pipes are created by StartCmd, but nothing is forwarding the output yet.
func newCmdTestSession(t *testing.T, script string) *sessionContext {
	t.Helper()

	sess, cleanup := newTestSessionContext(false, false, maxPendingOutputLines)
	t.Cleanup(cleanup)

	sess.id = 1
	sess.cmd = exec.Command("sh", "-c", script)
	return sess
}

func TestSessionOutputPipesAfterWait(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test uses a unix shell command")
	}

	sess := newCmdTestSession(t, "/bin/echo -n stdout-marker; /bin/echo -n stderr-marker >&2; exit 7")

	require.NoError(t, sess.StartCmd())

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
	assert.Equal(t, "stdout-marker", string(stdout))

	stderr, err := io.ReadAll(sess.stderr)
	require.NoError(t, err)
	assert.Equal(t, "stderr-marker", string(stderr))

	assert.Equal(t, 7, sess.cmd.ProcessState.ExitCode())
}

func TestSessionWaitWithDescendant(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test uses a unix shell command")
	}

	oldTimeout := outputForwardTimeout
	outputForwardTimeout = 300 * time.Millisecond
	defer func() { outputForwardTimeout = oldTimeout }()

	sess := newCmdTestSession(t, "(sleep 0.1; /bin/echo -n stdout-marker; sleep 2) & exit 0")

	require.NoError(t, sess.StartCmd())

	stream := newMockStream()
	sess.outForwarder = sess.newOutputForwarder("stdout", sess.stdout, stream)
	sess.outWG.Go(sess.outForwarder.forward)

	done := make(chan struct{})
	go func() {
		sess.Wait()
		close(done)
	}()

	select {
	case <-done:
		assert.Equal(t, "stdout-marker", stream.String())
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after the output forward timeout")
	}
}

func TestSessionWaitWithDescendantPTY(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test: only Linux PTYs block when a descendant holds stdout")
	}

	oldTimeout := outputForwardTimeout
	outputForwardTimeout = 300 * time.Millisecond
	defer func() { outputForwardTimeout = oldTimeout }()

	sess := newCmdTestSession(t, `python3 -c 'import os, subprocess; os.setsid(); `+
		`subprocess.Popen(["sh", "-c", "sleep 0.1; /bin/echo -n stdout-marker; sleep 2"])'`)

	require.NoError(t, sess.StartPty())

	stream := newMockStream()
	sess.outForwarder = sess.newOutputForwarder("stdout", sess.stdout, stream)
	sess.outWG.Go(sess.outForwarder.forward)

	done := make(chan struct{})
	go func() {
		sess.Wait()
		close(done)
	}()

	select {
	case <-done:
		assert.Equal(t, "stdout-marker", stream.String())
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after the output forward timeout")
	}
}

func TestSessionCleanupFuncs(t *testing.T) {
	session := &sessionContext{}
	calls := 0

	if !session.addCleanupFunc(func() { calls++ }) {
		t.Fatal("failed to register first cleanup")
	}
	if !session.addCleanupFunc(func() { calls++ }) {
		t.Fatal("failed to register second cleanup")
	}

	if calls != 0 {
		t.Fatalf("cleanup ran before session shutdown: %d", calls)
	}

	// Simulate the session entering shutdown before running its cleanups.
	session.closed.Store(true)
	session.runCleanupFuncs()

	if calls != 2 {
		t.Fatalf("cleanup calls = %d, want 2", calls)
	}

	// Running the cleanup registry again must not repeat cleanups.
	session.runCleanupFuncs()
	if calls != 2 {
		t.Fatalf("cleanup ran more than once: %d", calls)
	}

	// Registering cleanup after shutdown must execute it immediately.
	if session.addCleanupFunc(func() { calls++ }) {
		t.Fatal("cleanup should not be registered after session shutdown")
	}
	if calls != 3 {
		t.Fatalf("cleanup registered after shutdown was not executed: %d", calls)
	}
}
