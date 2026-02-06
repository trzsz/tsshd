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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trzsz/shellescape"
)

var maxPendingOutputLines = 1000
var maxPendingResumeBytes = 4 * 1024 * 1024 // 4 MB cap for buffered resume output

var discardPendingInputFlag atomic.Bool
var discardPendingInputMarker []byte
var discardMarkerMu sync.Mutex
var discardMarkerCurrentIndex uint32
var discardMarkerIndexMu sync.Mutex
var discardGeneration atomic.Uint64

func setDiscardPendingInputMarker(marker []byte) {
	discardMarkerMu.Lock()
	discardPendingInputMarker = append(discardPendingInputMarker[:0], marker...)
	discardPendingInputFlag.Store(true)
	discardMarkerMu.Unlock()
}

func getDiscardPendingInputMarker() []byte {
	discardMarkerMu.Lock()
	defer discardMarkerMu.Unlock()
	if !discardPendingInputFlag.Load() || len(discardPendingInputMarker) == 0 {
		return nil
	}
	marker := make([]byte, len(discardPendingInputMarker))
	copy(marker, discardPendingInputMarker)
	return marker
}

func clearDiscardPendingInputMarker() {
	discardMarkerMu.Lock()
	discardPendingInputMarker = nil
	discardPendingInputFlag.Store(false)
	discardMarkerMu.Unlock()
}

func enablePendingInputDiscard() {
	if globalSetting.keepPendingInput.Load() {
		return
	}

	idx := getNextDiscardMarkerIndex()
	marker := []byte{0xFF, 0xC0, 0xC1, 0xFF,
		byte(idx >> 24), byte(idx >> 16), byte(idx >> 8), byte(idx),
	}
	setDiscardPendingInputMarker(marker)
	discardGeneration.Add(1)

	// Must use goroutine: this is called from udpFrontendToBackend via setClientConn.
	// A synchronous sendBusMessage would block the packet forwarding goroutine if KCP's
	// send buffer is full (no client ACKs during disconnection), causing a deadlock.
	// Capture marker by value to avoid closure-by-reference race when called rapidly.
	go func() {
		debug("discard marker: %X", marker)
		_ = sendBusMessage("discard", discardMessage{DiscardMarker: marker})
	}()
}

func getNextDiscardMarkerIndex() uint32 {
	discardMarkerIndexMu.Lock()
	defer discardMarkerIndexMu.Unlock()

	discardMarkerCurrentIndex++
	for i := 3; i >= 0; i-- {
		shift := i * 8
		b := (discardMarkerCurrentIndex >> shift) & 0xFF
		if b == ';' || b == '\r' { // skip ; and \r for tmux
			discardMarkerCurrentIndex = ((discardMarkerCurrentIndex >> shift) + 1) << shift
			return discardMarkerCurrentIndex
		}
	}
	return discardMarkerCurrentIndex
}

type sessionContext struct {
	id      uint64
	cols    int
	rows    int
	cmd     *exec.Cmd
	pty     *tsshdPty
	outWG   sync.WaitGroup
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	started bool
	closed  atomic.Bool

	discardedBuffer []byte

	// Per-session discard state: each session independently tracks its discard marker
	// to avoid cross-session interference when multiple sessions resume concurrently.
	discarding     bool
	discardMarker  []byte
	lastDiscardGen uint64

	// resumeChan signals I/O goroutines to stop when a resume takes over
	resumeChan chan struct{}
	resumeMu   sync.Mutex

	// activeInputStream is the stream currently being read by forwardInput.
	// Protected by resumeMu. Closed on resume to unblock a blocking Read.
	activeInputStream Stream

	// sizeMu protects cols, rows, and pty.Resize calls to prevent races
	// between triggerRedraw and SetSize.
	sizeMu sync.Mutex

	// redrawDone is closed by forwardOutput after acquiring the stdout token,
	// signaling the reattachIO redraw ticker goroutine to stop.
	redrawDone chan struct{}

	// stdoutForwardToken is a channel-based semaphore (capacity 1) that ensures only
	// one stdout reader goroutine exists at a time. Uses a channel instead of sync.Mutex
	// to support timeout and cancellation during resume handoff.
	stdoutForwardToken chan struct{}
	// pendingResumeOutput stores bytes read by a superseded stdout forwarder.
	pendingResumeOutput []byte
	pendingOutputMu     sync.Mutex
}

// signalResume closes the current resumeChan to signal old I/O goroutines to stop,
// then creates a new one for the new connection. It also closes the old input
// stream's read side to unblock any forwardInput goroutine stuck in stream.Read,
// and sets a past read deadline on stdout to unblock non-PTY stdout forwarders.
func (c *sessionContext) signalResume() {
	c.resumeMu.Lock()
	defer c.resumeMu.Unlock()
	if c.resumeChan != nil {
		close(c.resumeChan)
	}
	c.resumeChan = make(chan struct{})
	if c.activeInputStream != nil {
		_ = c.activeInputStream.CloseRead()
		c.activeInputStream = nil
	}
	// For non-PTY sessions, interrupt blocking stdout reads by setting a past deadline.
	// PTY sessions use SIGWINCH via triggerRedraw instead.
	c.interruptStdoutRead()
}

// interruptStdoutRead sets a past read deadline on stdout for non-PTY sessions
// to unblock a forwardOutput goroutine stuck in reader.Read(). This is the
// non-PTY equivalent of triggerRedraw (which uses SIGWINCH for PTY sessions).
func (c *sessionContext) interruptStdoutRead() {
	if c.pty != nil || c.stdout == nil {
		return
	}
	type deadliner interface {
		SetReadDeadline(time.Time) error
	}
	if d, ok := c.stdout.(deadliner); ok {
		_ = d.SetReadDeadline(time.Now())
	}
}

// clearStdoutReadDeadline removes the read deadline set by interruptStdoutRead,
// allowing the new forwarder to read from stdout normally.
func (c *sessionContext) clearStdoutReadDeadline() {
	if c.pty != nil || c.stdout == nil {
		return
	}
	type deadliner interface {
		SetReadDeadline(time.Time) error
	}
	if d, ok := c.stdout.(deadliner); ok {
		_ = d.SetReadDeadline(time.Time{})
	}
}

// triggerRedraw sends SIGWINCH to the shell to force a screen redraw.
// Uses the cols+1 trick to ensure shells notice the change.
func (c *sessionContext) triggerRedraw() {
	if c.pty == nil {
		return
	}
	c.sizeMu.Lock()
	_ = c.pty.Resize(c.cols+1, c.rows)
	c.sizeMu.Unlock()

	time.Sleep(10 * time.Millisecond)

	// Re-read cols/rows in case SetSize was called during the sleep.
	c.sizeMu.Lock()
	_ = c.pty.Resize(c.cols, c.rows)
	c.sizeMu.Unlock()
}

// getResumeChan returns the current resume channel (for checking in I/O loops)
func (c *sessionContext) getResumeChan() <-chan struct{} {
	c.resumeMu.Lock()
	defer c.resumeMu.Unlock()
	return c.resumeChan
}

func (c *sessionContext) appendPendingResumeOutput(buf []byte) {
	if len(buf) == 0 {
		return
	}
	c.pendingOutputMu.Lock()
	defer c.pendingOutputMu.Unlock()
	if len(c.pendingResumeOutput)+len(buf) > maxPendingResumeBytes {
		// Drop oldest data to stay within the cap.
		overflow := len(c.pendingResumeOutput) + len(buf) - maxPendingResumeBytes
		if overflow >= len(c.pendingResumeOutput) {
			c.pendingResumeOutput = c.pendingResumeOutput[:0]
		} else {
			c.pendingResumeOutput = c.pendingResumeOutput[overflow:]
		}
		// If buf alone exceeds the cap, keep only its tail.
		if len(buf) > maxPendingResumeBytes {
			buf = buf[len(buf)-maxPendingResumeBytes:]
		}
	}
	c.pendingResumeOutput = append(c.pendingResumeOutput, buf...)
}

func (c *sessionContext) takePendingResumeOutput() []byte {
	c.pendingOutputMu.Lock()
	defer c.pendingOutputMu.Unlock()
	if len(c.pendingResumeOutput) == 0 {
		return nil
	}
	buf := make([]byte, len(c.pendingResumeOutput))
	copy(buf, c.pendingResumeOutput)
	c.pendingResumeOutput = nil
	return buf
}

type stderrStream struct {
	id     uint64
	wg     sync.WaitGroup
	stream Stream
}

var sessionMu sync.Mutex
var sessionMap = make(map[uint64]*sessionContext)

var stderrMu sync.Mutex
var stderrMap = make(map[uint64]*stderrStream)

func (c *sessionContext) StartPty() error {
	var err error
	c.pty, err = newTsshdPty(c.cmd, c.cols, c.rows)
	if err != nil {
		return fmt.Errorf("shell pty start failed: %v", err)
	}
	c.stdin = c.pty.stdin
	c.stdout = c.pty.stdout
	c.started = true
	debug("session [%d] start pty success", c.id)
	return nil
}

func (c *sessionContext) StartCmd() error {
	var err error
	if c.stdin, err = c.cmd.StdinPipe(); err != nil {
		return fmt.Errorf("cmd stdin pipe failed: %v", err)
	}
	if c.stdout, err = c.cmd.StdoutPipe(); err != nil {
		return fmt.Errorf("cmd stdout pipe failed: %v", err)
	}
	if c.stderr, err = c.cmd.StderrPipe(); err != nil {
		return fmt.Errorf("cmd stderr pipe failed: %v", err)
	}
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("start cmd %v failed: %v", c.cmd.Args, err)
	}
	c.started = true
	debug("session [%d] start cmd success", c.id)
	return nil
}

func (c *sessionContext) showMotd(stream Stream) {
	printMotd := func(paths []string) {
		for _, path := range paths {
			file, err := os.Open(path)
			if err != nil {
				continue
			}
			defer func() { _ = file.Close() }()
			reader := bufio.NewReader(file)
			for {
				line, err := reader.ReadBytes('\n')
				if err != nil {
					return
				}
				if len(line) <= 1 {
					_, _ = stream.Write([]byte("\r\n"))
					continue
				}
				if line[len(line)-2] != '\r' {
					_, _ = stream.Write(line[:len(line)-1])
					_, _ = stream.Write([]byte("\r\n"))
					continue
				}
				_, _ = stream.Write(line)
			}
		}
	}
	printMotd([]string{"/run/motd.dynamic", "/var/run/motd.dynamic"})
	printMotd([]string{"/etc/motd"}) // always print traditional /etc/motd.
}

func (c *sessionContext) discardPendingInput(buf []byte) error {
	c.discardedBuffer = append(c.discardedBuffer, buf...)
	if len(c.discardedBuffer) > maxPendingResumeBytes {
		warning("discardedBuffer exceeded %d bytes, giving up on discard marker", maxPendingResumeBytes)
		c.discardedBuffer = nil
		c.discardMarker = nil
		c.discarding = false
		return nil
	}
	pos := bytes.Index(c.discardedBuffer, c.discardMarker)
	if pos < 0 {
		return nil
	}

	remainingBuffer := c.discardedBuffer[pos+len(c.discardMarker):]
	if len(remainingBuffer) > 0 {
		if err := writeAll(c.stdin, remainingBuffer); err != nil {
			return err
		}
	}

	if pos > 0 {
		if enableDebugLogging {
			debug("discard input: %s", strconv.QuoteToASCII(string(c.discardedBuffer[:pos])))
		}
		_ = sendBusMessage("discard", discardMessage{DiscardedInput: c.discardedBuffer[:pos]})
	} else if enableDebugLogging {
		debug("no pending input to discard")
	}
	c.discardedBuffer = nil
	c.discardMarker = nil
	c.discarding = false
	clearDiscardPendingInputMarker()

	debug("new transport path is now active")
	return nil
}

func (c *sessionContext) forwardInput(stream Stream) {
	c.resumeMu.Lock()
	c.activeInputStream = stream
	c.resumeMu.Unlock()

	resumeCh := c.getResumeChan()
	resumed := false
	defer func() {
		c.resumeMu.Lock()
		if c.activeInputStream == stream {
			c.activeInputStream = nil
		}
		c.resumeMu.Unlock()
		// For PTY sessions, never close stdin here - keep PTY alive for resume.
		// For non-PTY sessions, close stdin to propagate EOF to the child process
		// (commands like cat, filters, piped Run need EOF to terminate),
		// unless exiting for a resume where the next forwardInput will take over.
		if c.pty == nil && !resumed {
			_ = c.stdin.Close()
		}
		_ = stream.CloseRead()
	}()
	buffer := make([]byte, 32*1024)
	for {
		// Check for resume signal before blocking read.
		select {
		case <-resumeCh:
			resumed = true
			return
		default:
		}

		n, err := stream.Read(buffer)

		// Check again after read returns.
		select {
		case <-resumeCh:
			resumed = true
			return
		default:
		}

		if n > 0 {
			// Enter per-session discard mode when a new discard generation is detected.
			// Each session independently tracks its marker to avoid cross-session interference.
			if !c.discarding {
				if gen := discardGeneration.Load(); gen > c.lastDiscardGen {
					if marker := getDiscardPendingInputMarker(); len(marker) > 0 {
						c.lastDiscardGen = gen
						c.discarding = true
						c.discardMarker = marker
					}
				}
			}
			if c.discarding {
				if err := c.discardPendingInput(buffer[:n]); err != nil {
					break
				}
			} else {
				if err := writeAll(c.stdin, buffer[:n]); err != nil {
					break
				}
			}
		}
		if err != nil {
			break
		}
	}
	debug("session [%d] stdin completed", c.id)
}

func (c *sessionContext) forwardOutput(name string, reader io.Reader, stream Stream) {
	resumeCh := c.getResumeChan()

	if name == "stdout" {
		select {
		case c.stdoutForwardToken <- struct{}{}:
			defer func() { <-c.stdoutForwardToken }()
		case <-resumeCh:
			return
		case <-time.After(30 * time.Second):
			warning("session [%d] timed out waiting for previous stdout forwarder to exit", c.id)
			return
		}
		// Old forwarder exited; stop the reattachIO redraw ticker.
		c.resumeMu.Lock()
		if c.redrawDone != nil {
			close(c.redrawDone)
			c.redrawDone = nil
		}
		c.resumeMu.Unlock()
		// Clear any read deadline set by signalResume for non-PTY sessions.
		c.clearStdoutReadDeadline()
	}

	var writeError atomic.Bool
	done := make(chan struct{})
	ch := make(chan []byte, 1)
	defer func() { close(ch); <-done }()
	go func() {
		defer func() { _ = stream.CloseWrite(); close(done) }()
		for buf := range ch {
			if err := writeAll(stream, buf); err != nil {
				writeError.Store(true)
				warning("write to [%s] failed: %v", name, err)
				return
			}
		}
	}()

	if name == "stdout" {
		if pending := c.takePendingResumeOutput(); len(pending) > 0 {
			if err := writeAll(stream, pending); err != nil {
				warning("write pending resume output failed: %v", err)
				return
			}
		}
	}

	var cacheLines [][]byte
	var tmuxOutputPrefix string
	var discardLines, discardBytes, voidedCapacity int

	cacheOutput := func(buf []byte) {
		for len(buf) > 0 {
			pos := bytes.IndexByte(buf, '\n')

			var line []byte
			if pos >= 0 {
				line = buf[:pos+1]
				buf = buf[pos+1:]
			} else {
				line = buf
				buf = nil
			}

			if len(cacheLines) == 0 {
				cacheLines = append(cacheLines, line)
				continue
			}
			last := cacheLines[len(cacheLines)-1]
			if last[len(last)-1] != '\n' {
				cacheLines[len(cacheLines)-1] = append(last, line...)
				continue
			}
			cacheLines = append(cacheLines, line)
		}

		maxLines := max(maxPendingOutputLines, c.rows*2)
		if len(cacheLines) > maxLines {
			if discardLines == 0 {
				tmuxOutputPrefix = extractTmuxOutputPrefix(cacheLines)
			}

			dropLines := len(cacheLines) - maxLines
			discardLines += dropLines
			for i := range dropLines {
				discardBytes += len(cacheLines[i])
			}
			cacheLines = cacheLines[dropLines:]

			voidedCapacity += dropLines
			if voidedCapacity > maxLines {
				newCacheLines := make([][]byte, len(cacheLines), maxLines*2+10)
				copy(newCacheLines, cacheLines)
				cacheLines = newCacheLines
				voidedCapacity = 0
			}
		}
	}

	// chHasNewLine ensures the client receives a complete line before further output is cached.
	var chHasNewLine bool

	flushOutput := func() {
		filteredCount := 0
		if enableDebugLogging {
			defer func() {
				if filteredCount > 0 {
					debug("filtered %d ESC[6n cursor position request(s)", filteredCount)
				}
			}()
		}
		for i := -1; i < len(cacheLines); i++ {
			var line []byte
			if i < 0 {
				if discardLines == 0 {
					continue
				}
				line = fmt.Appendf(nil,
					"\r\033[0;33mWarning: tsshd discarded %d lines %d bytes of output during client disconnection at this point!\033[0m\033[K\r\n",
					discardLines, discardBytes)
				if len(tmuxOutputPrefix) > 0 {
					line = encodeTmuxOutput(tmuxOutputPrefix, line)
				}
			} else {
				line = cacheLines[i]
				if enableDebugLogging {
					filteredCount += bytes.Count(line, []byte("\x1b[6n"))
				}
				line = bytes.ReplaceAll(line, []byte("\x1b[6n"), []byte(""))
				if len(line) == 0 {
					continue
				}
			}
		out:
			for {
				select {
				case ch <- line:
					if i < 0 {
						debug("discard output %d lines %d bytes", discardLines, discardBytes)
						discardLines, discardBytes = 0, 0
					}
					break out
				case <-resumeCh:
					if name == "stdout" {
						c.appendPendingResumeOutput(line)
						for j := i + 1; j < len(cacheLines); j++ {
							c.appendPendingResumeOutput(cacheLines[j])
						}
					}
					return
				default:
					if globalServerProxy.clientChecker.isTimeout() {
						if i > 0 {
							cacheLines = cacheLines[i:]
						}
						return
					}
					if writeError.Load() {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		}

		cacheLines, chHasNewLine = nil, false
	}

	buffer := make([]byte, 32*1024)
	for {
		// Check for resume signal before blocking read
		select {
		case <-resumeCh:
			return
		default:
		}

		n, err := reader.Read(buffer)

		if n > 0 {
			buf := make([]byte, n)
			copy(buf, buffer[:n])
			if name == "stdout" {
				select {
				case <-resumeCh:
					c.appendPendingResumeOutput(buf)
					return
				default:
				}
			} else {
				select {
				case <-resumeCh:
					return
				default:
				}
			}

			if chHasNewLine && globalServerProxy.clientChecker.isTimeout() && !globalSetting.keepPendingOutput.Load() {
				cacheOutput(buf)
				continue
			}

			if len(cacheLines) > 0 {
				cacheOutput(buf)
				flushOutput()
				continue
			}

			var remaining []byte
			if globalServerProxy.clientChecker.isTimeout() && !globalSetting.keepPendingOutput.Load() {
				if pos := bytes.IndexByte(buf, '\n'); pos >= 0 {
					remaining = buf[pos+1:]
					buf = buf[:pos+1]
					chHasNewLine = true
				}
			}

		out:
			for {
				select {
				case ch <- buf:
					break out
				case <-resumeCh:
					if name == "stdout" {
						c.appendPendingResumeOutput(buf)
					}
					return
				default:
					if globalServerProxy.clientChecker.isTimeout() {
						if globalSetting.keepPendingOutput.Load() {
							if globalServerProxy.clientChecker.waitUntilReconnected() != nil {
								return
							}
							continue
						}
						select {
						case b := <-ch:
							buf = append(b, buf...)
						default:
						}
						pos := bytes.IndexByte(buf, '\n')
						if pos < 0 {
							ch <- buf
							break out
						}

						ch <- buf[:pos+1]
						chHasNewLine = true

						left := buf[pos+1:]
						if len(left) > 0 {
							cacheOutput(left)
						}
						break out
					}
					if writeError.Load() {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}

			if len(remaining) > 0 {
				cacheOutput(remaining)
			}
		}

		if err != nil {
			// If the read error was caused by resume (e.g. SetReadDeadline for
			// non-PTY sessions), save any cached output for the new forwarder
			// instead of trying to flush to the dead stream.
			select {
			case <-resumeCh:
				if name == "stdout" {
					for _, line := range cacheLines {
						c.appendPendingResumeOutput(line)
					}
				}
				return
			default:
			}
			for len(cacheLines) > 0 && !writeError.Load() {
				if globalServerProxy.clientChecker.isTimeout() {
					if globalServerProxy.clientChecker.waitUntilReconnected() != nil {
						break
					}
				}
				flushOutput()
			}
			break
		}
	}
	debug("session [%d] %s completed", c.id, name)
}

func (c *sessionContext) forwardIO(stream Stream) {
	if c.stdin != nil {
		go c.forwardInput(stream)
	}

	if c.stdout != nil {
		c.outWG.Go(func() { c.forwardOutput("stdout", c.stdout, stream) })
	}

	if c.stderr != nil {
		c.outWG.Go(func() {
			if stderr := getStderrStream(c.id); stderr != nil {
				c.forwardOutput("stderr", c.stderr, stderr.stream)
				stderr.Close()
			} else {
				_, _ = io.Copy(io.Discard, c.stderr)
				debug("session [%d] stderr completed", c.id)
			}
		})
	} else if stderr := getStderrStream(c.id); stderr != nil {
		stderr.Close()
		debug("session [%d] stderr closed", c.id)
	}
}

// reattachIO forwards stdin/stdout for a resumed session and waits for completion.
// It reuses the normal I/O forwarding paths to keep behavior consistent.
func (c *sessionContext) reattachIO(stream Stream) {
	// Trigger SIGWINCH to unblock the old stdout forwarder blocking on pty.Read().
	// Retry every second until the new forwarder acquires the stdout token
	// (signaled via redrawDone), meaning the old forwarder has exited.
	c.resumeMu.Lock()
	c.redrawDone = make(chan struct{})
	redrawDone := c.redrawDone
	c.resumeMu.Unlock()

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		c.triggerRedraw()
		for {
			select {
			case <-redrawDone:
				return
			case <-ticker.C:
				c.triggerRedraw()
			}
		}
	}()

	var wg sync.WaitGroup

	if c.stdin != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.forwardInput(stream)
		}()
	}

	if c.stdout != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.forwardOutput("stdout", c.stdout, stream)
		}()
	} else {
		// No stdout — stop redraw ticker immediately.
		c.resumeMu.Lock()
		if c.redrawDone != nil {
			close(c.redrawDone)
			c.redrawDone = nil
		}
		c.resumeMu.Unlock()
	}

	// Re-forward stderr if the session has a separate stderr pipe (non-PTY sessions).
	// PTY sessions merge stderr into stdout, so this only matters for plain commands.
	if c.stderr != nil {
		if stderr := getStderrStream(c.id); stderr != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.forwardOutput("stderr", c.stderr, stderr.stream)
				stderr.Close()
			}()
		}
	}

	wg.Wait()
	debug("session [%d] resume I/O completed", c.id)
}

func (c *sessionContext) Wait() {
	// windows pty only close the stdout in pty.Wait
	if runtime.GOOS == "windows" && c.pty != nil {
		_ = c.pty.Wait()
		c.outWG.Wait()
		debug("session [%d] wait completed", c.id)
		return
	}

	done := make(chan struct{})
	go func() {
		c.outWG.Wait() // wait for the output first to prevent cmd.Wait close output too early
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
	}

	if c.pty != nil {
		_ = c.pty.Wait()
	} else {
		_ = c.cmd.Wait()
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		warning("child process has exited, but output streams did not close in time")
	}

	debug("session [%d] wait completed", c.id)
}

func (c *sessionContext) Close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}

	var code int
	if c.pty != nil {
		code = c.pty.GetExitCode()
	} else {
		code = c.cmd.ProcessState.ExitCode()
	}
	debug("session [%d] exiting with code: %d", c.id, code)

	if err := sendBusMessage("exit", exitMessage{
		ID:       c.id,
		ExitCode: code,
	}); err != nil {
		warning("send exit message failed: %v", err)
	}
	debug("session [%d] exit completed", c.id)

	if c.started {
		if c.pty != nil {
			_ = c.pty.Close()
			debug("session [%d] pty closed", c.id)
		} else {
			_ = c.cmd.Process.Kill()
			debug("session [%d] cmd killed", c.id)
		}
	}
}

func (c *sessionContext) SetSize(cols, rows int, redraw bool) error {
	if c.closed.Load() {
		return nil
	}
	if c.pty == nil {
		return fmt.Errorf("session %d %v is not pty", c.id, c.cmd.Args)
	}
	c.sizeMu.Lock()
	defer c.sizeMu.Unlock()
	if redraw {
		_ = c.pty.Resize(cols+1, rows)
		time.Sleep(10 * time.Millisecond) // fix redraw issue in `screen`
		debug("session [%d] redraw: %d, %d", c.id, cols, rows)
	} else {
		debug("session [%d] resize: %d, %d", c.id, cols, rows)
	}
	if err := c.pty.Resize(cols, rows); err != nil {
		return fmt.Errorf("pty set size failed: %v", err)
	}
	c.cols, c.rows = cols, rows
	return nil
}

func handleSessionEvent(stream Stream) {
	var msg startMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv start message failed: %v", err))
		return
	}

	// Check for existing session to resume before X11/Agent setup.
	// This avoids creating duplicate X11 listeners and agent sockets on resume.
	if ctx := tryResumeSession(msg.ID); ctx != nil {
		// Update terminal size from the reconnecting client.
		if msg.Cols > 0 && msg.Rows > 0 && ctx.pty != nil {
			ctx.sizeMu.Lock()
			ctx.cols = msg.Cols
			ctx.rows = msg.Rows
			_ = ctx.pty.Resize(msg.Cols, msg.Rows)
			ctx.sizeMu.Unlock()
		}

		// Signal old I/O goroutines to stop so we can take over
		ctx.signalResume()

		if err := sendSuccess(stream); err != nil {
			warning("session resume ack ok failed: %v", err)
			return
		}
		// Reattach I/O to the new stream without duplicating forwarding logic.
		ctx.reattachIO(stream)
		// Don't close session - original handler manages lifecycle
		return
	}

	// New session path - set up X11 and Agent before creating the session context,
	// as these modify msg.Envs which is consumed by getSessionStartCmd.
	handleX11Request(&msg)

	handleAgentRequest(&msg)

	ctx, err := createSessionContext(&msg)
	if err != nil {
		sendError(stream, err)
		return
	}
	defer ctx.Close()

	if msg.Pty {
		err = ctx.StartPty()
	} else {
		err = ctx.StartCmd()
	}
	if err != nil {
		sendError(stream, err)
		return
	}

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("session ack ok failed: %v", err)
		return
	}

	if msg.Shell {
		ctx.showMotd(stream)
	}

	ctx.forwardIO(stream)

	ctx.Wait()
}

// tryResumeSession returns an existing started session for the given ID, or nil.
func tryResumeSession(id uint64) *sessionContext {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if ctx, ok := sessionMap[id]; ok && ctx.started {
		debug("resuming existing session %d", id)
		return ctx
	}
	return nil
}

// createSessionContext creates a new session context. Returns an error if the
// session ID already exists (whether started or not), preventing races between
// session creation and the started flag being set.
func createSessionContext(msg *startMessage) (*sessionContext, error) {
	cmd, err := getSessionStartCmd(msg)
	if err != nil {
		return nil, fmt.Errorf("build start command failed: %v", err)
	}

	sessionMu.Lock()
	defer sessionMu.Unlock()

	if _, ok := sessionMap[msg.ID]; ok {
		return nil, fmt.Errorf("session id %d already exists", msg.ID)
	}

	ctx := &sessionContext{
		id:                 msg.ID,
		cmd:                cmd,
		cols:               msg.Cols,
		rows:               msg.Rows,
		lastDiscardGen:     discardGeneration.Load(),
		resumeChan:         make(chan struct{}),
		stdoutForwardToken: make(chan struct{}, 1),
	}
	sessionMap[ctx.id] = ctx
	return ctx, nil
}

func (c *stderrStream) Wait() {
	c.wg.Wait()
}

func (c *stderrStream) Close() {
	c.wg.Done()
	stderrMu.Lock()
	defer stderrMu.Unlock()
	delete(stderrMap, c.id)
}

func newStderrStream(id uint64, stream Stream) (*stderrStream, error) {
	stderrMu.Lock()
	defer stderrMu.Unlock()
	if _, ok := stderrMap[id]; ok {
		return nil, fmt.Errorf("session %d stderr already set", id)
	}
	errStream := &stderrStream{id: id, stream: stream}
	errStream.wg.Add(1)
	stderrMap[id] = errStream
	return errStream, nil
}

func getStderrStream(id uint64) *stderrStream {
	stderrMu.Lock()
	defer stderrMu.Unlock()
	if errStream, ok := stderrMap[id]; ok {
		return errStream
	}
	return nil
}

func getSessionStartCmd(msg *startMessage) (*exec.Cmd, error) {
	if msg.Subs != "" {
		return getSubsystemCmd(msg.Subs)
	}

	var envs []string
	for _, env := range os.Environ() {
		pos := strings.IndexRune(env, '=')
		if pos <= 0 {
			continue
		}
		name := strings.TrimSpace(env[:pos])
		if _, ok := msg.Envs[name]; !ok {
			envs = append(envs, env)
		}
	}
	for key, value := range msg.Envs {
		envs = append(envs, fmt.Sprintf("%s=%s", key, value))
	}

	if !msg.Shell {
		name := msg.Name
		args := msg.Args
		wrap := false
		if name == "cd" {
			wrap = true
		} else if _, err := exec.LookPath(name); err != nil {
			wrap = true
		} else {
			for _, arg := range args {
				if strings.HasPrefix(arg, "~/") {
					wrap = true
					break
				}
			}
		}
		if wrap {
			re := regexp.MustCompile(`\s`)
			var buf strings.Builder
			buf.WriteString(name)
			for _, arg := range args {
				buf.WriteByte(' ')
				if re.MatchString(arg) {
					buf.WriteString(shellescape.Quote(arg))
				} else {
					buf.WriteString(arg)
				}
			}
			if runtime.GOOS == "windows" {
				name = "cmd"
				args = []string{"/c", buf.String()}
			} else {
				name = "sh"
				args = []string{"-c", buf.String()}
			}
		}
		cmd := exec.Command(name, args...)
		cmd.Env = envs
		return cmd, nil
	}

	shell, err := getUserShell()
	if err != nil {
		return nil, fmt.Errorf("get user shell failed: %v", err)
	}
	cmd := exec.Command(shell)
	if runtime.GOOS != "windows" {
		cmd.Args = []string{"-" + filepath.Base(shell)}
	}
	cmd.Env = envs
	return cmd, nil
}

func getSubsystemCmd(name string) (*exec.Cmd, error) {
	command := getSshdSubsystem(name)
	if command == "" {
		return nil, fmt.Errorf("subsystem [%s] does not exist in [%s]", name, sshdConfigPath)
	}
	args, err := splitCommandLine(command)
	if err != nil {
		return nil, fmt.Errorf("split subsystem [%s] [%s] failed: %v", name, command, err)
	}
	return exec.Command(args[0], args[1:]...), nil
}

func handleStderrEvent(stream Stream) {
	var msg stderrMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv stderr message failed: %v", err))
		return
	}

	errStream, err := newStderrStream(msg.ID, stream)
	if err != nil {
		sendError(stream, err)
		return
	}

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("stderr ack ok failed: %v", err)
		return
	}

	errStream.Wait()
}

func handleResizeEvent(stream Stream) error {
	var msg resizeMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv resize message failed: %v", err)
	}
	if msg.Cols <= 0 || msg.Rows <= 0 {
		return fmt.Errorf("resize message invalid: %#v", msg)
	}
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if ctx, ok := sessionMap[msg.ID]; ok {
		return ctx.SetSize(msg.Cols, msg.Rows, msg.Redraw)
	}
	return fmt.Errorf("invalid session id: %d", msg.ID)
}

func handleX11Request(msg *startMessage) {
	if msg.X11 == nil {
		return
	}

	if v := strings.ToLower(getSshdConfig("X11Forwarding")); v != "yes" {
		warning("X11Forwarding is not permitted on the server. Check [X11Forwarding] in [%s] on the server.", sshdConfigPath)
		return
	}
	if v := strings.ToLower(getSshdConfig("DisableForwarding")); v == "yes" {
		warning("X11Forwarding is not permitted on the server. Check [DisableForwarding] in [%s] on the server.", sshdConfigPath)
		return
	}

	displayOffset := 10
	if offset := getSshdConfig("X11DisplayOffset"); offset != "" {
		if off, err := strconv.ParseUint(offset, 10, 32); err == nil && off < (65535-6000-1000) {
			displayOffset = int(off)
		}
	}

	useLocalhost := strings.ToLower(getSshdConfig("X11UseLocalhost")) != "no"
	listeners, port, err := listenTcpOnFreePort(useLocalhost, 6000+displayOffset, min(6000+displayOffset+1000, 65535))
	if err != nil {
		warning("X11 forwarding listen failed: %v", err)
		return
	}
	addOnExitFunc(func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	})

	hostname := getHostnameForX11(useLocalhost)
	displayNumber := port - 6000
	display := fmt.Sprintf("%s:%d.%d", hostname, displayNumber, msg.X11.ScreenNumber)
	authDisplay := display
	if useLocalhost {
		authDisplay = fmt.Sprintf("unix:%d.%d", displayNumber, msg.X11.ScreenNumber)
	}

	xauthPath := getXauthPath()
	xauthInput := fmt.Sprintf("remove %s\nadd %s %s %s\n", authDisplay, authDisplay, msg.X11.AuthProtocol, msg.X11.AuthCookie)
	if err := writeXauthData(xauthPath, xauthInput); err != nil {
		warning("write xauth data failed: %v", err)
	}
	addOnExitFunc(func() {
		_ = writeXauthData(xauthPath, fmt.Sprintf("remove %s\n", authDisplay))
	})

	for _, listener := range listeners {
		go handleChannelAccept(listener, msg.X11.ChannelType)
	}

	if msg.Envs == nil {
		msg.Envs = make(map[string]string)
	}
	msg.Envs["DISPLAY"] = display
}

func getHostnameForX11(useLocalhost bool) string {
	if useLocalhost {
		return "localhost"
	}

	hostname, err := os.Hostname()
	if err != nil {
		warning("get hostname for X11 forwarding failed: %v", err)
		return "localhost"
	}
	return hostname
}

func listenTcpOnFreePort(useLocalhost bool, low, high int) ([]net.Listener, int, error) {
	var ipv4Host, ipv6Host string
	if useLocalhost {
		ipv4Host, ipv6Host = "127.0.0.1", "::1"
	} else {
		ipv4Host, ipv6Host = "0.0.0.0", "::"
	}

	var netList, hostList []string
	listener4, err4 := net.Listen("tcp4", net.JoinHostPort(ipv4Host, "0"))
	if err4 == nil {
		_ = listener4.Close()
		netList = append(netList, "tcp4")
		hostList = append(hostList, ipv4Host)
	}
	listener6, err6 := net.Listen("tcp6", net.JoinHostPort(ipv6Host, "0"))
	if err6 == nil {
		_ = listener6.Close()
		netList = append(netList, "tcp6")
		hostList = append(hostList, ipv6Host)
	}

	if err4 != nil && err6 != nil {
		return nil, 0, fmt.Errorf("ipv4 and ipv6 both listen failed: %v, %v", err4, err6)
	}

	var lastErr error
	for port := low; port <= high; port++ {
		var listenerList []net.Listener
		portStr := strconv.Itoa(port)
		for i := range len(netList) {
			listener, err := net.Listen(netList[i], net.JoinHostPort(hostList[i], portStr))
			if err != nil {
				lastErr = err
				continue
			}
			listenerList = append(listenerList, listener)
		}
		if len(listenerList) == len(netList) {
			return listenerList, port, nil
		}
		for _, listener := range listenerList {
			_ = listener.Close()
		}
	}
	if lastErr != nil {
		return nil, 0, fmt.Errorf("listen tcp on [%s,%s][%d,%d] failed: %v", ipv4Host, ipv6Host, low, high, lastErr)
	}
	return nil, 0, fmt.Errorf("listen tcp on [%s,%s][%d,%d] failed", ipv4Host, ipv6Host, low, high)
}

func getXauthPath() string {
	xauthPath := getSshdConfig("XAuthLocation")
	if xauthPath != "" {
		if _, err := os.Stat(xauthPath); err != nil {
			warning("XAuthLocation [%s] not found: %v", xauthPath, err)
			return "xauth"
		}
		return xauthPath
	}

	return "xauth"
}

func writeXauthData(xauthPath, xauthInput string) error {
	cmd := exec.Command(xauthPath, "-q", "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe failed: %v", err)
	}
	defer func() { _ = stdin.Close() }()

	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("xauth start failed: %v", err)
	}

	if _, err := stdin.Write([]byte(xauthInput)); err != nil {
		return fmt.Errorf("stdin write failed: %v", err)
	}
	_ = stdin.Close()

	_, err = doWithTimeout(func() (int, error) {
		if err := cmd.Wait(); err != nil {
			if errBuf.Len() > 0 {
				return 0, fmt.Errorf("%s", strings.TrimSpace(errBuf.String()))
			}
			return 0, fmt.Errorf("xauth wait failed: %v", err)
		}
		return 0, nil
	}, 1000*time.Millisecond)
	return err
}

func handleAgentRequest(msg *startMessage) {
	if msg.Agent == nil {
		return
	}

	if v := strings.ToLower(getSshdConfig("AllowAgentForwarding")); v == "no" {
		warning("AgentForwarding is not permitted on the server. Check [AllowAgentForwarding] in [%s] on the server.", sshdConfigPath)
		return
	}
	if v := strings.ToLower(getSshdConfig("DisableForwarding")); v == "yes" {
		warning("AgentForwarding is not permitted on the server. Check [DisableForwarding] in [%s] on the server.", sshdConfigPath)
		return
	}

	listener, agentPath, err := listenForAgent()
	if err != nil {
		warning("listen for agent forwarding failed: %v", err)
		return
	}

	go handleChannelAccept(listener, msg.Agent.ChannelType)

	if msg.Envs == nil {
		msg.Envs = make(map[string]string)
	}
	msg.Envs["SSH_AUTH_SOCK"] = agentPath
}

func handleChannelAccept(listener net.Listener, channelType string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedError(err) {
				debug("listen channel closed: %v", err)
				break
			}
			warning("listen channel accept failed: %v", err)
			break
		}
		go func(conn net.Conn) {
			id := addAcceptConn(conn)
			if err := sendBusMessage("channel", &channelMessage{ChannelType: channelType, ID: id}); err != nil {
				warning("send channel message failed: %v", err)
			}
		}(conn)
	}
}

func closeSession(id uint64) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if ctx, ok := sessionMap[id]; ok {
		debug("closing the session [%d]", id)
		ctx.Close()
		delete(sessionMap, id)
	}
}

func closeAllSessions() {
	sessionMu.Lock()
	var sessions []*sessionContext
	for _, session := range sessionMap {
		sessions = append(sessions, session)
	}
	sessionMap = make(map[uint64]*sessionContext)
	sessionMu.Unlock()

	debug("closing all the sessions")
	for _, session := range sessions {
		session.Close()
	}
}
