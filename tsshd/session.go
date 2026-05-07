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

	"github.com/google/shlex"
	"github.com/trzsz/shellescape"
)

var maxSessionID atomic.Uint64
var maxPendingOutputLines = 1000

var discardMarkerCurrentIndex uint32
var discardMarkerIndexMutex sync.Mutex

func (s *sshUdpServer) enablePendingInputDiscard() {
	if s.keepPendingInput.Load() {
		return
	}

	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	if len(sessionMap) == 0 {
		// No need to register and send the marker if there are no active sessions.
		// Otherwise, concurrent session creation by the client might lead to garbled input.
		return
	}

	idx := getNextDiscardMarkerIndex()
	marker := []byte{0xFF, 0xC0, 0xC1, 0xFF,
		byte(idx >> 24), byte(idx >> 16), byte(idx >> 8), byte(idx),
	}

	for _, sess := range sessionMap {
		sess.discardMarker.Store(&marker)
	}

	go func() {
		debug("discard marker: %X", marker)
		if err := s.sendBusMessage("discard", discardMessage{DiscardMarker: marker}); err != nil {
			warning("send discard marker [%X] failed: %v", marker, err)
		}
	}()
}

func getNextDiscardMarkerIndex() uint32 {
	discardMarkerIndexMutex.Lock()
	defer discardMarkerIndexMutex.Unlock()

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
	id              uint64
	cols            int
	rows            int
	cmd             *exec.Cmd
	pty             *tsshdPty
	mwSess          *middlewareSession
	outWG           sync.WaitGroup
	stdin           io.WriteCloser
	stdout          io.ReadCloser
	stderr          io.ReadCloser
	started         bool
	closed          atomic.Bool
	waitDone        chan struct{}
	waitCancel      chan struct{}
	waitMutex       sync.Mutex
	resizeMutex     sync.Mutex
	server          atomic.Pointer[sshUdpServer]
	ioStream        *replaceableStream
	errStream       *replaceableStream
	clientChecker   *replaceableTimeoutChecker
	discardedBuffer []byte
	discardMarker   atomic.Pointer[[]byte]
}

var sessionMutex sync.Mutex
var sessionMap map[uint64]*sessionContext

func (c *sessionContext) StartMiddleware() error {
	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	c.stdin, c.stdout, c.stderr = stdinWriter, stdoutReader, stderrReader
	c.mwSess.stdin, c.mwSess.stdout, c.mwSess.stderr = stdinReader, stdoutWriter, stderrWriter

	if sessionHandler == nil {
		return fmt.Errorf("no session handler")
	}

	go func() {
		sessionHandler(c.mwSess)
		_ = c.mwSess.Exit(0)
	}()

	c.started = true
	debug("session [%d] start middleware success", c.id)

	return nil
}

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

func (c *sessionContext) discardPendingInput(server *sshUdpServer, buf []byte, marker *[]byte) error {
	c.discardedBuffer = append(c.discardedBuffer, buf...)
	pos := bytes.Index(c.discardedBuffer, *marker)
	if pos < 0 {
		return nil
	}

	remainingBuffer := c.discardedBuffer[pos+len(*marker):]
	if len(remainingBuffer) > 0 {
		if err := writeAll(c.stdin, remainingBuffer); err != nil {
			return err
		}
	}

	if pos > 0 {
		if enableDebugLogging {
			debug("discard input: %s", strconv.QuoteToASCII(string(c.discardedBuffer[:pos])))
		}
		if err := server.sendBusMessage("discard", discardMessage{DiscardedInput: c.discardedBuffer[:pos]}); err != nil {
			warning("send discard message failed: %v", err)
		}
	} else if enableDebugLogging {
		debug("no pending input to discard")
	}

	c.discardedBuffer = nil
	c.discardMarker.CompareAndSwap(marker, nil)
	return nil
}

func (c *sessionContext) forwardInput(stream Stream) {
	defer func() {
		debug("session [%d] stdin completed", c.id)
		_ = c.stdin.Close()
		_ = stream.CloseRead()
	}()

	buffer := make([]byte, 32*1024)
	for {
		n, err := stream.Read(buffer)
		if n > 0 {
			server := c.server.Load()
			if server == nil {
				// nil indicates the session has been detached, input from the old client should be discarded.
				continue
			}

			if marker := c.discardMarker.Load(); marker != nil {
				if err := c.discardPendingInput(server, buffer[:n], marker); err != nil {
					return
				}
				continue
			}

			if err := writeAll(c.stdin, buffer[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (c *sessionContext) isKeepPendingOutput() bool {
	if server := c.server.Load(); server != nil {
		return server.keepPendingOutput.Load()
	}
	return false
}

func (c *sessionContext) forwardOutput(name string, reader io.Reader, stream Stream) {
	var returned bool
	var handleMutex sync.Mutex
	var writeError atomic.Bool
	done := make(chan struct{})
	ch := make(chan []byte, 1)

	defer func() {
		handleMutex.Lock()
		returned = true
		close(ch)
		handleMutex.Unlock()

		<-done
	}()

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

	var cacheLines [][]byte
	var tmuxOutputPrefix string
	var discardLines, discardBytes, voidedCapacity int

	cacheOutput := func(buf []byte) {
		for len(buf) > 0 {
			pos := bytes.IndexByte(buf, '\n')
			if pos < 0 {
				pos = bytes.IndexByte(buf, '\r')
			}

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
			if b := last[len(last)-1]; b != '\n' && (b != '\r' || line[0] == '\n') && len(last) < 1000 {
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

	// noNewLineCount records consecutive reads that contain no '\n'.
	// After 3 consecutive reads without newline, output will start being cached.
	// This helps handle cases where some programs may output progress bars or status
	// lines by repeatedly using carriage return ('\r') without emitting newline characters.
	var noNewLineCount int

	flushOutput := func() {
		if len(cacheLines) == 0 || c.clientChecker.isTimeout() {
			return
		}

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
				newline := "\r\n"
				if len(cacheLines) > 0 && len(cacheLines[0]) > 0 && cacheLines[0][len(cacheLines[0])-1] == '\r' {
					newline = "\r"
				}
				line = fmt.Appendf(nil,
					"\r\033[0;33mWarning: tsshd discarded %d lines %d bytes of output during client disconnection at this point!\033[0m\033[K%s",
					discardLines, discardBytes, newline)
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
				default:
					if c.clientChecker.isTimeout() {
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

		cacheLines, chHasNewLine, noNewLineCount = nil, false, 0
	}

	c.clientChecker.onReconnected(func() {
		handleMutex.Lock()
		defer handleMutex.Unlock()

		if returned {
			return // do not flush after forwardoutput has returned
		}

		flushOutput()
	})

	handleBuffer := func(buf []byte) {
		handleMutex.Lock()
		defer handleMutex.Unlock()

		if chHasNewLine && c.clientChecker.isTimeout() && !c.isKeepPendingOutput() {
			cacheOutput(buf)
			return
		}

		if len(cacheLines) > 0 {
			cacheOutput(buf)
			flushOutput()
			return
		}

		var remaining []byte
		if c.clientChecker.isTimeout() && !c.isKeepPendingOutput() {
			pos := bytes.IndexByte(buf, '\n')
			if pos >= 0 {
				remaining = buf[pos+1:]
				buf = buf[:pos+1]
				chHasNewLine = true
			} else {
				if noNewLineCount < 3 {
					noNewLineCount++
				} else {
					chHasNewLine = true
					cacheOutput(buf)
					return
				}
			}
		}

	out:
		for {
			select {
			case ch <- buf:
				break out
			default:
				if c.clientChecker.isTimeout() {
					if c.isKeepPendingOutput() {
						if c.clientChecker.waitUntilReconnected() != nil {
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
					if pos < 0 && noNewLineCount < 3 {
						ch <- buf
						noNewLineCount++
						break out
					}

					if pos < 0 {
						ch <- buf
					} else {
						ch <- buf[:pos+1]
						left := buf[pos+1:]
						if len(left) > 0 {
							cacheOutput(left)
						}
					}

					chHasNewLine = true
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

	handleError := func() {
		handleMutex.Lock()
		defer handleMutex.Unlock()

		for len(cacheLines) > 0 && !writeError.Load() {
			if c.clientChecker.isTimeout() {
				if c.clientChecker.waitUntilReconnected() != nil {
					break
				}
			}
			flushOutput()
		}
	}

	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			buf := make([]byte, n)
			copy(buf, buffer[:n])
			handleBuffer(buf)
		}
		if err != nil {
			handleError()
			break
		}
	}

	debug("session [%d] %s completed", c.id, name)
}

func (c *sessionContext) forwardIO(server *sshUdpServer, stream Stream) {
	ioStream := stream
	if server.args.Attachable {
		c.ioStream = newReplaceableStream(ioStream)
		ioStream = c.ioStream
	}

	if c.stdin != nil {
		go c.forwardInput(ioStream)
	}

	if c.stdout != nil {
		c.outWG.Go(func() { c.forwardOutput("stdout", c.stdout, ioStream) })
	}

	var errStream Stream
	if s := server.getStderrStream(c.id); s != nil {
		errStream = s
	} else {
		errStream = &discardStream{}
	}
	if server.args.Attachable {
		c.errStream = newReplaceableStream(errStream)
		errStream = c.errStream
	}

	if c.stderr != nil {
		c.outWG.Go(func() {
			c.forwardOutput("stderr", c.stderr, errStream)
			_ = errStream.Close()
		})
	} else {
		_ = errStream.Close()
		debug("session [%d] stderr closed", c.id)
	}
}

func (c *sessionContext) Wait() {
	// windows pty only close the stdout in pty.Wait
	if runtime.GOOS == "windows" && c.mwSess == nil && c.pty != nil {
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

	if c.mwSess != nil {
		_ = c.mwSess.Wait()
	} else if c.pty != nil {
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

	code := -1
	if c.mwSess != nil {
		if exitCode := c.mwSess.exitCode.Load(); exitCode != nil {
			code = *exitCode
		}
	} else if c.pty != nil {
		code = c.pty.GetExitCode()
	} else {
		code = c.cmd.ProcessState.ExitCode()
	}
	debug("session [%d] exiting with code: %d", c.id, code)

	if server := c.server.Load(); server != nil {
		if err := server.sendBusMessage("exit", exitMessage{c.id, code}); err != nil {
			warning("send exit message failed: %v", err)
		}
	}
	debug("session [%d] exit completed", c.id)

	if c.started {
		if c.mwSess != nil {
			_ = c.mwSess.Close()
			debug("session [%d] middleware closed", c.id)
		} else if c.pty != nil {
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

	var resize func(cols, rows int) error
	if c.mwSess != nil {
		if c.mwSess.pty {
			resize = c.mwSess.Resize
		}
	} else if c.pty != nil {
		resize = c.pty.Resize
	}
	if resize == nil {
		return fmt.Errorf("session %d is not pty", c.id)
	}

	c.resizeMutex.Lock()
	defer c.resizeMutex.Unlock()

	if redraw {
		if err := resize(cols+1, rows); err != nil {
			warning("redraw pty failed: %v", err)
		}
		time.Sleep(10 * time.Millisecond) // fix redraw issue in `screen`
		debug("session [%d] redraw: %d, %d", c.id, cols, rows)
	} else {
		debug("session [%d] resize: %d, %d", c.id, cols, rows)
	}

	if err := resize(cols, rows); err != nil {
		return fmt.Errorf("resize pty failed: %v", err)
	}

	c.cols, c.rows = cols, rows
	return nil
}

func (c *sessionContext) cancellableWait() {
	newCancel := make(chan struct{})

	c.waitMutex.Lock()
	if cancel := c.waitCancel; cancel != nil {
		close(cancel)
	}
	c.waitCancel = newCancel
	c.waitMutex.Unlock()

	select {
	case <-newCancel:
		return
	case <-c.waitDone:
		return
	}
}

func (s *sshUdpServer) handleSessionEvent(stream Stream) {
	if enableDebugLogging {
		debug("session goroutine for client [%x] started", s.client.proxyAddr.clientID)
		defer debug("session goroutine for client [%x] returned", s.client.proxyAddr.clientID)
	}

	var msg startMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv start message failed: %v", err))
		return
	}

	if msg.Attach {
		sess, err := s.attachSession(stream, &msg)
		if err != nil {
			sendError(stream, fmt.Errorf("attach to session [%d] failed: %v", msg.ID, err))
			return
		}

		sess.cancellableWait()
		return
	}

	sess, err := newSessionContext(s, &msg)
	if err != nil {
		sendError(stream, err)
		return
	}

	sess.handleX11Request(&msg)

	sess.handleAgentRequest(&msg)

	if sess.mwSess != nil {
		err = sess.StartMiddleware()
	} else if msg.Pty {
		err = sess.StartPty()
	} else {
		err = sess.StartCmd()
	}
	if err != nil {
		sendError(stream, err)
		sess.Close()
		return
	}

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("start session ack ok failed: %v", err)
		sess.Close()
		return
	}

	if sess.mwSess == nil && msg.Shell {
		sess.showMotd(stream)
	}

	sess.forwardIO(s, stream)

	if s.args.Attachable {
		// Each session is started only once since duplicate session IDs are rejected,
		// ensuring this block executes a single time without concurrency.
		sess.waitDone = make(chan struct{})
		go func() {
			sess.Wait()
			sess.Close()
			close(sess.waitDone)
		}()
		sess.cancellableWait()
		return
	}

	sess.Wait()
	sess.Close()
}

func newSessionContext(server *sshUdpServer, msg *startMessage) (*sessionContext, error) {
	var cmd *exec.Cmd
	var mwSess *middlewareSession
	if sessionHandler != nil {
		mwSess = newMiddlewareSession(msg)
	} else {
		var err error
		cmd, err = getSessionStartCmd(msg)
		if err != nil {
			return nil, fmt.Errorf("build start command failed: %v", err)
		}
	}

	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	if _, ok := sessionMap[msg.ID]; ok {
		return nil, fmt.Errorf("session id %d existed", msg.ID)
	}

	if msg.ID > maxSessionID.Load() {
		maxSessionID.Store(msg.ID)
	}

	sess := &sessionContext{
		id:            msg.ID,
		cmd:           cmd,
		mwSess:        mwSess,
		cols:          msg.Cols,
		rows:          msg.Rows,
		clientChecker: newReplaceableTimeoutChecker(server.clientChecker),
	}
	sess.server.Store(server)

	if sessionMap == nil {
		sessionMap = make(map[uint64]*sessionContext)
	}
	sessionMap[sess.id] = sess
	return sess, nil
}

type stderrStream struct {
	Stream
	id     uint64
	wg     sync.WaitGroup
	server *sshUdpServer
	closed atomic.Bool
}

func (c *stderrStream) Wait() {
	c.wg.Wait()
}

func (c *stderrStream) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	c.wg.Done()

	c.server.stderrMutex.Lock()
	delete(c.server.stderrMap, c.id)
	c.server.stderrMutex.Unlock()

	return c.Stream.Close()
}

func (s *sshUdpServer) newStderrStream(id uint64, stream Stream) (*stderrStream, error) {
	s.stderrMutex.Lock()
	defer s.stderrMutex.Unlock()

	if _, ok := s.stderrMap[id]; ok {
		return nil, fmt.Errorf("session %d stderr already set", id)
	}

	errStream := &stderrStream{server: s, id: id, Stream: stream}
	errStream.wg.Add(1)

	if s.stderrMap == nil {
		s.stderrMap = make(map[uint64]*stderrStream)
	}
	s.stderrMap[id] = errStream

	return errStream, nil
}

func (s *sshUdpServer) getStderrStream(id uint64) *stderrStream {
	s.stderrMutex.Lock()
	defer s.stderrMutex.Unlock()

	if errStream, ok := s.stderrMap[id]; ok {
		return errStream
	}

	return nil
}

func getSessionStartCmd(msg *startMessage) (*exec.Cmd, error) {
	if msg.Subs != "" {
		return getSubsystemCmd(msg.Subs)
	}

	envs := getEnvironments(msg)

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

func getEnvironments(msg *startMessage) []string {
	var envs []string

	var acceptEnvExpr string
	acceptEnv := getSshdConfig("AcceptEnv")
	if acceptEnv != "" {
		patterns, err := shlex.Split(acceptEnv)
		if err != nil {
			warning("split AcceptEnv [%s] failed: %v", acceptEnv, err)
		} else {
			var buf strings.Builder
			for _, pattern := range patterns {
				if buf.Len() > 0 {
					buf.WriteByte('|')
				}
				buf.WriteByte('(')
				buf.WriteString(wildcardToRegexp(pattern))
				buf.WriteByte(')')
			}
			acceptEnvExpr = buf.String()
			debug("accept env regexp: %s", acceptEnvExpr)
		}
	}

	var acceptEnvRegexp *regexp.Regexp
	if acceptEnvExpr != "" {
		var err error
		acceptEnvRegexp, err = regexp.Compile(acceptEnvExpr)
		if err != nil {
			warning("compile AcceptEnv [%s] regexp [%s] failed: %v", acceptEnv, acceptEnvExpr, err)
		}
	}

	acceptMap := make(map[string]struct{})
	for name, value := range msg.Envs {
		if name == "TERM" { // always allow TERM from pty-req
			acceptMap[name] = struct{}{}
			envs = append(envs, fmt.Sprintf("%s=%s", name, value))
			continue
		}
		if acceptEnvRegexp == nil || !acceptEnvRegexp.MatchString(name) {
			debug("ignore env: %s=%s", name, value)
			continue
		}
		debug("accept env: %s=%s", name, value)
		acceptMap[name] = struct{}{}
		envs = append(envs, fmt.Sprintf("%s=%s", name, value))
	}

	for _, env := range os.Environ() {
		pos := strings.IndexRune(env, '=')
		if pos <= 0 {
			continue
		}
		name := strings.TrimSpace(env[:pos])
		if name == kEnvTsshdBackground {
			continue
		}
		if _, ok := acceptMap[name]; !ok {
			envs = append(envs, env)
		}
	}

	return envs
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
	if len(args) == 0 || args[0] == "" {
		return nil, fmt.Errorf("subsystem [%s] command is empty in [%s]", name, sshdConfigPath)
	}
	return exec.Command(args[0], args[1:]...), nil
}

func (s *sshUdpServer) handleStderrEvent(stream Stream) {
	if enableDebugLogging {
		debug("stderr goroutine for client [%x] started", s.client.proxyAddr.clientID)
		defer debug("stderr goroutine for client [%x] returned", s.client.proxyAddr.clientID)
	}

	var msg stderrMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv stderr message failed: %v", err))
		return
	}

	errStream, err := s.newStderrStream(msg.ID, stream)
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

func (s *sshUdpServer) handleResizeEvent(stream Stream) error {
	var msg resizeMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv resize message failed: %v", err)
	}
	if msg.Cols <= 0 || msg.Rows <= 0 {
		return fmt.Errorf("resize message invalid: %#v", msg)
	}
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if sess, ok := sessionMap[msg.ID]; ok {
		return sess.SetSize(msg.Cols, msg.Rows, msg.Redraw)
	}
	return fmt.Errorf("invalid session id: %d", msg.ID)
}

func (c *sessionContext) handleX11Request(msg *startMessage) {
	if msg.X11 == nil {
		return
	}

	if !enableForwardings {
		warning("X11 forwarding is not enabled on the server")
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
		if err := writeXauthData(xauthPath, fmt.Sprintf("remove %s\n", authDisplay)); err != nil {
			warning("remove xauth data failed: %v", err)
		}
	})

	for _, listener := range listeners {
		go c.handleChannelAccept(listener, msg.X11.ChannelType)
	}

	env := fmt.Sprintf("DISPLAY=%s", display)
	if c.mwSess != nil {
		c.mwSess.envs = append(c.mwSess.envs, env)
	} else {
		c.cmd.Env = append(c.cmd.Env, env)
	}
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

func (c *sessionContext) handleAgentRequest(msg *startMessage) {
	if msg.Agent == nil {
		return
	}

	if !enableForwardings {
		warning("agent forwarding is not enabled on the server")
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

	go c.handleChannelAccept(listener, msg.Agent.ChannelType)

	env := fmt.Sprintf("SSH_AUTH_SOCK=%s", agentPath)
	if c.mwSess != nil {
		c.mwSess.envs = append(c.mwSess.envs, env)
	} else {
		c.cmd.Env = append(c.cmd.Env, env)
	}
}

func (c *sessionContext) handleChannelAccept(listener net.Listener, channelType string) {
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
			server := c.server.Load()
			if server == nil {
				_ = conn.Close()
				return
			}
			id := server.addAcceptConn(conn)
			if err := server.sendBusMessage("channel", &channelMessage{ChannelType: channelType, ID: id}); err != nil {
				warning("send channel message failed: %v", err)
			}
		}(conn)
	}
}

func closeSession(id uint64) {
	sessionMutex.Lock()

	sess, ok := sessionMap[id]
	if !ok {
		sessionMutex.Unlock()
		return
	}

	delete(sessionMap, id)
	sessionMutex.Unlock()

	debug("closing the session [%d]", id)
	sess.Close()
}

func closeAllSessions() {
	sessionMutex.Lock()
	var sessions []*sessionContext
	for _, session := range sessionMap {
		sessions = append(sessions, session)
	}
	sessionMap = nil
	sessionMutex.Unlock()

	debug("closing all the sessions")
	for _, session := range sessions {
		session.Close()
	}
}
