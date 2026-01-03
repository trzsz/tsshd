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

var discardPendingInputFlag atomic.Bool
var discardPendingInputMarker []byte
var discardMarkerCurrentIndex uint32
var discardMarkerIndexMutex sync.Mutex

func enablePendingInputDiscard() {
	if globalSetting.keepPendingInput.Load() {
		return
	}

	idx := getNextDiscardMarkerIndex()
	discardPendingInputMarker = []byte{0xFF, 0xC0, 0xC1, 0xFF,
		byte(idx >> 24), byte(idx >> 16), byte(idx >> 8), byte(idx),
	}
	discardPendingInputFlag.Store(true)

	go func() {
		debug("discard marker: %X", discardPendingInputMarker)
		_ = sendBusMessage("discard", discardMessage{DiscardMarker: discardPendingInputMarker})
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
	id      uint64
	cols    int
	rows    int
	cmd     *exec.Cmd
	pty     *tsshdPty
	wg      sync.WaitGroup
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	started bool
	closed  atomic.Bool

	discardedBuffer []byte
}

type stderrStream struct {
	id     uint64
	wg     sync.WaitGroup
	stream Stream
}

var sessionMutex sync.Mutex
var sessionMap = make(map[uint64]*sessionContext)

var stderrMutex sync.Mutex
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
	pos := bytes.Index(c.discardedBuffer, discardPendingInputMarker)
	if pos < 0 {
		return nil
	}

	remainingBuffer := c.discardedBuffer[pos+len(discardPendingInputMarker):]
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

	discardPendingInputFlag.Store(false)
	debug("new transport path is now active")
	return nil
}

func (c *sessionContext) forwardInput(stream Stream) {
	defer func() {
		_ = c.stdin.Close()
		_ = stream.CloseRead()
	}()
	buffer := make([]byte, 32*1024)
	for {
		n, err := stream.Read(buffer)
		if n > 0 {
			if discardPendingInputFlag.Load() {
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
		n, err := reader.Read(buffer)
		if n > 0 {
			buf := make([]byte, n)
			copy(buf, buffer[:n])

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
		c.wg.Go(func() { c.forwardOutput("stdout", c.stdout, stream) })
	}

	if c.stderr != nil {
		c.wg.Go(func() {
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

func (c *sessionContext) Wait() {
	// windows pty only close the stdout in pty.Wait
	if runtime.GOOS == "windows" && c.pty != nil {
		_ = c.pty.Wait()
		c.wg.Wait()
		debug("session [%d] wait completed", c.id)
		return
	}

	c.wg.Wait() // wait for the output done first to prevent cmd.Wait close output too early
	if c.pty != nil {
		_ = c.pty.Wait()
	} else {
		_ = c.cmd.Wait()
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

	handleX11Request(&msg)

	handleAgentRequest(&msg)

	ctx, err := newSessionContext(&msg)
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

func newSessionContext(msg *startMessage) (*sessionContext, error) {
	cmd, err := getSessionStartCmd(msg)
	if err != nil {
		return nil, fmt.Errorf("build start command failed: %v", err)
	}

	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	if ctx, ok := sessionMap[msg.ID]; ok {
		return nil, fmt.Errorf("session id %d %v existed", msg.ID, ctx.cmd.Args)
	}

	ctx := &sessionContext{
		id:   msg.ID,
		cmd:  cmd,
		cols: msg.Cols,
		rows: msg.Rows,
	}
	sessionMap[ctx.id] = ctx
	return ctx, nil
}

func (c *stderrStream) Wait() {
	c.wg.Wait()
}

func (c *stderrStream) Close() {
	c.wg.Done()
	stderrMutex.Lock()
	defer stderrMutex.Unlock()
	delete(stderrMap, c.id)
}

func newStderrStream(id uint64, stream Stream) (*stderrStream, error) {
	stderrMutex.Lock()
	defer stderrMutex.Unlock()
	if _, ok := stderrMap[id]; ok {
		return nil, fmt.Errorf("session %d stderr already set", id)
	}
	errStream := &stderrStream{id: id, stream: stream}
	errStream.wg.Add(1)
	stderrMap[id] = errStream
	return errStream, nil
}

func getStderrStream(id uint64) *stderrStream {
	stderrMutex.Lock()
	defer stderrMutex.Unlock()
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
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
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

	listener, port, err := listenTcpOnFreePort("localhost", 6000+displayOffset, min(6000+displayOffset+1000, 65535))
	if err != nil {
		warning("X11 forwarding listen failed: %v", err)
		return
	}
	onExitFuncs = append(onExitFuncs, func() {
		_ = listener.Close()
	})
	displayNumber := port - 6000
	if msg.X11.AuthProtocol != "" && msg.X11.AuthCookie != "" {
		authDisplay := fmt.Sprintf("unix:%d.%d", displayNumber, msg.X11.ScreenNumber)
		input := fmt.Sprintf("remove %s\nadd %s %s %s\n", authDisplay, authDisplay, msg.X11.AuthProtocol, msg.X11.AuthCookie)
		if err := writeXauthData(input); err == nil {
			onExitFuncs = append(onExitFuncs, func() {
				_ = writeXauthData(fmt.Sprintf("remove %s\n", authDisplay))
			})
		}
	}
	go handleChannelAccept(listener, msg.X11.ChannelType)
	if msg.Envs == nil {
		msg.Envs = make(map[string]string)
	}
	msg.Envs["DISPLAY"] = fmt.Sprintf("localhost:%d.%d", displayNumber, msg.X11.ScreenNumber)
}

func listenTcpOnFreePort(host string, low, high int) (net.Listener, int, error) {
	var err error
	var listener net.Listener
	for port := low; port <= high; port++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
		if err == nil {
			return listener, port, nil
		}
	}
	if err != nil {
		return nil, 0, fmt.Errorf("listen tcp on %s:[%d,%d] failed: %v", host, low, high, err)
	}
	return nil, 0, fmt.Errorf("listen tcp on %s:[%d,%d] failed", host, low, high)
}

func writeXauthData(input string) error {
	cmd := exec.Command("xauth", "-q", "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer func() { _ = stdin.Close() }()
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte(input)); err != nil {
		return err
	}
	_ = stdin.Close()
	_, _ = doWithTimeout(func() (int, error) {
		_ = cmd.Wait()
		return 0, nil
	}, 200*time.Millisecond)
	return nil
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
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if ctx, ok := sessionMap[id]; ok {
		debug("closing the session [%d]", id)
		ctx.Close()
		delete(sessionMap, id)
	}
}

func closeAllSessions() {
	sessionMutex.Lock()
	var sessions []*sessionContext
	for _, session := range sessionMap {
		sessions = append(sessions, session)
	}
	sessionMap = make(map[uint64]*sessionContext)
	sessionMutex.Unlock()

	debug("closing all the sessions")
	for _, session := range sessions {
		session.Close()
	}
}
