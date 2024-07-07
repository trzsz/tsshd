/*
MIT License

Copyright (c) 2024 The Trzsz SSH Authors.

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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

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
}

type stderrStream struct {
	id     uint64
	wg     sync.WaitGroup
	stream net.Conn
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
	return nil
}

func (c *sessionContext) forwardIO(stream net.Conn) {
	if c.stdin != nil {
		go func() {
			_, _ = io.Copy(c.stdin, stream)
		}()
	}

	if c.stdout != nil {
		c.wg.Add(1)
		go func() {
			_, _ = io.Copy(stream, c.stdout)
			c.wg.Done()
		}()
	}

	if c.stderr != nil {
		c.wg.Add(1)
		go func() {
			if stderr, ok := stderrMap[c.id]; ok {
				_, _ = io.Copy(stderr.stream, c.stderr)
			} else {
				_, _ = io.Copy(stream, c.stderr)
			}
			c.wg.Done()
		}()
	}
}

func (c *sessionContext) Wait() {
	if c.pty != nil {
		_ = c.pty.Wait()
	} else {
		_ = c.cmd.Wait()
	}
	c.wg.Wait()
}

func (c *sessionContext) Close() {
	if err := sendBusMessage("exit", ExitMessage{
		ID:       c.id,
		ExitCode: c.cmd.ProcessState.ExitCode(),
	}); err != nil {
		trySendErrorMessage("send exit message failed: %v", err)
	}
	if c.stdin != nil {
		c.stdin.Close()
	}
	if c.stdout != nil {
		c.stdout.Close()
	}
	if c.stderr != nil {
		c.stderr.Close()
	}
	if c.started {
		if c.pty != nil {
			_ = c.pty.Close()
		} else {
			_ = c.cmd.Process.Kill()
		}
	}
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	delete(sessionMap, c.id)
}

func (c *sessionContext) SetSize(cols, rows int) error {
	if c.pty == nil {
		return fmt.Errorf("session %d %v is not pty", c.id, c.cmd.Args)
	}
	if err := c.pty.Resize(cols, rows); err != nil {
		return fmt.Errorf("pty set size failed: %v", err)
	}
	return nil
}

func handleSessionEvent(stream net.Conn) {
	var msg StartMessage
	if err := RecvMessage(stream, &msg); err != nil {
		SendError(stream, fmt.Errorf("recv start message failed: %v", err))
		return
	}

	handleX11Request(&msg)

	handleAgentRequest(&msg)

	if errStream := getStderrStream(msg.ID); errStream != nil {
		defer errStream.Close()
	}

	ctx, err := newSessionContext(&msg)
	if err != nil {
		SendError(stream, err)
		return
	}
	defer ctx.Close()

	if msg.Pty {
		err = ctx.StartPty()
	} else {
		err = ctx.StartCmd()
	}
	if err != nil {
		SendError(stream, err)
		return
	}

	if err := SendSuccess(stream); err != nil { // ack ok
		trySendErrorMessage("session ack ok failed: %v", err)
		return
	}

	ctx.forwardIO(stream)

	ctx.Wait()
}

func newSessionContext(msg *StartMessage) (*sessionContext, error) {
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

func newStderrStream(id uint64, stream net.Conn) (*stderrStream, error) {
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

func getSessionStartCmd(msg *StartMessage) (*exec.Cmd, error) {
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
		cmd := exec.Command(msg.Name, msg.Args...)
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

func handleStderrEvent(stream net.Conn) {
	var msg StderrMessage
	if err := RecvMessage(stream, &msg); err != nil {
		SendError(stream, fmt.Errorf("recv stderr message failed: %v", err))
		return
	}

	errStream, err := newStderrStream(msg.ID, stream)
	if err != nil {
		SendError(stream, err)
		return
	}

	if err := SendSuccess(stream); err != nil { // ack ok
		trySendErrorMessage("stderr ack ok failed: %v", err)
		return
	}

	errStream.Wait()
}

func handleResizeEvent(stream net.Conn) error {
	var msg ResizeMessage
	if err := RecvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv resize message failed: %v", err)
	}
	if msg.Cols <= 0 || msg.Rows <= 0 {
		return fmt.Errorf("resize message invalid: %#v", msg)
	}
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if ctx, ok := sessionMap[msg.ID]; ok {
		return ctx.SetSize(msg.Cols, msg.Rows)
	}
	return fmt.Errorf("invalid session id: %d", msg.ID)
}

func handleX11Request(msg *StartMessage) {
	if msg.X11 == nil {
		return
	}
	listener, port, err := listenTcpOnFreePort("localhost", 6020, 6999)
	if err != nil {
		trySendErrorMessage("X11 forwarding listen failed: %v", err)
		return
	}
	onExitFuncs = append(onExitFuncs, func() {
		listener.Close()
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
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte(input)); err != nil {
		return err
	}
	stdin.Close()
	done := make(chan struct{}, 1)
	go func() {
		defer close(done)
		_ = cmd.Wait()
		done <- struct{}{}
	}()
	select {
	case <-time.After(200 * time.Millisecond):
	case <-done:
	}
	return nil
}

func handleAgentRequest(msg *StartMessage) {
	if msg.Agent == nil {
		return
	}
	tempDir, err := os.MkdirTemp("", "tsshd-")
	if err != nil {
		trySendErrorMessage("agent forwarding mkdir temp failed: %v", err)
		return
	}
	onExitFuncs = append(onExitFuncs, func() {
		_ = os.RemoveAll(tempDir)
	})
	agentPath := filepath.Join(tempDir, fmt.Sprintf("agent.%d", os.Getpid()))
	listener, err := net.Listen("unix", agentPath)
	if err != nil {
		trySendErrorMessage("agent forwarding listen on [%s] failed: %v", agentPath, err)
		return
	}
	if err := os.Chmod(agentPath, 0600); err != nil {
		trySendErrorMessage("agent forwarding chmod [%s] failed: %v", agentPath, err)
	}
	onExitFuncs = append(onExitFuncs, func() {
		listener.Close()
		_ = os.Remove(agentPath)
	})
	go handleChannelAccept(listener, msg.Agent.ChannelType)
	msg.Envs["SSH_AUTH_SOCK"] = agentPath
}

func handleChannelAccept(listener net.Listener, channelType string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			trySendErrorMessage("channel accept failed: %v", err)
			break
		}
		go func(conn net.Conn) {
			id := addAcceptConn(conn)
			if err := sendBusMessage("channel", &ChannelMessage{ChannelType: channelType, ID: id}); err != nil {
				trySendErrorMessage("send channel message failed: %v", err)
			}
		}(conn)
	}
}
