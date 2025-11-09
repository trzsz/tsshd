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
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/shlex"
	"golang.org/x/crypto/ssh"
)

const (
	kX11ChannelType   = "x11"
	kX11RequestName   = "x11-req"
	kAgentChannelType = "auth-agent@openssh.com"
	kAgentRequestName = "auth-agent-req@openssh.com"
)

type x11Request struct {
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

type agentRequest struct {
}

func doWithTimeout[T any](task func() (T, error), timeout time.Duration) (T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan struct {
		ret T
		err error
	}, 1)
	go func() {
		ret, err := task()
		done <- struct {
			ret T
			err error
		}{ret, err}
		close(done)
	}()
	select {
	case <-ctx.Done():
		var ret T
		return ret, fmt.Errorf("timeout exceeded %v", timeout)
	case res := <-done:
		return res.ret, res.err
	}
}

type udpClient interface {
	closeClient() error
	newStream(connectTimeout time.Duration) (net.Conn, error)
}

type SshUdpClient struct {
	client         udpClient
	proxy          *clientProxy
	connectTimeout time.Duration
	waitGroup      sync.WaitGroup
	closed         atomic.Bool
	busMutex       sync.Mutex
	busStream      net.Conn
	sessionMutex   sync.Mutex
	sessionID      atomic.Uint64
	sessionMap     map[uint64]*SshUdpSession
	channelMutex   sync.Mutex
	channelMap     map[string]chan ssh.NewChannel
	aliveCallback  func()
	warning        func(string, ...any)
}

func NewSshUdpClient(addr string, info *ServerInfo, connectTimeout, aliveTimeout, intervalTime time.Duration,
	warningCallback func(string, ...any)) (*SshUdpClient, error) {
	var proxy *clientProxy
	if info.ProxyKey != "" {
		var err error
		addr, proxy, err = startClientProxy(addr, info)
		if err != nil {
			return nil, err
		}
		if err := proxy.renewUdpPath(connectTimeout); err != nil {
			return nil, err
		}
	}

	client, err := newUdpClient(addr, info, connectTimeout)
	if err != nil {
		return nil, err
	}
	udpClient := &SshUdpClient{
		client:         client,
		proxy:          proxy,
		sessionMap:     make(map[uint64]*SshUdpSession),
		channelMap:     make(map[string]chan ssh.NewChannel),
		connectTimeout: connectTimeout,
		warning:        warningCallback,
	}

	busStream, err := udpClient.newStream("bus")
	if err != nil {
		return nil, err
	}
	if err := sendMessage(busStream, busMessage{Timeout: aliveTimeout, Interval: intervalTime}); err != nil {
		_ = busStream.Close()
		return nil, fmt.Errorf("send bus message failed: %v", err)
	}
	if err := recvError(busStream); err != nil {
		_ = busStream.Close()
		return nil, err
	}

	udpClient.busStream = busStream
	go udpClient.handleBusEvent()

	return udpClient, nil
}

func (c *SshUdpClient) Wait() error {
	c.waitGroup.Wait()
	return nil
}

func (c *SshUdpClient) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	_, _ = doWithTimeout(func() (int, error) {
		c.busMutex.Lock()
		defer c.busMutex.Unlock()
		_ = sendCommand(c.busStream, "close")
		_ = c.busStream.Close()
		time.Sleep(200 * time.Millisecond) // give udp some time
		return 0, nil
	}, 300*time.Millisecond)

	return c.client.closeClient()
}

func (c *SshUdpClient) Reconnect(timeout time.Duration) error {
	if c.proxy != nil {
		return c.proxy.renewUdpPath(timeout)
	}
	return fmt.Errorf("no proxy for connection migration")
}

func (c *SshUdpClient) newStream(cmd string) (net.Conn, error) {
	stream, err := doWithTimeout(func() (net.Conn, error) {
		stream, err := c.client.newStream(c.connectTimeout)
		if err != nil {
			return nil, fmt.Errorf("new stream [%s] failed: %v", cmd, err)
		}
		if err = sendCommand(stream, cmd); err != nil {
			return stream, fmt.Errorf("send command [%s] failed: %v", cmd, err)
		}
		if err = recvError(stream); err != nil {
			return stream, fmt.Errorf("new stream [%s] error: %v", cmd, err)
		}
		return stream, nil
	}, c.connectTimeout)

	if err != nil && stream != nil {
		_ = stream.Close()
	}

	return stream, err
}

func (c *SshUdpClient) NewSession() (*SshUdpSession, error) {
	stream, err := c.newStream("session")
	if err != nil {
		return nil, err
	}
	c.waitGroup.Add(1)
	udpSession := &SshUdpSession{client: c, stream: stream, envs: make(map[string]string)}
	udpSession.wg.Add(1)
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	udpSession.id = c.sessionID.Add(1) - 1
	c.sessionMap[udpSession.id] = udpSession
	return udpSession, nil
}

func (c *SshUdpClient) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	stream, err := c.newStream("dial")
	if err != nil {
		return nil, err
	}
	msg := dialMessage{
		Network: network,
		Addr:    addr,
		Timeout: timeout,
	}
	if err := sendMessage(stream, &msg); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send dial message failed: %v", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	c.waitGroup.Add(1)
	return &sshUdpConn{Conn: stream, client: c}, nil
}

func (c *SshUdpClient) Listen(network, addr string) (net.Listener, error) {
	stream, err := c.newStream("listen")
	if err != nil {
		return nil, err
	}
	msg := listenMessage{
		Network: network,
		Addr:    addr,
	}
	if err := sendMessage(stream, &msg); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send listen message failed: %v", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	c.waitGroup.Add(1)
	return &sshUdpListener{client: c, stream: stream}, nil
}

func (c *SshUdpClient) HandleChannelOpen(channelType string) <-chan ssh.NewChannel {
	c.channelMutex.Lock()
	defer c.channelMutex.Unlock()
	if _, ok := c.channelMap[channelType]; ok {
		return nil
	}
	switch channelType {
	case kAgentChannelType, kX11ChannelType:
		ch := make(chan ssh.NewChannel)
		c.channelMap[channelType] = ch
		return ch
	default:
		c.warning("channel type [%s] is not supported yet", channelType)
		return nil
	}
}

func (c *SshUdpClient) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, fmt.Errorf("ssh udp client SendRequest is not supported yet")
}

func (c *SshUdpClient) KeepAlive(intervalTime time.Duration, aliveCallback func()) {
	c.aliveCallback = aliveCallback
	go func() {
		for !c.IsClosed() {
			if err := c.sendBusCommand("alive"); err != nil && !c.IsClosed() {
				c.warning("udp keep alive failed: %v", err)
			}
			time.Sleep(intervalTime)
		}
	}()
}

func (c *SshUdpClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *SshUdpClient) Exit(code int) {
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	for _, udpSession := range c.sessionMap {
		udpSession.exit(code)
		c.waitGroup.Done()
	}
	c.sessionMap = make(map[uint64]*SshUdpSession)
	_ = c.Close()
}

func (c *SshUdpClient) ForwardUDPv1(addr string, timeout time.Duration) (string, error) {
	localAddr := "127.0.0.1:0"
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return "", fmt.Errorf("resolve udp addr [%s] failed: %v", localAddr, err)
	}
	localConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", fmt.Errorf("listen udp on [%s] failed: %v", localAddr, err)
	}
	localAddr = fmt.Sprintf("127.0.0.1:%d", localConn.LocalAddr().(*net.UDPAddr).Port)

	stream, err := c.newStream("UDPv1")
	if err != nil {
		_ = localConn.Close()
		return "", err
	}
	if err := sendMessage(stream, &udpv1Message{addr, timeout}); err != nil {
		_ = stream.Close()
		_ = localConn.Close()
		return "", fmt.Errorf("send UDPv1 message failed: %v", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		_ = localConn.Close()
		return "", err
	}

	_ = localConn.SetReadBuffer(kProxyBufferSize)
	_ = localConn.SetWriteBuffer(kProxyBufferSize)
	go func() {
		buffer := make([]byte, 0xffff)
		for !c.IsClosed() {
			n, addr, err := localConn.ReadFromUDP(buffer)
			if err != nil || n <= 0 {
				continue
			}
			if err := sendUDPv1Packet(stream, uint16(addr.Port), buffer[:n]); err != nil && !c.IsClosed() {
				c.warning("UDPv1 forward send failed: %v", err)
			}
		}
	}()

	go func() {
		localUdpAddr := udpAddr
		for !c.IsClosed() {
			port, data, err := recvUDPv1Packet(stream)
			if err != nil {
				if !c.IsClosed() {
					c.warning("UDPv1 forward recv failed: %v", err)
				}
				return
			}
			if c.aliveCallback != nil {
				c.aliveCallback()
			}
			localUdpAddr.Port = int(port)
			_, _ = localConn.WriteToUDP(data, localUdpAddr)
		}
	}()

	return localAddr, nil
}

func (c *SshUdpClient) sendBusCommand(command string) error {
	c.busMutex.Lock()
	defer c.busMutex.Unlock()
	return sendCommand(c.busStream, command)
}

func (c *SshUdpClient) sendBusMessage(command string, msg any) error {
	c.busMutex.Lock()
	defer c.busMutex.Unlock()
	if err := sendCommand(c.busStream, command); err != nil {
		return err
	}
	return sendMessage(c.busStream, msg)
}

func (c *SshUdpClient) handleBusEvent() {
	for {
		command, err := recvCommand(c.busStream)
		if c.IsClosed() {
			return
		}
		if err != nil {
			c.warning("recv bus command failed: %v", err)
			return
		}
		switch command {
		case "exit":
			c.handleExitEvent()
		case "error":
			c.handleErrorEvent()
		case "channel":
			c.handleChannelEvent()
		case "alive":
			if c.aliveCallback != nil {
				c.aliveCallback()
			}
		default:
			c.warning("unknown command bus command: %s", command)
		}
	}
}

func (c *SshUdpClient) handleExitEvent() {
	var exitMsg exitMessage
	if err := recvMessage(c.busStream, &exitMsg); err != nil {
		c.warning("recv exit message failed: %v", err)
		return
	}

	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()

	udpSession, ok := c.sessionMap[exitMsg.ID]
	if !ok {
		c.warning("invalid or exited session id: %d", exitMsg.ID)
		return
	}
	udpSession.exit(exitMsg.ExitCode)

	delete(c.sessionMap, exitMsg.ID)
	c.waitGroup.Done()
}

func (c *SshUdpClient) handleErrorEvent() {
	var errMsg errorMessage
	if err := recvMessage(c.busStream, &errMsg); err != nil {
		c.warning("recv error message failed: %v", err)
		return
	}
	c.warning("udp error: %s", errMsg.Msg)
}

func (c *SshUdpClient) handleChannelEvent() {
	var channelMsg channelMessage
	if err := recvMessage(c.busStream, &channelMsg); err != nil {
		c.warning("recv channel message failed: %v", err)
		return
	}
	c.channelMutex.Lock()
	defer c.channelMutex.Unlock()
	if ch, ok := c.channelMap[channelMsg.ChannelType]; ok {
		go func() {
			ch <- &sshUdpNewChannel{
				client:      c,
				channelType: channelMsg.ChannelType,
				id:          channelMsg.ID}
		}()
	} else {
		c.warning("channel [%s] has no handler", channelMsg.ChannelType)
	}
}

type SshUdpSession struct {
	id      uint64
	wg      sync.WaitGroup
	client  *SshUdpClient
	stream  net.Conn
	pty     bool
	height  int
	width   int
	envs    map[string]string
	started bool
	closed  atomic.Bool
	stdin   io.Reader
	stdout  io.WriteCloser
	stderr  net.Conn
	code    int
	x11     *x11Request
	agent   *agentRequest
}

func (s *SshUdpSession) Wait() error {
	s.wg.Wait()
	if s.code != 0 {
		return fmt.Errorf("udp session exit with %d", s.code)
	}
	return nil
}

func (s *SshUdpSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.stdout != nil {
		_ = s.stdout.Close()
	}
	if s.stderr != nil {
		_ = s.stderr.Close()
	}

	_, err := doWithTimeout(func() (int, error) {
		err := s.stream.Close()
		time.Sleep(200 * time.Millisecond) // give udp some time
		return 0, err
	}, 300*time.Millisecond)
	return err
}

func (s *SshUdpSession) Shell() error {
	msg := startMessage{
		ID:    s.id,
		Pty:   s.pty,
		Shell: true,
		Cols:  s.width,
		Rows:  s.height,
		Envs:  s.envs,
	}
	return s.startSession(&msg)
}

func (s *SshUdpSession) Run(cmd string) error {
	if err := s.Start(cmd); err != nil {
		return err
	}
	return s.Wait()
}

func (s *SshUdpSession) Start(cmd string) error {
	args, err := shlex.Split(cmd)
	if err != nil {
		return fmt.Errorf("split cmd [%s] failed: %v", cmd, err)
	}
	if len(args) == 0 {
		return fmt.Errorf("cmd [%s] is empty", cmd)
	}
	msg := startMessage{
		ID:    s.id,
		Pty:   s.pty,
		Shell: false,
		Name:  args[0],
		Args:  args[1:],
		Envs:  s.envs,
	}
	return s.startSession(&msg)
}

func (s *SshUdpSession) startSession(msg *startMessage) error {
	if s.started {
		return fmt.Errorf("session already started")
	}
	s.started = true
	if s.x11 != nil {
		msg.X11 = &x11RequestMessage{
			ChannelType:      kX11ChannelType,
			SingleConnection: s.x11.SingleConnection,
			AuthProtocol:     s.x11.AuthProtocol,
			AuthCookie:       s.x11.AuthCookie,
			ScreenNumber:     s.x11.ScreenNumber,
		}
	}
	if s.agent != nil {
		msg.Agent = &agentRequestMessage{
			ChannelType: kAgentChannelType,
		}
	}
	if err := sendMessage(s.stream, msg); err != nil {
		return fmt.Errorf("send session message failed: %v", err)
	}
	if err := recvError(s.stream); err != nil {
		return err
	}
	if s.stdin != nil {
		go func() {
			_, _ = io.Copy(s.stream, s.stdin)
		}()
	}
	if s.stdout != nil {
		go func() {
			defer func() { _ = s.stdout.Close() }()
			_, _ = io.Copy(s.stdout, s.stream)
		}()
	}
	return nil
}

func (s *SshUdpSession) exit(code int) {
	s.code = code
	s.wg.Done()
	if s.stdout != nil {
		_ = s.stdout.Close()
	}
	if s.stderr != nil {
		_ = s.stderr.Close()
	}
}

func (s *SshUdpSession) WindowChange(height, width int) error {
	s.height, s.width = height, width
	return s.client.sendBusMessage("resize", resizeMessage{
		ID:   s.id,
		Cols: width,
		Rows: height,
	})
}

func (s *SshUdpSession) Setenv(name, value string) error {
	s.envs[name] = value
	return nil
}

func (s *SshUdpSession) StdinPipe() (io.WriteCloser, error) {
	if s.stdin != nil {
		return nil, fmt.Errorf("stdin already set")
	}
	reader, writer := io.Pipe()
	s.stdin = reader
	return writer, nil
}

func (s *SshUdpSession) StdoutPipe() (io.Reader, error) {
	if s.stdout != nil {
		return nil, fmt.Errorf("stdout already set")
	}
	reader, writer := io.Pipe()
	s.stdout = writer
	return reader, nil
}

func (s *SshUdpSession) StderrPipe() (io.Reader, error) {
	if s.stderr != nil {
		return nil, fmt.Errorf("stderr already set")
	}
	stream, err := s.client.newStream("stderr")
	if err != nil {
		return nil, err
	}
	if err := sendMessage(stream, stderrMessage{ID: s.id}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send stderr message failed: %v", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	s.stderr = stream
	return s.stderr, nil
}

func (s *SshUdpSession) Output(cmd string) ([]byte, error) {
	stdout, err := s.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := s.Start(cmd); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = buf.ReadFrom(stdout)
	})
	if err := s.Wait(); err != nil {
		return nil, err
	}
	wg.Wait()
	return buf.Bytes(), nil
}

func (s *SshUdpSession) CombinedOutput(cmd string) ([]byte, error) {
	output, err := s.Output(cmd)
	if err != nil || s.stderr == nil {
		return output, err
	}
	var buf bytes.Buffer
	buf.Write(output)
	_, _ = buf.ReadFrom(s.stderr)
	return buf.Bytes(), nil
}

func (s *SshUdpSession) RequestPty(term string, height, width int, termmodes ssh.TerminalModes) error {
	s.pty = true
	s.envs["TERM"] = term
	s.height, s.width = height, width
	return nil
}

func (s *SshUdpSession) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	switch name {
	case kX11RequestName:
		s.x11 = &x11Request{}
		if payload != nil {
			if err := ssh.Unmarshal(payload, s.x11); err != nil {
				return false, fmt.Errorf("unmarshal x11 request failed: %v", err)
			}
		}
		return true, nil
	case kAgentRequestName:
		s.agent = &agentRequest{}
		if payload != nil {
			if err := ssh.Unmarshal(payload, s.agent); err != nil {
				return false, fmt.Errorf("unmarshal agent request failed: %v", err)
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("ssh udp session SendRequest [%s] is not supported yet", name)
	}
}

func (s *SshUdpSession) RedrawScreen() {
	if s.height <= 0 || s.width <= 0 {
		return
	}
	_ = s.client.sendBusMessage("resize", resizeMessage{
		ID:     s.id,
		Cols:   s.width,
		Rows:   s.height,
		Redraw: true,
	})
}

func (s *SshUdpSession) GetTerminalWidth() int {
	return s.width
}

type sshUdpListener struct {
	client *SshUdpClient
	stream net.Conn
	closed atomic.Bool
}

func (l *sshUdpListener) Accept() (net.Conn, error) {
	var msg acceptMessage
	if err := recvMessage(l.stream, &msg); err != nil {
		return nil, fmt.Errorf("recv accept message failed: %v", err)
	}
	stream, err := l.client.newStream("accept")
	if err != nil {
		return nil, err
	}
	if err := sendMessage(stream, &msg); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send accept message failed: %v", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	l.client.waitGroup.Add(1)
	return &sshUdpConn{Conn: stream, client: l.client}, nil
}

func (l *sshUdpListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	l.client.waitGroup.Done()
	return l.stream.Close()
}

func (l *sshUdpListener) Addr() net.Addr {
	return nil
}

type sshUdpConn struct {
	net.Conn
	client *SshUdpClient
	closed atomic.Bool
}

func (c *sshUdpConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.client.waitGroup.Done()
	return c.Conn.Close()
}

type sshUdpNewChannel struct {
	client      *SshUdpClient
	channelType string
	id          uint64
}

func (c *sshUdpNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	stream, err := c.client.newStream("accept")
	if err != nil {
		return nil, nil, err
	}
	if err := sendMessage(stream, &acceptMessage{ID: c.id}); err != nil {
		_ = stream.Close()
		return nil, nil, fmt.Errorf("send accept message failed: %v", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, nil, err
	}
	c.client.waitGroup.Add(1)
	return &sshUdpChannel{Conn: stream, client: c.client}, nil, nil
}

func (c *sshUdpNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	return fmt.Errorf("ssh udp new channel Reject is not supported yet")
}

func (c *sshUdpNewChannel) ChannelType() string {
	return c.channelType
}

func (c *sshUdpNewChannel) ExtraData() []byte {
	return nil
}

type sshUdpChannel struct {
	net.Conn
	client *SshUdpClient
	closed atomic.Bool
}

func (c *sshUdpChannel) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.client.waitGroup.Done()
	return c.Conn.Close()
}

func (c *sshUdpChannel) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	} else {
		// close the entire stream since there is no half-close
		time.Sleep(200 * time.Millisecond)
		return c.Close()
	}
}

func (c *sshUdpChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, fmt.Errorf("ssh udp channel SendRequest is not supported yet")
}

func (c *sshUdpChannel) Stderr() io.ReadWriter {
	c.client.warning("ssh udp channel Stderr is not supported yet")
	return nil
}
