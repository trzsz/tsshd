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

type udpClient interface {
	closeClient() error
	newStream(connectTimeout time.Duration) (net.Conn, error)
}

// SshUdpClient implements a UDP SSH client
type SshUdpClient struct {
	client          udpClient
	proxy           *clientProxy
	connectTimeout  time.Duration
	waitGroup       sync.WaitGroup
	closed          atomic.Bool
	busMutex        sync.Mutex
	busStream       net.Conn
	sessionMutex    sync.Mutex
	sessionID       atomic.Uint64
	sessionMap      map[uint64]*SshUdpSession
	channelMutex    sync.Mutex
	channelMap      map[string]chan ssh.NewChannel
	aliveCallback   func(int64)
	aliveNewVer     bool
	quitCallback    func(string)
	discardCallback func([]byte, []byte)
	enableDebugging bool
	clientDebugFunc func(int64, string)
	enableWarning   bool
	clientWarningFn func(string)
	outputChecker   *timeoutChecker
}

// UdpClientOptions contains all configuration parameters required to create and initialize a new SshUdpClient
type UdpClientOptions struct {
	EnableDebugging  bool
	EnableWarning    bool
	IPv4             bool
	IPv6             bool
	TsshdAddr        string
	ServerInfo       *ServerInfo
	AliveTimeout     time.Duration
	IntervalTime     time.Duration
	ConnectTimeout   time.Duration
	HeartbeatTimeout time.Duration
	DebugFunc        func(int64, string)
	WarningFunc      func(string)
	QuitCallback     func(reason string)
	DiscardCallback  func(before []byte, after []byte)
}

// NewSshUdpClient creates a SshUdpClient
func NewSshUdpClient(opts *UdpClientOptions) (*SshUdpClient, error) {
	enableDebugLogging, clientDebug = opts.EnableDebugging, opts.DebugFunc
	enableWarningLogging, clientWarningFunc = opts.EnableWarning, opts.WarningFunc

	udpClient := &SshUdpClient{
		sessionMap:      make(map[uint64]*SshUdpSession),
		channelMap:      make(map[string]chan ssh.NewChannel),
		connectTimeout:  opts.ConnectTimeout,
		quitCallback:    opts.QuitCallback,
		discardCallback: opts.DiscardCallback,
		enableDebugging: opts.EnableDebugging,
		clientDebugFunc: opts.DebugFunc,
		enableWarning:   opts.EnableWarning,
		clientWarningFn: opts.WarningFunc,
	}

	network := "udp"
	if opts.ServerInfo.ProxyMode == kProxyModeTCP {
		network = "tcp"
	}
	if opts.IPv4 && !opts.IPv6 {
		network += "4"
	} else if opts.IPv6 && !opts.IPv4 {
		network += "6"
	}

	var err error
	var tsshdAddr string
	if opts.ServerInfo.ProxyKey != "" {
		tsshdAddr, udpClient.proxy, err = startClientProxy(udpClient, network, opts.TsshdAddr, opts.ServerInfo)
		if err != nil {
			return nil, err
		}
		if err := udpClient.proxy.renewTransportPath(opts.ConnectTimeout); err != nil {
			return nil, err
		}
	} else {
		addr, err := net.ResolveUDPAddr(network, opts.TsshdAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve [%s] addr [%s] failed: %v", network, opts.TsshdAddr, err)
		}
		tsshdAddr = addr.String()
	}

	udpClient.client, err = newUdpClient(tsshdAddr, opts.ServerInfo, opts.ConnectTimeout)
	if err != nil {
		return nil, err
	}

	udpClient.outputChecker = newTimeoutChecker(opts.HeartbeatTimeout, func(timeout bool) {
		if timeout {
			udpClient.debug("input forwarding blocked due to no server output for [%v]", opts.HeartbeatTimeout)
		} else {
			udpClient.debug("input forwarding resumed after receiving server output")
		}
	})

	busStream, err := udpClient.newStream("bus")
	if err != nil {
		return nil, err
	}
	if err := sendMessage(busStream, busMessage{
		Timeout:          opts.AliveTimeout,
		Interval:         opts.IntervalTime,
		HeartbeatTimeout: opts.HeartbeatTimeout}); err != nil {
		_ = busStream.Close()
		return nil, fmt.Errorf("send bus message failed: %w", err)
	}
	if err := recvError(busStream); err != nil {
		_ = busStream.Close()
		return nil, err
	}

	udpClient.busStream = busStream
	go udpClient.handleBusEvent()

	return udpClient, nil
}

func (c *SshUdpClient) debug(format string, a ...any) {
	if !c.enableDebugging || c.clientDebugFunc == nil {
		return
	}

	msg := fmt.Sprintf(format, a...)
	c.clientDebugFunc(time.Now().UnixMilli(), fmt.Sprintf("[client] %s", msg))
}

func (c *SshUdpClient) warning(format string, a ...any) {
	if !c.enableWarning || c.clientWarningFn == nil {
		return
	}

	msg := fmt.Sprintf(format, a...)
	c.clientWarningFn(msg)
}

// Wait blocks until the client has shut down
func (c *SshUdpClient) Wait() error {
	c.waitGroup.Wait()
	return nil
}

// Close closes the client
func (c *SshUdpClient) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}

	_, _ = doWithTimeout(func() (int, error) {
		if err := c.sendBusCommand("close"); err != nil {
			c.debug("send cmd [close] failed: %v", err)
		} else {
			c.debug("send cmd [close] completed")
		}
		// UDP connections do not support half-close (write-only close) for now,
		// so we add extra wait time to allow all incoming data to be received.
		time.Sleep(200 * time.Millisecond) // give udp some time
		if err := c.busStream.Close(); err != nil {
			c.debug("close bus stream failed: %v", err)
		} else {
			c.debug("close bus stream completed")
		}
		return 0, nil
	}, 300*time.Millisecond)

	_, err := doWithTimeout(func() (int, error) {
		err := c.client.closeClient()
		if err != nil {
			c.debug("close client failed: %v", err)
		} else {
			c.debug("close client completed")
		}
		return 0, err
	}, 200*time.Millisecond)

	return err
}

// Reconnect creates a new UDP path to the server
func (c *SshUdpClient) Reconnect(timeout time.Duration) error {
	if c.proxy == nil {
		return fmt.Errorf("no proxy for connection migration")
	}

	if err := c.proxy.renewTransportPath(timeout); err != nil {
		return err
	}

	c.outputChecker.updateTime(time.Now().UnixMilli())

	if err := c.sendBusCommand("alive"); err != nil { // ping the server
		return fmt.Errorf("ping server failed: %w", err)
	}

	return nil
}

func (c *SshUdpClient) newStream(cmd string) (net.Conn, error) {
	stream, err := doWithTimeout(func() (net.Conn, error) {
		stream, err := c.client.newStream(c.connectTimeout)
		if err != nil {
			return nil, fmt.Errorf("new stream [%s] failed: %w", cmd, err)
		}
		if err = sendCommand(stream, cmd); err != nil {
			return stream, fmt.Errorf("send command [%s] failed: %w", cmd, err)
		}
		if err = recvError(stream); err != nil {
			return stream, fmt.Errorf("new stream [%s] error: %w", cmd, err)
		}
		return stream, nil
	}, c.connectTimeout)

	if err != nil && stream != nil {
		_ = stream.Close()
	}

	return stream, err
}

// NewSession opens a new Session for this client
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

// DialTimeout initiates a connection to the addr from the remote host
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
		return nil, fmt.Errorf("send dial message failed: %w", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	c.waitGroup.Add(1)
	return &sshUdpConn{Conn: stream, client: c}, nil
}

// Listen requests the remote peer open a listening socket on addr
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
		return nil, fmt.Errorf("send listen message failed: %w", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	c.waitGroup.Add(1)
	return &sshUdpListener{client: c, stream: stream}, nil
}

// HandleChannelOpen returns a channel on which NewChannel requests
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

// SendRequest is not supported yet
func (c *SshUdpClient) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, fmt.Errorf("ssh udp client SendRequest is not supported yet")
}

// KeepAlive send heartbeat packets to the server
func (c *SshUdpClient) KeepAlive(aliveTime int64, aliveCallback func(int64)) error {
	if c.IsClosed() {
		return nil
	}
	if !c.aliveNewVer {
		_ = c.sendBusCommand("alive")
	}
	c.aliveCallback = aliveCallback
	return c.sendBusMessage("alive2", aliveMessage{aliveTime})
}

// IsClosed returns whether the client has closed
func (c *SshUdpClient) IsClosed() bool {
	return c.closed.Load()
}

// ForwardUDPv1 forwards UDP packets for proxy jump
func (c *SshUdpClient) ForwardUDPv1(addr string, timeout time.Duration) (string, error) {
	localAddr := "127.0.0.1:0"
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return "", fmt.Errorf("resolve udp addr [%s] failed: %w", localAddr, err)
	}
	localConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", fmt.Errorf("listen udp on [%s] failed: %w", localAddr, err)
	}
	localAddr = localConn.LocalAddr().String()

	stream, err := c.newStream("UDPv1")
	if err != nil {
		_ = localConn.Close()
		return "", err
	}
	if err := sendMessage(stream, &udpv1Message{addr, timeout}); err != nil {
		_ = stream.Close()
		_ = localConn.Close()
		return "", fmt.Errorf("send UDPv1 message failed: %w", err)
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
			for c.outputChecker.isTimeout() {
				time.Sleep(10 * time.Millisecond)
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
			c.outputChecker.updateTime(time.Now().UnixMilli())
			if err != nil {
				if !c.IsClosed() {
					c.warning("UDPv1 forward recv failed: %v", err)
				}
				return
			}
			localUdpAddr.Port = int(port)
			_, _ = localConn.WriteToUDP(data, localUdpAddr)
		}
	}()

	return localAddr, nil
}

// GetLastOutputTime returns the last server output time in milliseconds
func (c *SshUdpClient) GetLastOutputTime() int64 {
	return c.outputChecker.getAliveTime()
}

// SetKeepPendingInput sets whether to keep the pending input during reconnection.
func (c *SshUdpClient) SetKeepPendingInput(keep bool) error {
	return c.sendBusMessage("setting", settingsMessage{KeepPendingInput: &keep})
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
		if err != nil {
			if !c.IsClosed() {
				c.warning("recv bus command failed: %v", err)
			}
			return
		}
		c.outputChecker.updateTime(time.Now().UnixMilli())
		switch command {
		case "quit":
			c.handleQuitEvent()
		case "exit":
			c.handleExitEvent()
		case "debug":
			c.handleDebugEvent()
		case "error":
			c.handleErrorEvent()
		case "channel":
			c.handleChannelEvent()
		case "alive":
			if c.aliveCallback != nil {
				go c.aliveCallback(0)
			}
		case "alive2":
			c.handleAliveEvent()
		case "discard":
			c.handleDiscardEvent()
		default:
			if err := handleUnknownEvent(c.busStream, command); err != nil {
				c.warning("handle bus command [%s] failed: %v. You may need to upgrade tssh.", command, err)
			}
		}
	}
}

func (c *SshUdpClient) handleQuitEvent() {
	var quitMsg quitMessage
	if err := recvMessage(c.busStream, &quitMsg); err != nil {
		c.warning("recv quit message failed: %v", err)
		return
	}
	c.debug("quit due to %s", quitMsg.Msg)
	if c.quitCallback != nil {
		go c.quitCallback(quitMsg.Msg)
	} else {
		c.warning("quit due to %s", quitMsg.Msg)
	}
}

func (c *SshUdpClient) handleExitEvent() {
	var exitMsg exitMessage
	if err := recvMessage(c.busStream, &exitMsg); err != nil {
		c.warning("recv exit message failed: %v", err)
		return
	}
	c.debug("session [%d] exiting with code: %d", exitMsg.ID, exitMsg.ExitCode)

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

func (c *SshUdpClient) handleDebugEvent() {
	var dbgMsg debugMessage
	if err := recvMessage(c.busStream, &dbgMsg); err != nil {
		c.warning("recv debug message failed: %v", err)
		return
	}
	if !c.enableDebugging || c.clientDebugFunc == nil {
		return
	}
	if dbgMsg.Time == 0 {
		dbgMsg.Time = time.Now().UnixMilli()
	}
	c.clientDebugFunc(dbgMsg.Time, fmt.Sprintf("[server] %s", dbgMsg.Msg))
}

func (c *SshUdpClient) handleErrorEvent() {
	var errMsg errorMessage
	if err := recvMessage(c.busStream, &errMsg); err != nil {
		c.warning("recv error message failed: %v", err)
		return
	}
	c.warning("%s", errMsg.Msg)
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

func (c *SshUdpClient) handleAliveEvent() {
	var aliveMsg aliveMessage
	if err := recvMessage(c.busStream, &aliveMsg); err != nil {
		c.warning("recv alive message failed: %v", err)
		return
	}
	if c.aliveCallback != nil {
		go c.aliveCallback(aliveMsg.Time)
	}
	c.aliveNewVer = true
}

func (c *SshUdpClient) handleDiscardEvent() {
	var discardMsg discardMessage
	if err := recvMessage(c.busStream, &discardMsg); err != nil {
		c.warning("recv discard message failed: %v", err)
		return
	}
	if c.discardCallback != nil {
		c.discardCallback(discardMsg.DiscardMarker, discardMsg.DiscardedInput)
	}
}

// SshUdpSession represents a connection to a remote command or shell
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
	stderr  io.WriteCloser
	code    int
	x11     *x11Request
	agent   *agentRequest
}

// Wait waits for the remote command to exit
func (s *SshUdpSession) Wait() error {
	s.wg.Wait()
	return nil
}

// Close closes the underlying network connection
func (s *SshUdpSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	_, err := doWithTimeout(func() (int, error) {
		err := s.stream.Close()
		s.client.debug("close session completed")
		return 0, err
	}, 100*time.Millisecond)
	return err
}

// Shell starts a login shell on the remote host
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

// Run runs cmd on the remote host
func (s *SshUdpSession) Run(cmd string) error {
	if err := s.Start(cmd); err != nil {
		return err
	}
	return s.Wait()
}

// Start runs cmd on the remote host
func (s *SshUdpSession) Start(cmd string) error {
	args, err := shlex.Split(cmd)
	if err != nil {
		return fmt.Errorf("split cmd [%s] failed: %w", cmd, err)
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
		return fmt.Errorf("send session message failed: %w", err)
	}
	if err := recvError(s.stream); err != nil {
		return err
	}
	if s.stdin != nil {
		go s.forwardInput()
	}
	if s.stdout != nil {
		s.wg.Go(func() { s.forwardOutput("stdout", s.stream, s.stdout) })
	}
	return nil
}

func (s *SshUdpSession) forwardInput() {
	defer func() { _ = s.stream.Close() }()
	buffer := make([]byte, 32*1024)
	for {
		n, err := s.stdin.Read(buffer)
		if n > 0 {
			for s.client.outputChecker.isTimeout() {
				time.Sleep(10 * time.Millisecond)
			}
			if err := writeAll(s.stream, buffer[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	s.client.debug("session [%d] stdin completed", s.id)
}

func (s *SshUdpSession) forwardOutput(name string, reader io.Reader, writer io.WriteCloser) {
	defer func() { _ = writer.Close() }()
	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		s.client.outputChecker.updateTime(time.Now().UnixMilli())
		if n > 0 {
			if err := writeAll(writer, buffer[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	s.client.debug("session [%d] %s completed", s.id, name)
}

func (s *SshUdpSession) exit(code int) {
	s.code = code
	s.wg.Done()
}

// WindowChange informs the remote host about a terminal window dimension
// change to height rows and width columns.
func (s *SshUdpSession) WindowChange(height, width int) error {
	s.height, s.width = height, width
	return s.client.sendBusMessage("resize", resizeMessage{
		ID:   s.id,
		Cols: width,
		Rows: height,
	})
}

// Setenv sets an environment variable that will be applied to any
// command executed by Shell or Run.
func (s *SshUdpSession) Setenv(name, value string) error {
	s.envs[name] = value
	return nil
}

// StdinPipe returns a pipe that will be connected to the
// remote command's standard input when the command starts.
func (s *SshUdpSession) StdinPipe() (io.WriteCloser, error) {
	if s.stdin != nil {
		return nil, fmt.Errorf("stdin already set")
	}
	reader, writer := io.Pipe()
	s.stdin = reader
	return writer, nil
}

// StdoutPipe returns a pipe that will be connected to the
// remote command's standard output when the command starts.
func (s *SshUdpSession) StdoutPipe() (io.Reader, error) {
	if s.stdout != nil {
		return nil, fmt.Errorf("stdout already set")
	}
	reader, writer := io.Pipe()
	s.stdout = writer
	return reader, nil
}

// StderrPipe returns a pipe that will be connected to the
// remote command's standard error when the command starts.
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
		return nil, fmt.Errorf("send stderr message failed: %w", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	reader, writer := io.Pipe()
	s.stderr = writer
	s.wg.Go(func() { s.forwardOutput("stderr", stream, s.stderr) })
	return reader, nil
}

// Output runs cmd on the remote host and returns its standard output.
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
	wg.Go(func() { _, _ = buf.ReadFrom(stdout) })
	if err := s.Wait(); err != nil {
		return nil, err
	}
	wg.Wait()
	return buf.Bytes(), nil
}

// CombinedOutput runs cmd on the remote host and returns its combined
// standard output and standard error.
func (s *SshUdpSession) CombinedOutput(cmd string) ([]byte, error) {
	stdout, err := s.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := s.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := s.Start(cmd); err != nil {
		return nil, err
	}
	var outbuf bytes.Buffer
	var errbuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Go(func() { _, _ = outbuf.ReadFrom(stdout) })
	wg.Go(func() { _, _ = errbuf.ReadFrom(stderr) })
	if err := s.Wait(); err != nil {
		return nil, err
	}
	wg.Wait()
	outbuf.Write(errbuf.Bytes())
	return outbuf.Bytes(), nil
}

// RequestPty requests the association of a pty with the session on the remote host.
func (s *SshUdpSession) RequestPty(term string, height, width int, termmodes ssh.TerminalModes) error {
	s.pty = true
	s.envs["TERM"] = term
	s.height, s.width = height, width
	return nil
}

// SendRequest sends an out-of-band channel request on the SSH channel
// underlying the session.
func (s *SshUdpSession) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	switch name {
	case kX11RequestName:
		s.x11 = &x11Request{}
		if payload != nil {
			if err := ssh.Unmarshal(payload, s.x11); err != nil {
				return false, fmt.Errorf("unmarshal x11 request failed: %w", err)
			}
		}
		return true, nil
	case kAgentRequestName:
		s.agent = &agentRequest{}
		if payload != nil {
			if err := ssh.Unmarshal(payload, s.agent); err != nil {
				return false, fmt.Errorf("unmarshal agent request failed: %w", err)
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("ssh udp session SendRequest [%s] is not supported yet", name)
	}
}

// RequestSubsystem requests the association of a subsystem with the session on the remote host.
// A subsystem is a predefined command that runs in the background when the ssh session is initiated
func (s *SshUdpSession) RequestSubsystem(name string) error {
	msg := startMessage{
		ID:   s.id,
		Subs: name,
	}
	return s.startSession(&msg)
}

// RedrawScreen clear and redraw the screen right now
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

// GetTerminalWidth returns the width of the terminal
func (s *SshUdpSession) GetTerminalWidth() int {
	return s.width
}

// GetExitCode returns exit code if exists
func (s *SshUdpSession) GetExitCode() int {
	return s.code
}

type sshUdpListener struct {
	client *SshUdpClient
	stream net.Conn
	closed atomic.Bool
}

func (l *sshUdpListener) Accept() (net.Conn, error) {
	var msg acceptMessage
	if err := recvMessage(l.stream, &msg); err != nil {
		return nil, fmt.Errorf("recv accept message failed: %w", err)
	}
	l.client.outputChecker.updateTime(time.Now().UnixMilli())
	stream, err := l.client.newStream("accept")
	if err != nil {
		return nil, err
	}
	if err := sendMessage(stream, &msg); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send accept message failed: %w", err)
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

func (c *sshUdpConn) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(buf)
	c.client.outputChecker.updateTime(time.Now().UnixMilli())
	return n, err
}

func (c *sshUdpConn) Write(buf []byte) (int, error) {
	for c.client.outputChecker.isTimeout() {
		time.Sleep(10 * time.Millisecond)
	}
	return c.Conn.Write(buf)
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
		return nil, nil, fmt.Errorf("send accept message failed: %w", err)
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

func (c *sshUdpChannel) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(buf)
	c.client.outputChecker.updateTime(time.Now().UnixMilli())
	return n, err
}

func (c *sshUdpChannel) Write(buf []byte) (int, error) {
	for c.client.outputChecker.isTimeout() {
		time.Sleep(10 * time.Millisecond)
	}
	return c.Conn.Write(buf)
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
