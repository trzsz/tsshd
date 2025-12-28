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

// SshUdpClient implements a UDP SSH client
type SshUdpClient struct {
	proxyClient     *SshUdpClient
	protoClient     protocolClient
	networkProxy    *clientProxy
	intervalTime    time.Duration
	connectTimeout  time.Duration
	exitWG          sync.WaitGroup
	closed          atomic.Bool
	busMutex        sync.Mutex
	busStream       Stream
	busClosed       chan struct{}
	sessionMutex    sync.Mutex
	sessionID       atomic.Uint64
	sessionMap      map[uint64]*SshUdpSession
	channelMutex    sync.Mutex
	channelMap      map[string]chan ssh.NewChannel
	quitCallback    func(string)
	discardCallback func([]byte, []byte)
	enableDebugging bool
	clientDebugFunc func(int64, string)
	enableWarning   bool
	clientWarningFn func(string)
	activeChecker   *timeoutChecker
	activeAckChan   chan int64
	reconnectMutex  sync.Mutex
	reconnectError  atomic.Pointer[error]
}

// UdpClientOptions contains all configuration parameters required to create and initialize a new SshUdpClient
type UdpClientOptions struct {
	ProxyClient      *SshUdpClient
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

	if opts.ServerInfo.ServerVer == "" {
		return nil, fmt.Errorf("please upgrade tsshd to continue")
	}

	udpClient := &SshUdpClient{
		proxyClient:     opts.ProxyClient,
		sessionMap:      make(map[uint64]*SshUdpSession),
		channelMap:      make(map[string]chan ssh.NewChannel),
		intervalTime:    opts.IntervalTime,
		connectTimeout:  opts.ConnectTimeout,
		quitCallback:    opts.QuitCallback,
		discardCallback: opts.DiscardCallback,
		enableDebugging: opts.EnableDebugging,
		clientDebugFunc: opts.DebugFunc,
		enableWarning:   opts.EnableWarning,
		clientWarningFn: opts.WarningFunc,
	}

	var err error
	var tsshdAddr string
	tsshdAddr, udpClient.networkProxy, err = startClientProxy(udpClient, opts)
	if err != nil {
		return nil, err
	}
	if err := udpClient.networkProxy.renewTransportPath(opts.ProxyClient, opts.ConnectTimeout); err != nil {
		return nil, err
	}

	mtu := uint16(0)
	if opts.ProxyClient != nil {
		mtu = opts.ProxyClient.GetMaxDatagramSize()
	}
	udpClient.protoClient, err = newProtoClient(tsshdAddr, opts.ServerInfo, mtu, opts.ConnectTimeout)
	if err != nil {
		return nil, err
	}

	udpClient.activeChecker = newTimeoutChecker(opts.HeartbeatTimeout)
	if enableDebugLogging {
		udpClient.activeChecker.onTimeout(func() {
			udpClient.debug("transport offline, last activity at %v", time.UnixMilli(udpClient.activeChecker.getAliveTime()).Format("15:04:05.000"))
		})
		udpClient.activeChecker.onReconnected(func() {
			udpClient.debug("transport resumed, last activity at %v", time.UnixMilli(udpClient.activeChecker.getAliveTime()).Format("15:04:05.000"))
		})
	}
	udpClient.activeChecker.onReconnected(func() {
		totalSize, totalCount := udpClient.networkProxy.pktCache.clearCache()
		if enableDebugLogging {
			udpClient.debug("drop packet cache count [%d] cache size [%d]", totalCount, totalSize)
		}
	})
	udpClient.activeChecker.onTimeout(udpClient.tryToReconnect)

	busStream, err := udpClient.newStream("bus")
	if err != nil {
		return nil, err
	}
	if err := sendMessage(busStream, busMessage{
		ClientVer:        kTsshdVersion,
		AliveTimeout:     opts.AliveTimeout,
		IntervalTime:     opts.IntervalTime,
		HeartbeatTimeout: opts.HeartbeatTimeout}); err != nil {
		_ = busStream.Close()
		return nil, fmt.Errorf("send bus message failed: %w", err)
	}
	if err := recvError(busStream); err != nil {
		_ = busStream.Close()
		return nil, err
	}

	udpClient.busStream, udpClient.busClosed = busStream, make(chan struct{})
	go udpClient.handleBusEvent()

	udpClient.activeAckChan = make(chan int64, 1)
	go udpClient.keepAlive(opts.IntervalTime)

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
	c.exitWG.Wait()
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
		_ = c.busStream.CloseWrite()

		select {
		case <-c.busClosed:
			c.debug("close bus stream completed")
		case <-time.After(280 * time.Millisecond):
			c.debug("close bus stream timeout")
		}
		_ = c.busStream.Close()
		return 0, nil
	}, 300*time.Millisecond)

	_, err := doWithTimeout(func() (int, error) {
		err := c.protoClient.closeClient()
		if err != nil {
			c.debug("close client failed: %v", err)
		} else {
			c.debug("close client completed")
		}
		return 0, err
	}, 200*time.Millisecond)

	c.networkProxy.Close()
	c.activeChecker.Close()

	return err
}

func (c *SshUdpClient) newStream(cmd string) (Stream, error) {
	stream, err := c.protoClient.newStream(c.connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("new stream [%s] failed: %w", cmd, err)
	}
	if err := sendCommand(stream, cmd); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send command [%s] failed: %w", cmd, err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("new stream [%s] error: %w", cmd, err)
	}
	return stream, nil
}

// NewSession opens a new Session for this client
func (c *SshUdpClient) NewSession() (*SshUdpSession, error) {
	stream, err := c.newStream("session")
	if err != nil {
		return nil, err
	}
	c.exitWG.Add(1)
	udpSession := &SshUdpSession{client: c, stream: stream, envs: make(map[string]string)}
	udpSession.exitWG.Add(1)
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	udpSession.id = c.sessionID.Add(1) - 1
	c.sessionMap[udpSession.id] = udpSession
	return udpSession, nil
}

// DialTimeout initiates a connection to the addr from the remote host
func (c *SshUdpClient) DialTimeout(network, addr string, timeout time.Duration) (Stream, error) {
	stream, err := c.newStream("dial")
	if err != nil {
		return nil, err
	}
	msg := dialMessage{
		Net:     network,
		Addr:    addr,
		Timeout: timeout,
	}
	if err := sendMessage(stream, &msg); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send dial message failed: %w", err)
	}
	var resp dialResponse
	if err := recvResponse(stream, &resp); err != nil {
		_ = stream.Close()
		return nil, err
	}
	c.exitWG.Add(1)
	return &sshUdpConn{Stream: stream, rAddr: resp.RemoteAddr, client: c}, nil
}

// DialUDP initiates a logical UDP connection to the addr from the remote host
func (c *SshUdpClient) DialUDP(network, addr string, timeout time.Duration) (PacketConn, error) {
	stream, err := c.newStream("dial-udp")
	if err != nil {
		return nil, err
	}

	msg := dialUdpMessage{
		Net:     network,
		Addr:    addr,
		Timeout: timeout,
	}
	if err := sendMessage(stream, &msg); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send dial udp message failed: %w", err)
	}
	var resp dialUdpResponse
	if err := recvResponse(stream, &resp); err != nil {
		_ = stream.Close()
		return nil, err
	}

	conn := newPacketConn(stream, resp.ID, c.protoClient.getUdpForwarder(), c.networkProxy.serverChecker)

	var ok udpReadyMessage
	if err := sendMessage(stream, &ok); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send udp ready message failed: %w", err)
	}

	c.exitWG.Add(1)
	return &sshUdpPacketConn{conn, c}, nil
}

// Listen requests the remote peer open a listening socket on addr
func (c *SshUdpClient) Listen(network, addr string) (net.Listener, error) {
	stream, err := c.newStream("listen")
	if err != nil {
		return nil, err
	}
	msg := listenMessage{
		Net:  network,
		Addr: addr,
	}
	if err := sendMessage(stream, &msg); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send listen message failed: %w", err)
	}
	if err := recvError(stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	c.exitWG.Add(1)
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

// SetKeepPendingInput sets whether to keep the pending input during disconnection.
func (c *SshUdpClient) SetKeepPendingInput(keep bool) error {
	return c.sendBusMessage("setting", settingsMessage{KeepPendingInput: &keep})
}

// SetKeepPendingOutput sets whether to keep the pending output during disconnection.
func (c *SshUdpClient) SetKeepPendingOutput(keep bool) error {
	return c.sendBusMessage("setting", settingsMessage{KeepPendingOutput: &keep})
}

// IsClosed returns whether the client has closed
func (c *SshUdpClient) IsClosed() bool {
	return c.closed.Load()
}

// GetLastActiveTime returns the last confirmed two-way activity time in milliseconds
func (c *SshUdpClient) GetLastActiveTime() int64 {
	return c.activeChecker.getAliveTime()
}

// GetLastReconnectError returns the last error encountered during reconnection attempts
func (c *SshUdpClient) GetLastReconnectError() error {
	client := c
	err := client.reconnectError.Load()
	for client.proxyClient != nil {
		client = client.proxyClient
		if e := client.reconnectError.Load(); e != nil {
			err = e
		}
	}
	if err != nil {
		return *err
	}
	return nil
}

// GetMaxDatagramSize returns the maximum payload size (in bytes) that
// can be sent in a single datagram over this SshUdpClient.
func (c *SshUdpClient) GetMaxDatagramSize() uint16 {
	return c.protoClient.getUdpForwarder().conn.GetMaxDatagramSize()
}

func (c *SshUdpClient) tryToReconnect() {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()

	if c.proxyClient != nil {
		// prioritize allowing the proxy to reconnect first
		time.Sleep(c.proxyClient.intervalTime)

		// wait for the proxy to reconnect first
		if c.proxyClient.activeChecker.isTimeout() {
			if c.proxyClient.activeChecker.waitUntilReconnected() != nil {
				c.debug("proxy server timeout and closed")
				return
			}
		}

		// wait for auto-recovery after proxy reconnection
		time.Sleep(c.intervalTime)
	}

	for c.activeChecker.isTimeout() {
		c.debug("attempting new transport path")
		if err := c.networkProxy.renewTransportPath(c.proxyClient, c.connectTimeout); err != nil {
			c.debug("reconnect failed: %v", err)
			c.reconnectError.Store(&err)
			time.Sleep(c.intervalTime) // don't reconnect too frequently
			continue
		}

		c.debug("new transport path established")
		c.reconnectError.Store(nil)

		// blocks until the server becomes active or a timeout occurs
		for !c.networkProxy.serverChecker.isTimeout() {
			time.Sleep(c.intervalTime)
			if !c.activeChecker.isTimeout() {
				return
			}
		}
	}
}

func (c *SshUdpClient) keepAlive(intervalTime time.Duration) {
	ticker := time.NewTicker(intervalTime)
	defer ticker.Stop()

	for range ticker.C {
		if c.IsClosed() {
			return
		}

		aliveTime := time.Now().UnixMilli()
		if enableDebugLogging && c.activeChecker.isTimeout() {
			c.debug("sending new keep alive [%d]", aliveTime)
		}
		if err := c.sendBusMessage("alive2", aliveMessage{aliveTime}); err != nil {
			if !c.IsClosed() {
				c.warning("send keep alive [%d] failed: %v", aliveTime, err)
			}
		} else if enableDebugLogging && c.activeChecker.isTimeout() {
			c.debug("keep alive [%d] sent success", aliveTime)
		}

		ackTime := <-c.activeAckChan
		c.activeChecker.updateTime(ackTime)
	}
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
			close(c.busClosed)
			return
		}
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
		case "alive1":
			c.handleAlive1Event()
		case "alive2":
			c.handleAlive2Event()
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
	c.exitWG.Done()
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

func (c *SshUdpClient) handleAlive1Event() {
	var aliveMsg aliveMessage
	if err := recvMessage(c.busStream, &aliveMsg); err != nil {
		c.warning("recv alive message failed: %v", err)
		return
	}

	if err := c.sendBusMessage("alive1", aliveMsg); err != nil {
		if !c.IsClosed() {
			c.warning("send alive message failed: %v", err)
		}
	}
}

func (c *SshUdpClient) handleAlive2Event() {
	var aliveMsg aliveMessage
	if err := recvMessage(c.busStream, &aliveMsg); err != nil {
		c.warning("recv alive message failed: %v", err)
		return
	}

	c.activeAckChan <- aliveMsg.Time
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
	exitWG  sync.WaitGroup
	client  *SshUdpClient
	stream  Stream
	pty     bool
	height  int
	width   int
	envs    map[string]string
	started bool
	closed  atomic.Bool
	stdin   *io.PipeReader
	stdout  *io.PipeWriter
	stderr  *io.PipeWriter
	code    int
	x11     *x11Request
	agent   *agentRequest
}

// Wait waits for the remote command to exit
func (s *SshUdpSession) Wait() error {
	s.exitWG.Wait()
	return nil
}

// Close closes the underlying network connection
func (s *SshUdpSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	isExited := func(timeout time.Duration) bool {
		done := make(chan struct{})
		go func() {
			s.exitWG.Wait()
			close(done)
		}()

		select {
		case <-done:
			return true
		case <-time.After(timeout):
			return false
		}
	}

	_, err := doWithTimeout(func() (int, error) {

		if isExited(100 * time.Millisecond) {
			err := s.stream.Close()
			return 0, err
		}

		s.client.debug("requesting exit session [%d]", s.id)
		if err := s.client.sendBusMessage("exit", exitMessage{ID: s.id}); err != nil {
			s.client.debug("exit session [%d] failed: %v", s.id, err)
			err := s.stream.Close()
			return 0, err
		}

		if isExited(350 * time.Millisecond) {
			s.client.debug("exit session [%d] wait completed", s.id)
		}

		err := s.stream.Close()
		return 0, err

	}, 500*time.Millisecond)

	if err != nil {
		s.client.debug("close session [%d] failed: %v", s.id, err)
	} else {
		s.client.debug("close session [%d] completed", s.id)
	}
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
		s.exitWG.Go(func() { s.forwardOutput("stdout", s.stream, s.stdout) })
	}
	return nil
}

func (s *SshUdpSession) forwardInput() {
	defer func() {
		_ = s.stdin.Close()
		if err := s.stream.CloseWrite(); err != nil {
			s.client.debug("session [%d] close write failed: %v", s.id, err)
		}
	}()
	buffer := make([]byte, 32*1024)
	for {
		n, err := s.stdin.Read(buffer)
		if n > 0 {
			if s.client.networkProxy.serverChecker.isTimeout() {
				if s.client.networkProxy.serverChecker.waitUntilReconnected() != nil {
					s.client.debug("session [%d] server timeout and closed", s.id)
					break
				}
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

func (s *SshUdpSession) forwardOutput(name string, reader Stream, writer *io.PipeWriter) {
	defer func() {
		_ = writer.Close()
		_ = reader.CloseRead()
	}()
	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
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
	s.exitWG.Done()
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
	s.exitWG.Go(func() { s.forwardOutput("stderr", stream, s.stderr) })
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
	stream Stream
	closed atomic.Bool
}

func (l *sshUdpListener) Accept() (net.Conn, error) {
	var msg acceptMessage
	if err := recvMessage(l.stream, &msg); err != nil {
		return nil, fmt.Errorf("recv accept message failed: %w", err)
	}
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
	l.client.exitWG.Add(1)
	return &sshUdpConn{Stream: stream, client: l.client}, nil
}

func (l *sshUdpListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := l.stream.Close()
	l.client.exitWG.Done()
	return err
}

func (l *sshUdpListener) Addr() net.Addr {
	return nil
}

type sshUdpConn struct {
	Stream
	rAddr  *net.TCPAddr
	client *SshUdpClient
	closed atomic.Bool
}

func (c *sshUdpConn) Write(buf []byte) (int, error) {
	if c.client.networkProxy.serverChecker.isTimeout() {
		if err := c.client.networkProxy.serverChecker.waitUntilReconnected(); err != nil {
			return 0, fmt.Errorf("server timeout and closed: %v", err)
		}
	}
	return c.Stream.Write(buf)
}

func (c *sshUdpConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := c.Stream.Close()
	c.client.exitWG.Done()
	return err
}

func (c *sshUdpConn) RemoteAddr() net.Addr {
	if c.rAddr != nil {
		return c.rAddr
	}
	return c.Stream.RemoteAddr()
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
	c.client.exitWG.Add(1)
	return &sshUdpChannel{Stream: stream, client: c.client}, nil, nil
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
	Stream
	client *SshUdpClient
	closed atomic.Bool
}

func (c *sshUdpChannel) Write(buf []byte) (int, error) {
	if c.client.networkProxy.serverChecker.isTimeout() {
		if err := c.client.networkProxy.serverChecker.waitUntilReconnected(); err != nil {
			return 0, fmt.Errorf("server timeout and closed: %v", err)
		}
	}
	return c.Stream.Write(buf)
}

func (c *sshUdpChannel) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := c.Stream.Close()
	c.client.exitWG.Done()
	return err
}

func (c *sshUdpChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, fmt.Errorf("ssh udp channel SendRequest is not supported yet")
}

func (c *sshUdpChannel) Stderr() io.ReadWriter {
	c.client.warning("ssh udp channel Stderr is not supported yet")
	return nil
}

type sshUdpPacketConn struct {
	*packetConn
	client *SshUdpClient
}

func (c *sshUdpPacketConn) Close() error {
	err := c.packetConn.Close()
	c.client.exitWG.Done()
	return err
}
