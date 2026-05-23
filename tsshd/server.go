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
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var activeSshUdpServer atomic.Pointer[sshUdpServer]

type streamHandler interface {
	handleStream(stream Stream)
}

type sshUdpServer struct {
	args   *tsshdArgs
	client *clientState
	proto  protocolServer
	closed atomic.Bool

	nextStreamID atomic.Uint64
	streamMutex  sync.Mutex
	streamMap    map[uint64]Stream

	// timeout related
	aliveTimeout  time.Duration
	intervalTime  time.Duration
	clientChecker *timeoutChecker

	// bus related
	serving              atomic.Bool
	busMutex             sync.Mutex
	busStream            Stream
	clientAliveTime      aliveTime
	pendingClearPktCache bool
	shouldSample         atomic.Bool

	// session related
	stderrMutex       sync.Mutex
	stderrMap         map[uint64]*stderrStream
	keepPendingInput  atomic.Bool
	keepPendingOutput atomic.Bool

	// TCP forwarding
	nextFwdAcceptID atomic.Uint64
	fwdAcceptMutex  sync.Mutex
	fwdAcceptMap    map[uint64]net.Conn

	// UDP forwarding
	nextUdpFwdChannelID  atomic.Uint64
	nextUdpFwdListenerID atomic.Uint64
	udpFwdSessionMutex   sync.Mutex
	udpFwdSessionMap     map[string]*udpForwardSession
	udpFwdPendingMutex   sync.Mutex
	udpFwdPendingMap     map[uint64]*udpForwardSession
}

var newSshUdpServer = func(args *tsshdArgs, proxy *serverProxy, addr net.Addr, proto protocolServer) streamHandler {
	clientAddr, ok := addr.(*proxyClientAddr)
	if !ok {
		warning("invalid client address type: %T", addr)
		return nil
	}

	client := proxy.getClient(clientAddr.clientID)
	if client == nil {
		warning("no client found for id: %x", clientAddr.clientID)
		return nil
	}

	// A client is allowed to bind to only one server instance.
	// Re-binding is not allowed even after the server is closed and cleared.
	if !client.sealed.CompareAndSwap(false, true) {
		warning("client [%x] has already been sealed", clientAddr.clientID)
		return nil
	}

	server := &sshUdpServer{args: args, client: client, proto: proto,
		streamMap: make(map[uint64]Stream),
	}

	go func() {
		// close the server if it does not enter the serving state within connect timeout.
		time.Sleep(args.ConnectTimeout)
		if !server.serving.Load() {
			server.Close()
		}
	}()

	return server
}

func (s *sshUdpServer) initClientChecker(timeout time.Duration) {
	s.clientChecker = newTimeoutChecker(timeout)

	if enableDebugLogging {
		s.clientChecker.onTimeout(func() {
			debug("blocked due to no client [%x] input for [%v]", s.client.proxyAddr.clientID, s.clientChecker.heartbeatTimeout)
		})
		s.clientChecker.onReconnected(func() {
			debug("resumed after receiving client [%x] input", s.client.proxyAddr.clientID)
		})
	}

	s.clientChecker.onTimeout(func() {
		// Clear authenticated UDP client addresses to prevent the UDP endpoint
		// from being reused by another peer after timeout.
		s.client.setAuthedAddr(nil)
		s.client.setClientAddr(nil)
		// Also proactively close the TCP connection to ensure it cannot be
		// reused or remain in a half-open state after the client times out.
		if conn := s.client.clientConn.Swap(nil); conn != nil {
			_ = conn.Close()
		}
		debug("client [%x] transport cleared due to timeout", s.client.proxyAddr.clientID)
	})
}

func (s *sshUdpServer) activateServer(sessionName string) error {
	if !s.args.Attachable {
		if !activeSshUdpServer.CompareAndSwap(nil, s) {
			return fmt.Errorf("active server is already in use")
		}
		s.client.server.Store(s)
		s.serving.Store(true)
		return nil
	}

	attachMutex.Lock()
	defer attachMutex.Unlock()

	if busClosing.Load() {
		return fmt.Errorf("bus is closed")
	}

	oldServer := activeSshUdpServer.Swap(s)

	// Preserve the session name from the initial connection.
	// Later attaches do not overwrite it.
	if oldServer == nil && globalSocketInfo != nil {
		globalSocketInfo.sessionName = sessionName
	}

	s.detachAllSessions()

	if oldServer != nil {
		go func() {
			// Close all active streams of the old client first.
			// This prevents the session on the target host (behind a ProxyJump)
			// from exiting unexpectedly while the old client is still connected.
			oldServer.closeActiveStreams()

			if oldServer.clientChecker.isTimeout() {
				oldServer.Close()
			} else {
				debug("new client [%x] notifying old client [%x] to quit", s.client.proxyAddr.clientID, oldServer.client.proxyAddr.clientID)
				if err := oldServer.sendBusMessage("quit",
					quitMessage{fmt.Sprintf("another client attached from %s", s.client.remoteAddr())}); err != nil {
					debug("send quit message failed: %v", err)
				}
				time.Sleep(time.Second) // give udp some time
				oldServer.Close()
			}
		}()
	}

	s.client.server.Store(s)
	s.serving.Store(true)
	return nil
}

func (s *sshUdpServer) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}

	// close bus
	s.busMutex.Lock()
	if s.busStream != nil {
		_ = s.busStream.Close()
	}
	s.busMutex.Unlock()

	// Ensure all active streams are closed.
	// closeActiveStreams is idempotent and safe to call multiple times.
	s.closeActiveStreams()

	// close server connection
	_ = s.proto.closeServer()

	// Release the server reference.
	// The clientState is kept in memory to prevent replay attacks.
	s.client.server.Store(nil)
}

// handlerFunc defines the signature for stream handlers.
type handlerFunc func(*sshUdpServer, Stream)

// baseHandlers contains handlers for core stream types.
var baseHandlers = map[string]handlerFunc{
	"bus":     (*sshUdpServer).handleBusEvent,
	"session": (*sshUdpServer).handleSessionEvent,
	"stderr":  (*sshUdpServer).handleStderrEvent,
}

// forwardHandlers contains handlers for port forwarding related streams.
var forwardHandlers = map[string]handlerFunc{
	"dial":       (*sshUdpServer).handleDialEvent,
	"listen":     (*sshUdpServer).handleListenEvent,
	"accept":     (*sshUdpServer).handleAcceptEvent,
	"dial-udp":   (*sshUdpServer).handleDialUdpEvent,
	"listen-udp": (*sshUdpServer).handleListenUdpEvent,
	"accept-udp": (*sshUdpServer).handleAcceptUdpEvent,
}

func (s *sshUdpServer) handleStream(stream Stream) {
	// register stream with closed check
	s.streamMutex.Lock()
	if s.streamMap == nil { // nil indicates the server is shutting down and no longer accepting new streams.
		s.streamMutex.Unlock()
		_ = stream.Close()
		return
	}
	id := s.nextStreamID.Add(1)
	s.streamMap[id] = stream
	s.streamMutex.Unlock()

	// unregister stream on return
	defer func() {
		s.streamMutex.Lock()
		delete(s.streamMap, id)
		s.streamMutex.Unlock()
		_ = stream.Close()
	}()

	// read initial command
	command, err := recvCommand(stream)
	if err != nil {
		sendError(stream, fmt.Errorf("recv stream command failed: %v", err))
		return
	}

	if enableDebugLogging && command != "dial" && command != "accept" && command != "dial-udp" && command != "accept-udp" {
		debug("stream [%x][%d] command [%s] starts", s.client.proxyAddr.clientID, id, command)
		defer debug("stream [%x][%d] command [%s] closes", s.client.proxyAddr.clientID, id, command)
	}

	// NOTE: In attachable mode, multiple servers may coexist.
	if command == "bus" {
		// Only one bus stream is allowed per server (checked in handleBusEvent).
		// The bus stream is treated specially and is closed after all other streams.
		s.streamMutex.Lock()
		delete(s.streamMap, id)
		s.streamMutex.Unlock()
	} else {
		// Other streams require bus initialization and that this server is the active instance.
		if !s.serving.Load() {
			sendError(stream, fmt.Errorf("bus must be initialized first"))
			return
		}
		if server := activeSshUdpServer.Load(); server != s {
			sendError(stream, fmt.Errorf("not the active server instance"))
			return
		}
	}

	// dispatch handler
	var handler handlerFunc
	if h, ok := baseHandlers[command]; ok {
		handler = h
	} else if h, ok := forwardHandlers[command]; ok {
		if !enableForwardings {
			sendError(stream, fmt.Errorf("port forwarding is not enabled: %s", command))
			return
		}
		handler = h
	} else {
		sendError(stream, fmt.Errorf("unknown stream command: %s", command))
		return
	}

	// handshake before processing
	if err := sendSuccess(stream); err != nil { // say hello
		warning("tsshd say hello failed: %v", err)
		return
	}

	handler(s, stream)
}

func (s *sshUdpServer) closeActiveStreams() {
	s.streamMutex.Lock()

	if s.streamMap == nil {
		s.streamMutex.Unlock()
		return
	}

	entries := make([]struct {
		id     uint64
		stream Stream
	}, 0, len(s.streamMap))

	for id, stream := range s.streamMap {
		entries = append(entries, struct {
			id     uint64
			stream Stream
		}{id: id, stream: stream})
	}

	s.streamMap = nil // mark the server as shutting down so no new streams are accepted.

	s.streamMutex.Unlock()

	for _, entry := range entries {
		debug("server shutdown closing stream [%x][%d]", s.client.proxyAddr.clientID, entry.id)
		_ = entry.stream.Close()
	}
}
