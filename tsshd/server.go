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
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var activeSshUdpServer atomic.Pointer[sshUdpServer]

var errServerClosed = errors.New("server is closed")

type streamHandler interface {
	handleStream(stream Stream)
}

type clientPathExpiry struct {
	aliveTime int64
	deadline  time.Time
	cleanup   func(string)
}

type sshUdpServer struct {
	args   *tsshdArgs
	client *clientState
	proxy  *serverProxy
	proto  protocolServer
	closed atomic.Bool

	nextStreamID atomic.Uint64
	streamMutex  sync.Mutex
	streamMap    map[uint64]Stream

	// timeout related
	aliveTimeout  time.Duration
	intervalTime  time.Duration
	clientChecker *timeoutChecker

	activationMutex sync.Mutex

	// bus related
	serving   atomic.Bool
	busMutex  sync.Mutex
	busStream Stream

	// clientAliveTime records the last time the server received a heartbeat from the client
	// over the KCP/QUIC stream. It is not updated by arbitrary incoming UDP datagrams.
	clientAliveTime atomic.Int64

	// pendingPathExpiry tracks a pending expiration of the proxy-side client path.
	// It is accessed only by the server liveness monitor.
	pendingPathExpiry *clientPathExpiry

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

	// Cleanup functions for resources owned by this server.
	cleanupMutex  sync.Mutex
	cleanupFuncs  map[uint64]func()
	nextCleanupID uint64
}

var newSshUdpServer = func(args *tsshdArgs, proxy *serverProxy, addr net.Addr, proto protocolServer) streamHandler {
	clientAddr, ok := addr.(*proxyClientAddr)
	if !ok {
		warning("new server failed: invalid client address type: %T", addr)
		return nil
	}

	client := proxy.getClient(clientAddr.clientID)
	if client == nil {
		warning("new server failed: no client found for id: %x", clientAddr.clientID)
		return nil
	}
	if client.closed.Load() {
		warning("new server failed: client [%x] is closed", clientAddr.clientID)
		return nil
	}

	// A client is allowed to bind to only one server instance.
	// Re-binding is not allowed even after the server is closed and cleared.
	if !client.sealed.CompareAndSwap(false, true) {
		warning("new server failed: client [%x] has already been sealed", clientAddr.clientID)
		return nil
	}

	server := &sshUdpServer{args: args, client: client, proxy: proxy, proto: proto,
		streamMap: make(map[uint64]Stream),
	}

	// close the server if it does not enter the serving state within connect timeout.
	time.AfterFunc(args.ConnectTimeout, func() { server.closeServer(true) })

	return server
}

func (s *sshUdpServer) initClientChecker(timeout time.Duration) error {
	s.activationMutex.Lock()
	defer s.activationMutex.Unlock()

	if s.closed.Load() {
		return errServerClosed
	}
	if s.clientChecker != nil {
		return errors.New("client checker has already been initialized")
	}

	s.clientChecker = newTimeoutChecker(timeout)

	if enableDebugLogging.Load() {
		s.clientChecker.onTimeout(func() {
			debug("blocked due to no client [%x] input for [%v]", s.client.proxyAddr.clientID, s.clientChecker.heartbeatTimeout)
			if traffic := s.client.udpTraffic.Load(); traffic != nil && !traffic.recFlag.Load() {
				traffic.resetStats()
				traffic.recFlag.Store(true)
			}
		})
		s.clientChecker.onReconnected(func() {
			debug("resumed after receiving client [%x] input", s.client.proxyAddr.clientID)
			time.AfterFunc(10*time.Second, func() {
				if !s.clientChecker.isTimeout() {
					if traffic := s.client.udpTraffic.Load(); traffic != nil {
						traffic.recFlag.Store(false)
					}
				}
			})
		})
	}

	s.clientChecker.onTimeout(func() {
		// Clear the proxy-side client path when no UDP packets are received,
		// to prevent another peer from inheriting the client's authentication
		// if its NAT mapping expires.
		cleanup := s.captureClientPathCleanup()
		if cleanup == nil {
			return
		}

		// A reconnect may happen concurrently with this timeout callback.
		// The transport loaded above may already belong to the new connection.
		//
		// Wait one heartbeat interval so the checker can observe the reconnect
		// and clear the timeout state. If the timeout has been cleared, this is
		// a stale timeout event and should not remove any transport.
		//
		// The CAS-based cleanup below ensures that only the transport observed
		// above is removed, even if another reconnect occurs while waiting.
		time.Sleep(s.clientChecker.heartbeatTimeout)
		if !s.clientChecker.isTimeout() {
			return
		}

		// Remove the old authenticated path so a new owner of the same NAT
		// endpoint cannot inherit the client's authentication.
		cleanup("no UDP packets received")
	})

	// Notify all sessions currently attached to this server when the client
	// connection is re-established.
	s.clientChecker.onReconnected(func() {
		// Serialize with session attach/detach operations so that session ownership
		// cannot change between checking sess.server and notifying the session.
		attachMutex.Lock()
		defer attachMutex.Unlock()

		for _, sess := range getAllSessions() {
			if sess.server.Load() != s {
				// Skip sessions that are not owned by the current server.
				continue
			}
			// Notify the session while its ownership is guaranteed to remain
			// unchanged by attach/detach operations.
			go sess.onReconnected()
		}
	})

	return nil
}

func (s *sshUdpServer) activateServer(sessionName string) error {
	debug("client [%x] starting server activation", s.client.proxyAddr.clientID)

	if s.args.Attachable {
		// Serialize server activation with session attach/detach operations.
		// This ensures the active server transition and cleanup of sessions
		// owned by the previous server happen atomically.
		attachMutex.Lock()
		defer attachMutex.Unlock()
	}

	s.activationMutex.Lock()
	defer s.activationMutex.Unlock()

	if s.closed.Load() {
		return errServerClosed
	}

	if !s.args.Attachable {
		if !activeSshUdpServer.CompareAndSwap(nil, s) {
			return errors.New("active server is already in use")
		}
		s.client.server.Store(s)
		s.serving.Store(true)
		return nil
	}

	if busClosing.Load() {
		return errors.New("bus is closed")
	}

	oldServer := activeSshUdpServer.Swap(s)

	// Preserve the session name from the initial connection.
	// Later attaches do not overwrite it.
	if oldServer == nil && globalSocketInfo != nil {
		globalSocketInfo.sessionName = sessionName
	}

	s.detachAllSessions(oldServer)

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
				if _, err := doWithTimeout(func() (int, error) {
					return 0, oldServer.sendBusMessage("quit",
						quitMessage{fmt.Sprintf("another client attached from %s", s.client.remoteAddr())})
				}, time.Second); err != nil {
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
	s.closeServer(false)
}

func (s *sshUdpServer) closeServer(onlyIfNotServing bool) {
	s.activationMutex.Lock()

	if onlyIfNotServing && s.serving.Load() {
		s.activationMutex.Unlock()
		return
	}

	if !s.closed.CompareAndSwap(false, true) {
		s.activationMutex.Unlock()
		return
	}

	checker := s.clientChecker

	s.activationMutex.Unlock()

	if onlyIfNotServing {
		debug("client [%x] bus initialization timed out after %v", s.client.proxyAddr.clientID, s.args.ConnectTimeout)
	} else {
		debug("client [%x] shutting down server", s.client.proxyAddr.clientID)
	}

	s.runCleanupFuncs()

	// Stop accepting new streams and collect all currently active streams.
	streams := s.collectActiveStreams()

	// Stop the client checker and its background goroutines.
	//
	// The client checker is created during bus initialization, so it is nil
	// if the server is closed before the client has initialized the bus,
	// e.g. on connect timeout.
	if checker != nil {
		checker.Close()
	}

	// Best-effort shutdown of the bus stream.
	//
	// Avoid acquiring busMutex here. During shutdown, it is more important
	// to make forward progress than to wait for a potentially blocked
	// goroutine holding the lock. Missing this close is acceptable because
	// connection teardown will eventually release resources.
	if busStream := s.busStream; busStream != nil {
		_, err := doWithTimeout(func() (int, error) { return 0, busStream.Close() }, time.Second)
		debug("client [%x] bus stream closed: %v", s.client.proxyAddr.clientID, err)
	}

	// Unblock stderr handler goroutines waiting in stderrStream.Wait
	// so they can return and be cleaned up during server shutdown.
	s.closeAllStderrStreams()

	// Give all streams a short chance to close gracefully before shutting
	// down the transport. If this times out, the cleanup goroutine continues
	// in the background and the transport shutdown below must unblock it.
	_, err := doWithTimeout(func() (int, error) {
		for _, entry := range streams {
			err := entry.stream.Close()
			debug("active stream [%x][%d] closed: %v", s.client.proxyAddr.clientID, entry.id, err)
		}

		debug("client [%x] all stream close calls completed", s.client.proxyAddr.clientID)
		return 0, nil
	}, time.Second)
	if err != nil {
		debug("client [%x] stream shutdown timed out: %v", s.client.proxyAddr.clientID, err)
	}

	// Close the transport to interrupt any remaining stream operations.
	err = s.proto.Close()
	debug("client [%x] transport closed: %v", s.client.proxyAddr.clientID, err)

	// The clientState is kept in memory to prevent replay attacks.
	s.client.Close()
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
		// Usually, CloseWrite has already been called, allowing the client to receive EOF.
		// If we call Close immediately, the underlying QUIC/KCP layer might discard
		// in-flight data that hasn't been received by the client yet.
		// We delay the final closure to provide a grace period for the transport layer
		// to complete data delivery, especially during connection roaming or high latency.
		for range 60 {
			// The client checker is only available once the bus has been initialized.
			// Streams opened before that have no reconnection to wait for.
			if s.serving.Load() && s.clientChecker.isTimeout() {
				// Wait for potential reconnection to ensure the last packets can be delivered.
				_ = s.clientChecker.waitUntilReconnected()
			}
			if s.closed.Load() {
				// If the server is shutting down, it handles cleaning up all active streams.
				return
			}
			time.Sleep(time.Second)
		}

		s.streamMutex.Lock()
		delete(s.streamMap, id)
		s.streamMutex.Unlock()

		err := stream.Close()
		debug("stream [%x][%d] closed: %v", s.client.proxyAddr.clientID, id, err)
	}()

	// read initial command
	command, err := recvCommand(stream)
	if err != nil {
		sendError(stream, fmt.Errorf("recv stream command failed: %v", err))
		return
	}

	if enableDebugLogging.Load() && command != "dial" && command != "accept" && command != "dial-udp" && command != "accept-udp" {
		debug("stream [%x][%d] command [%s] starts", s.client.proxyAddr.clientID, id, command)
		defer debug("stream [%x][%d] command [%s] closing", s.client.proxyAddr.clientID, id, command)
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
			sendError(stream, errors.New("bus must be initialized first"))
			return
		}
		if server := activeSshUdpServer.Load(); server != s {
			sendError(stream, errors.New("not the active server instance"))
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

type streamEntry struct {
	id     uint64
	stream Stream
}

// collectActiveStreams returns all currently registered streams and prevents
// subsequent streams from being registered.
func (s *sshUdpServer) collectActiveStreams() []streamEntry {
	s.streamMutex.Lock()
	defer s.streamMutex.Unlock()

	if s.streamMap == nil {
		return nil
	}

	streams := make([]streamEntry, 0, len(s.streamMap))
	for id, stream := range s.streamMap {
		streams = append(streams, streamEntry{id, stream})
	}

	s.streamMap = nil // mark the server as shutting down so no new streams are accepted.

	return streams
}

func (s *sshUdpServer) closeActiveStreams() {
	for _, entry := range s.collectActiveStreams() {
		_, err := doWithTimeout(func() (int, error) { return 0, entry.stream.Close() }, time.Second)
		debug("active stream [%x][%d] closed: %v", s.client.proxyAddr.clientID, entry.id, err)
	}
}

func (s *sshUdpServer) isClientAlive() bool {
	if !s.serving.Load() {
		return false
	}

	return time.Since(time.UnixMilli(s.clientAliveTime.Load())) < s.clientChecker.heartbeatTimeout
}

func (s *sshUdpServer) captureClientPathCleanup() func(reason string) {
	oldAuthedPath := s.client.authedPath.Load()
	oldClientPath := s.client.clientPath.Load()
	oldClientConn := s.client.clientConn.Load()

	if oldAuthedPath == nil && oldClientPath == nil && oldClientConn == nil {
		return nil
	}

	return func(reason string) {
		if oldAuthedPath != nil && oldAuthedPath == s.client.authedPath.Load() {
			debug("client [%x] clearing authed path due to %s", s.client.proxyAddr.clientID, reason)
			s.client.setAuthedPath(oldAuthedPath, nil)
		}
		if oldClientPath != nil && oldClientPath == s.client.clientPath.Load() {
			debug("client [%x] clearing client path due to %s", s.client.proxyAddr.clientID, reason)
			s.client.setClientPath(oldClientPath, nil)
		}
		if oldClientConn != nil && oldClientConn == s.client.clientConn.Load() {
			debug("client [%x] clearing client conn due to %s", s.client.proxyAddr.clientID, reason)
			s.client.setClientConn(oldClientConn, nil)
		}
	}
}

// expireInactiveClientPath expires the proxy-side client path if no heartbeat
// has been received over the KCP/QUIC stream for a prolonged period.
//
// The proxy's client checker only tracks incoming UDP datagrams. Spoofed
// UDP datagrams can keep it alive without producing valid KCP/QUIC stream
// heartbeats. Meanwhile, the legitimate client's NAT mapping may expire,
// allowing its public UDP endpoint (IP:port) to be reassigned to another
// peer. If the old authenticated endpoint is retained, the new owner may
// be treated as the authenticated client by the proxy, causing server
// replies to be sent to the wrong peer.
//
// Tracking clientAliveTime independently prevents spoofed UDP datagrams
// from indefinitely extending the lifetime of the proxy-side client path.
func (s *sshUdpServer) expireInactiveClientPath() {
	if !s.serving.Load() || s.clientChecker.heartbeatTimeout <= 0 {
		return
	}

	now := time.Now()
	aliveTime := s.clientAliveTime.Load()
	timeout := 3 * s.clientChecker.heartbeatTimeout

	if now.Sub(time.UnixMilli(aliveTime)) <= timeout {
		s.pendingPathExpiry = nil
		return
	}

	state := s.pendingPathExpiry
	if state == nil || state.aliveTime != aliveTime {
		cleanup := s.captureClientPathCleanup()
		if cleanup == nil {
			s.pendingPathExpiry = nil
			return
		}

		s.pendingPathExpiry = &clientPathExpiry{
			aliveTime: aliveTime,
			deadline:  now.Add(timeout),
			cleanup:   cleanup,
		}
		return
	}

	if now.Before(state.deadline) {
		return
	}

	// Only expire the path if the transport has remained inactive.
	if s.clientAliveTime.Load() == aliveTime {
		// Clear the authenticated path so another peer cannot inherit the client's
		// authentication after its NAT mapping expires, even if spoofed UDP datagrams
		// keep the client checker alive.
		state.cleanup("no stream heartbeat received")
	}

	s.pendingPathExpiry = nil
}

func (s *sshUdpServer) addCleanupFunc(fn func()) func() {
	s.cleanupMutex.Lock()

	if s.closed.Load() {
		s.cleanupMutex.Unlock()
		fn()
		return func() {}
	}

	if s.cleanupFuncs == nil {
		s.cleanupFuncs = make(map[uint64]func())
	}

	s.nextCleanupID++
	id := s.nextCleanupID
	s.cleanupFuncs[id] = fn

	s.cleanupMutex.Unlock()

	return func() {
		s.cleanupMutex.Lock()
		if s.cleanupFuncs == nil {
			s.cleanupMutex.Unlock()
			return
		}

		_, exists := s.cleanupFuncs[id]
		if exists {
			delete(s.cleanupFuncs, id)
		}
		s.cleanupMutex.Unlock()

		if exists {
			fn()
		}
	}
}

func (s *sshUdpServer) runCleanupFuncs() {
	s.cleanupMutex.Lock()

	funcs := s.cleanupFuncs
	s.cleanupFuncs = nil

	s.cleanupMutex.Unlock()

	for _, fn := range funcs {
		fn()
	}
}
