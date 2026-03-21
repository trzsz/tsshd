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
	"sync"
	"sync/atomic"
	"time"
)

var busClosing atomic.Bool
var busClosingMu sync.Mutex
var busClosingWG sync.WaitGroup

func (s *sshUdpServer) sendBusMessage(command string, msg any) error {
	s.busMutex.Lock()
	defer s.busMutex.Unlock()
	if s.busStream == nil {
		return fmt.Errorf("bus stream is nil")
	}
	return sendCommandAndMessage(s.busStream, command, msg)
}

func (s *sshUdpServer) initBusStream(stream Stream) error {
	s.busMutex.Lock()
	defer s.busMutex.Unlock()

	// only one bus
	if s.busStream != nil {
		return fmt.Errorf("bus has been initialized")
	}

	s.busStream = stream
	return nil
}

func (s *sshUdpServer) handleBusEvent(stream Stream) {
	var msg busMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv bus message failed: %v", err))
		return
	}

	ver, err := parseTsshdVersion(msg.ClientVer)
	if err != nil {
		sendError(stream, fmt.Errorf("tsshd version invalid: %v", err))
		return
	}
	if ver.compare(&tsshdVersion{0, 1, 6}) < 0 {
		sendError(stream, fmt.Errorf("please upgrade tssh to continue"))
		return
	}

	if err := s.initBusStream(stream); err != nil {
		sendError(stream, err)
		return
	}

	s.initClientChecker(msg.HeartbeatTimeout)
	s.clientAliveTime.addMilli(time.Now().UnixMilli())
	s.aliveTimeout, s.intervalTime = msg.AliveTimeout, msg.IntervalTime

	if err := s.activateServer(); err != nil {
		sendError(stream, err)
		return
	}

	if err := sendResponse(stream, &busResponse{NextSessionID: maxSessionID.Load() + 1}); err != nil { // ack ok
		warning("send bus response failed: %v", err)
		return
	}

	intervalTimeMilli := int64(msg.IntervalTime / time.Millisecond)
	heartbeatTimeoutMilli := int64(msg.HeartbeatTimeout / time.Millisecond)

	for {
		command, err := recvCommand(stream)
		if err != nil {
			if isClosedError(err) {
				return
			}
			warning("recv bus command failed: %v", err)
			return
		}

		if server := activeSshUdpServer.Load(); server != s {
			if enableDebugLogging {
				_ = s.sendBusMessage("debug", debugMessage{Msg: "server instance is no longer active", Time: time.Now().UnixMilli()})
			}
			return
		}

		switch command {
		case "exit": // close a session
			err = s.handleExitEvent(stream)
		case "resize": // resize a session
			err = s.handleResizeEvent(stream)
		case "close": // close bus and exit tsshd
			s.handleCloseEvent()
			return // return will close the bus stream
		case "alive":
			err = s.handleAliveEvent(stream, heartbeatTimeoutMilli, intervalTimeMilli)
		case "setting":
			err = s.handleSettingEvent(stream)
		case "rekey":
			err = s.handleRekeyEvent(stream)
		default:
			if err := handleUnknownEvent(stream, command); err != nil {
				warning("handle bus command [%s] failed: %v. You may need to upgrade tsshd.", command, err)
			}
		}
		if err != nil {
			warning("handle bus command [%s] failed: %v", command, err)
		}
	}
}

func (s *sshUdpServer) handleExitEvent(stream Stream) error {
	var exitMsg exitMessage
	if err := recvMessage(stream, &exitMsg); err != nil {
		return fmt.Errorf("recv exit message failed: %v", err)
	}
	closeSession(exitMsg.ID)
	return nil
}

func (s *sshUdpServer) handleCloseEvent() {
	closeAllSessions()
	debug("close bus and exit tsshd")

	busClosingMu.Lock()
	busClosing.Store(true)
	if debugMsgChan != nil {
		close(debugMsgChan)
	}
	if warningMsgChan != nil {
		close(warningMsgChan)
	}
	busClosingMu.Unlock()

	busClosingWG.Wait()

	go func() {
		time.Sleep(200 * time.Millisecond) // give udp some time
		exitWithCode(kExitCodeNormal)
	}()
}

func (s *sshUdpServer) handleAliveEvent(stream Stream, heartbeatTimeoutMilli, intervalTimeMilli int64) error {
	var msg aliveMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv alive message failed: %v", err)
	}

	now := time.Now().UnixMilli()

	// If the time since the last recorded activity exceeds heartbeatTimeout,
	// it indicates that the client was previously disconnected and has now reconnected.
	// Set the flag to clear the packet cache after the client stabilizes.
	if now-s.clientAliveTime.latest() > heartbeatTimeoutMilli {
		if enableDebugLogging {
			debug("keep alive [%d] received: reconnected=%v, elapsed=%v", msg.Time, true,
				time.Duration(now-s.clientAliveTime.latest())*time.Millisecond)
		}
		s.pendingClearPktCache = true
	} else if enableDebugLogging && s.pendingClearPktCache {
		debug("keep alive [%d] received: stabilizing=%v, interval=%v", msg.Time, s.pendingClearPktCache,
			time.Duration(now-s.clientAliveTime.latest())*time.Millisecond)
	}

	s.clientAliveTime.addMilli(now)

	if s.pendingClearPktCache {
		// If the client has remained active for a sufficient number of intervals,
		// consider the connection stable and clear the packet cache.
		if now-s.clientAliveTime.oldest() < (kAliveTimeCap+1)*intervalTimeMilli {
			totalSize, totalCount := s.client.pktCache.clearCache()
			if enableDebugLogging && (totalSize > 0 || totalCount > 0) {
				debug("drop packet cache count [%d] size [%d]", totalCount, totalSize)
			}
			s.pendingClearPktCache = false
		}
	}

	return s.sendBusMessage("alive", msg)
}

func (s *sshUdpServer) handleSettingEvent(stream Stream) error {
	var msg settingsMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv settings message failed: %v", err)
	}
	if msg.KeepPendingInput != nil {
		s.keepPendingInput.Store(*msg.KeepPendingInput)
	}
	if msg.KeepPendingOutput != nil {
		s.keepPendingOutput.Store(*msg.KeepPendingOutput)
	}
	return nil
}

func (s *sshUdpServer) handleRekeyEvent(stream Stream) error {
	var msg rekeyMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv rekey message failed: %v", err)
	}

	if s.client.kcpCrypto == nil {
		return fmt.Errorf("rekey failed: crypto is nil")
	}
	if err := s.client.kcpCrypto.handleServerRekey(s, &msg); err != nil {
		return fmt.Errorf("rekey failed: %v", err)
	}

	return nil
}

func handleUnknownEvent(stream Stream, command string) error {
	var msg struct{}
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv message for unknown command [%s] failed: %v", command, err)
	}
	return fmt.Errorf("unknown command: %s", command)
}
