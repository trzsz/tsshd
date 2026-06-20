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
	// Synchronize with bus stream initialization before accessing it.
	// A mutex is used instead of an atomic pointer to avoid polling or
	// sleeping while waiting for the bus stream to become available.
	//
	// Do not hold the lock during the write operation, since writes may
	// block and unnecessarily prevent other goroutines from accessing
	// the bus stream state.
	s.busMutex.Lock()
	busStream := s.busStream
	s.busMutex.Unlock()

	if busStream == nil {
		return fmt.Errorf("bus stream is nil")
	}

	// sendCommandAndMessage assembles the command and payload into a
	// single buffer before writing, making the transmission atomic at
	// the stream level.
	return sendCommandAndMessage(busStream, command, msg)
}

func (s *sshUdpServer) initBusAndServer(stream Stream, msg *busMessage) error {
	s.busMutex.Lock()
	defer s.busMutex.Unlock()

	// only one bus
	if s.busStream != nil {
		return fmt.Errorf("bus has been initialized")
	}

	s.initClientChecker(msg.HeartbeatTimeout)
	s.clientAliveTime.Store(time.Now().UnixMilli())
	s.aliveTimeout, s.intervalTime = msg.AliveTimeout, msg.IntervalTime

	if err := s.activateServer(msg.SessionName); err != nil {
		return err
	}

	if err := sendResponse(stream, &busResponse{NextSessionID: maxSessionID.Load() + 1}); err != nil { // ack ok
		warning("send bus response failed: %v", err)
		// Return nil to avoid redundant error response, but s.busStream remains nil
		return nil
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

	if msg.ProtoVer == 0 {
		ver, err := parseTsshdVersion(msg.ClientVer)
		if err != nil {
			sendError(stream, fmt.Errorf("tsshd version invalid: %v", err))
			return
		}
		if ver.compare(&tsshdVersion{0, 1, 6}) < 0 {
			sendError(stream, fmt.Errorf("please upgrade tssh to continue"))
			return
		}
	}

	if err := s.initBusAndServer(stream, &msg); err != nil {
		sendError(stream, err)
		return
	}
	if s.busStream == nil { // ACK failed, bus remains uninitialized
		return
	}

	if enableDebugLogging {
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for range ticker.C {
				if s.closed.Load() {
					return
				}
				if s.client.udpTraffic.recFlag.Load() {
					if msg := s.client.udpTraffic.flushLog(); msg != "" {
						debug("client [%x] %s", s.client.proxyAddr.clientID, msg)
					}
				}
			}
		}()
	}

	heartbeatCount := kHeartbeatInitCount

	for {
		command, err := recvCommand(stream)
		if err != nil {
			if IsClosedError(err) {
				return
			}
			warning("recv bus command failed: %v", err)
			return
		}

		if server := activeSshUdpServer.Load(); server != s {
			if enableDebugLogging {
				if err := s.sendBusMessage("debug",
					debugMessage{Msg: "server instance is no longer active", Time: time.Now().UnixMilli()}); err != nil {
					debug("send debug message failed: %v", err)
				}
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
			err = s.handleAliveEvent(stream, msg.HeartbeatTimeout, &heartbeatCount)
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
	if busClosing.CompareAndSwap(false, true) {
		if debugMsgChan != nil {
			close(debugMsgChan)
		}
		if warningMsgChan != nil {
			close(warningMsgChan)
		}
	}
	busClosingMu.Unlock()

	_, _ = doWithTimeout(func() (int, error) { busClosingWG.Wait(); return 0, nil }, time.Second)

	if enableWarningLogging || enableDebugLogging {
		// Give warning and debug logs some time to be delivered to the client.
		time.Sleep(time.Second)
	}
	exitWithCode(kExitCodeNormal)
}

func (s *sshUdpServer) handleAliveEvent(stream Stream, heartbeatTimeout time.Duration, heartbeatCount *uint64) error {
	var msg aliveMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv alive message failed: %v", err)
	}

	now := time.Now().UnixMilli()

	if enableDebugLogging {
		elapsed := time.Duration(now-s.clientAliveTime.Load()) * time.Millisecond
		// If the time since the last recorded activity exceeds heartbeatTimeout,
		// it indicates that the client was previously disconnected and has now reconnected.
		reconnect := elapsed > heartbeatTimeout
		if reconnect {
			*heartbeatCount = 0
		}
		if reconnect || *heartbeatCount <= kHeartbeatLogLimit {
			debug("keep alive [%d] received: reconnect=%v, heartbeat=%d, elapsed=%v", msg.Time, reconnect, *heartbeatCount, elapsed)
		}
		(*heartbeatCount)++
	}

	s.clientAliveTime.Store(now)

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

	var kcpCrypto *rotatingCrypto
	if s.args.Attachable {
		kcpCrypto = s.client.kcpCrypto.Load()
	} else {
		kcpCrypto = s.proxy.kcpCrypto
	}
	if kcpCrypto == nil {
		return fmt.Errorf("rekey failed: crypto is nil")
	}
	if err := kcpCrypto.handleServerRekey(s, &msg); err != nil {
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
