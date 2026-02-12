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
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var serving atomic.Bool

var busStream Stream
var busMu sync.Mutex
var activeBusForwarder *udpForwarder

var busClosing atomic.Bool
var busClosingMu sync.Mutex
var busClosingWG sync.WaitGroup

var keepAliveMu sync.Mutex
var keepAliveCancel context.CancelFunc

var clientAliveTime aliveTime
var pendingClearPktCache bool

func sendBusMessage(command string, msg any) error {
	busMu.Lock()
	defer busMu.Unlock()
	if busStream == nil {
		return fmt.Errorf("bus stream is nil")
	}
	return sendCommandAndMessage(busStream, command, msg)
}

func initBusStream(stream Stream, forwarder *udpForwarder) error {
	busMu.Lock()
	oldStream := busStream

	if oldStream != nil && !globalServerProxy.args.Reconnect {
		busMu.Unlock()
		return fmt.Errorf("client reconnection not enabled (use --reconnect to allow)")
	}

	// Update clientAliveTime immediately to prevent the old keepAlive
	// goroutine from timing out during reconnection handshake.
	clientAliveTime.addMilli(time.Now().UnixMilli())

	busStream = stream
	activeBusForwarder = forwarder
	busMu.Unlock()

	// Close the old bus stream outside the lock to avoid potential deadlock
	// if Close triggers error paths that call sendBusMessage (which also acquires busMu).
	if oldStream != nil {
		debug("initBusStream: closing existing bus stream for new connection")
		_ = oldStream.Close()
	}
	return nil
}

// resetBusStream clears the bus stream reference if it matches the expected stream.
// This prevents a dying old bus handler from clearing a newly established replacement bus.
func resetBusStream(expected Stream) {
	busMu.Lock()
	defer busMu.Unlock()
	if busStream == expected {
		busStream = nil
		activeBusForwarder = nil
		debug("bus stream reset, ready for reconnection")
	}
}

func isActiveBusForwarder(forwarder *udpForwarder) bool {
	busMu.Lock()
	defer busMu.Unlock()
	return busStream != nil && activeBusForwarder == forwarder
}

func isBusStreamInited() bool {
	busMu.Lock()
	defer busMu.Unlock()
	return busStream != nil
}

func handleBusEvent(stream Stream, forwarder *udpForwarder) {
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

	if err := initBusStream(stream, forwarder); err != nil {
		sendError(stream, err)
		return
	}

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("bus ack ok failed: %v", err)
		return
	}

	serving.Store(true)

	// If a discard marker was pending (set by setClientConn before this bus was ready),
	// re-send it on the new bus. This handles the app termination scenario where the
	// marker was sent on the dead old bus and never reached the client.
	if marker := getDiscardPendingInputMarker(); len(marker) > 0 {
		debug("re-sending pending discard marker on new bus: %X", marker)
		_ = sendBusMessage("discard", discardMessage{DiscardMarker: marker})
	}

	intervalTime := int64(msg.IntervalTime / time.Millisecond)
	heartbeatTimeout := int64(msg.HeartbeatTimeout / time.Millisecond)

	globalServerProxy.clientChecker.timeoutMilli.Store(heartbeatTimeout)

	clientAliveTime.addMilli(time.Now().UnixMilli())
	startBusKeepAlive(msg.AliveTimeout, msg.IntervalTime)

	for {
		command, err := recvCommand(stream)
		if err != nil {
			if isClosedError(err) {
				break
			}
			warning("recv bus command failed: %v", err)
			break
		}

		switch command {
		case "exit":
			err = handleExitEvent(stream)
		case "resize":
			err = handleResizeEvent(stream)
		case "close":
			handleCloseEvent()
			return // return will close the bus stream
		case "alive":
			err = handleAliveEvent(stream, heartbeatTimeout, intervalTime)
		case "setting":
			err = handleSettingEvent(stream)
		case "rekey":
			err = handleRekeyEvent(stream)
		default:
			if err := handleUnknownEvent(stream, command); err != nil {
				warning("handle bus command [%s] failed: %v. You may need to upgrade tsshd.", command, err)
			}
		}
		if err != nil {
			warning("handle bus command [%s] failed: %v", command, err)
		}
	}

	// Bus stream died unexpectedly (not graceful close).
	// Reset to allow reconnecting client to establish new bus.
	// Sessions are preserved so reconnecting client can resume them.
	// Only reset if this is still the active bus (not already replaced).
	resetBusStream(stream)
}

func handleExitEvent(stream Stream) error {
	var exitMsg exitMessage
	if err := recvMessage(stream, &exitMsg); err != nil {
		return fmt.Errorf("recv exit message failed: %v", err)
	}
	closeSession(exitMsg.ID)
	return nil
}

func handleCloseEvent() {
	closeAllSessions()
	debug("close bus and exit tsshd")
	stopBusKeepAlive()

	busMu.Lock()
	busStream = nil
	activeBusForwarder = nil
	busMu.Unlock()

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
		select {
		case exitChan <- 0:
		default:
		}
	}()
}

func handleAliveEvent(stream Stream, heartbeatTimeout, intervalTime int64) error {
	var msg aliveMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv alive message failed: %v", err)
	}

	now := time.Now().UnixMilli()

	// If the time since the last recorded activity exceeds heartbeatTimeout,
	// it indicates that the client was previously disconnected and has now reconnected.
	// Set the flag to clear the packet cache after the client stabilizes.
	if now-clientAliveTime.latest() > heartbeatTimeout {
		debug("client reconnected, last active at %v", time.UnixMilli(clientAliveTime.latest()).Format("15:04:05.000"))
		pendingClearPktCache = true
	} else if enableDebugLogging && pendingClearPktCache {
		debug("client active at %v", time.UnixMilli(now).Format("15:04:05.000"))
	}

	clientAliveTime.addMilli(now)

	if pendingClearPktCache {
		// If the client has remained active for a sufficient number of intervals,
		// consider the connection stable and clear the packet cache.
		if now-clientAliveTime.oldest() < (kAliveTimeCap+1)*intervalTime {
			totalSize, totalCount := globalServerProxy.pktCache.clearCache()
			if enableDebugLogging && (totalSize > 0 || totalCount > 0) {
				debug("drop packet cache count [%d] size [%d]", totalCount, totalSize)
			}
			pendingClearPktCache = false
		}
	}

	return sendBusMessage("alive", msg)
}

func handleSettingEvent(stream Stream) error {
	var msg settingsMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv settings message failed: %v", err)
	}
	if msg.KeepPendingInput != nil {
		globalSetting.keepPendingInput.Store(*msg.KeepPendingInput)
	}
	if msg.KeepPendingOutput != nil {
		globalSetting.keepPendingOutput.Store(*msg.KeepPendingOutput)
	}
	return nil
}

func handleRekeyEvent(stream Stream) error {
	var msg rekeyMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv rekey message failed: %v", err)
	}
	if globalProtoServer == nil {
		return fmt.Errorf("protocol server not initialized")
	}
	return globalProtoServer.handleRekeyEvent(&msg)
}

func handleUnknownEvent(stream Stream, command string) error {
	var msg struct{}
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv message for unknown command [%s] failed: %v", command, err)
	}
	return fmt.Errorf("unknown command: %s", command)
}

func startBusKeepAlive(aliveTimeout, intervalTime time.Duration) {
	keepAliveMu.Lock()
	defer keepAliveMu.Unlock()

	// Always cancel any previous keepalive goroutine, even if not starting a new one.
	if keepAliveCancel != nil {
		keepAliveCancel()
		keepAliveCancel = nil
	}

	if aliveTimeout <= 0 {
		return
	}
	if intervalTime <= 0 {
		intervalTime = 100 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	keepAliveCancel = cancel
	go keepAlive(ctx, aliveTimeout, intervalTime)
}

func stopBusKeepAlive() {
	keepAliveMu.Lock()
	if keepAliveCancel != nil {
		keepAliveCancel()
		keepAliveCancel = nil
	}
	keepAliveMu.Unlock()
}

func keepAlive(ctx context.Context, aliveTimeout time.Duration, intervalTime time.Duration) {
	ticker := time.NewTicker(intervalTime)
	defer ticker.Stop()

	timeoutMilli := int64(aliveTimeout / time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Now().UnixMilli()-clientAliveTime.latest() > timeoutMilli {
				warning("tsshd keep alive timeout")
				select {
				case exitChan <- 2:
				default:
					debug("keepAlive: exit channel full, timeout signal dropped")
				}
				return
			}
		}
	}
}

func handleExitSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGTERM, // Default signal for the kill command
		syscall.SIGHUP,  // Terminal closed (System reboot/shutdown)
		os.Interrupt,    // Ctrl+C signal
	)
	go func() {
		sig := <-sigChan
		_ = sendBusMessage("quit", quitMessage{fmt.Sprintf("receiving signal [%v] from the operating system", sig)})
		go func() {
			time.Sleep(1000 * time.Millisecond) // give udp some time
			debug("quit by signal wait timeout")
			select {
			case exitChan <- 3:
			default:
			}
		}()
	}()
}
