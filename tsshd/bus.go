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
var busMutex sync.Mutex

var busClosing atomic.Bool
var busClosingMu sync.Mutex
var busClosingWG sync.WaitGroup

var globalActiveChecker *timeoutChecker

func sendBusMessage(command string, msg any) error {
	busMutex.Lock()
	defer busMutex.Unlock()
	if busStream == nil {
		return fmt.Errorf("bus stream is nil")
	}
	if err := sendCommand(busStream, command); err != nil {
		return err
	}
	return sendMessage(busStream, msg)
}

func initBusStream(stream Stream) error {
	busMutex.Lock()
	defer busMutex.Unlock()

	// only one bus
	if busStream != nil {
		return fmt.Errorf("bus has been initialized")
	}

	busStream = stream
	return nil
}

func handleBusEvent(stream Stream) {
	var msg busMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv bus message failed: %v", err))
		return
	}

	if msg.ClientVer == "" {
		sendError(stream, fmt.Errorf("please upgrade tssh to continue"))
		return
	}

	err := initBusStream(stream)
	if err != nil {
		sendError(stream, err)
		return
	}

	if err := sendSuccess(stream); err != nil { // ack ok
		warning("bus ack ok failed: %v", err)
		return
	}

	serving.Store(true)

	globalActiveChecker = newTimeoutChecker(msg.HeartbeatTimeout)
	if enableDebugLogging {
		globalActiveChecker.onTimeout(func() {
			debug("transport offline, last activity at %v", time.UnixMilli(globalActiveChecker.getAliveTime()).Format("15:04:05.000"))
		})
		globalActiveChecker.onReconnected(func() {
			debug("transport resumed, last activity at %v", time.UnixMilli(globalActiveChecker.getAliveTime()).Format("15:04:05.000"))
		})
	}
	globalActiveChecker.onReconnected(func() {
		totalSize, totalCount := globalServerProxy.pktCache.clearCache()
		if enableDebugLogging {
			debug("drop packet cache count [%d] cache size [%d]", totalCount, totalSize)
		}
	})

	globalServerProxy.clientChecker.timeoutMilli.Store(int64(msg.HeartbeatTimeout / time.Millisecond))

	activeAckChan := make(chan int64, 1)
	defer close(activeAckChan)
	go keepAlive(msg.AliveTimeout, msg.IntervalTime, activeAckChan)

	for {
		command, err := recvCommand(stream)
		if err != nil {
			if isClosedError(err) {
				break
			}
			warning("recv bus command failed: %v", err)
			continue
		}

		switch command {
		case "resize":
			err = handleResizeEvent(stream)
		case "close":
			handleCloseEvent()
			return // return will close the bus stream
		case "alive1":
			err = handleAlive1Event(stream, activeAckChan)
		case "alive2":
			err = handleAlive2Event(stream)
		case "setting":
			err = handleSettingEvent(stream)
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

func handleCloseEvent() {
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
		exitChan <- 0
	}()
}

func handleAlive1Event(stream Stream, activeAckChan chan<- int64) error {
	var msg aliveMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv alive message failed: %v", err)
	}

	activeAckChan <- msg.Time
	return nil
}

func handleAlive2Event(stream Stream) error {
	var msg aliveMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv alive message failed: %v", err)
	}

	return sendBusMessage("alive2", msg)
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

func handleUnknownEvent(stream Stream, command string) error {
	var msg struct{}
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv message for unknown command [%s] failed: %v", command, err)
	}
	return fmt.Errorf("unknown command: %s", command)
}

func keepAlive(totalTimeout time.Duration, intervalTime time.Duration, activeAckChan <-chan int64) {
	ticker := time.NewTicker(intervalTime)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			aliveTime := time.Now().UnixMilli()
			if enableDebugLogging && globalActiveChecker.isTimeout() {
				debug("sending new keep alive [%d]", aliveTime)
			}
			if err := sendBusMessage("alive1", aliveMessage{aliveTime}); err != nil {
				warning("send keep alive [%d] failed: %v", aliveTime, err)
			} else if enableDebugLogging && globalActiveChecker.isTimeout() {
				debug("keep alive [%d] sent success", aliveTime)
			}

			ackTime := <-activeAckChan
			globalActiveChecker.updateTime(ackTime)
		}
	}()

	timeoutMilli := int64(totalTimeout / time.Millisecond)
	for {
		if time.Now().UnixMilli()-globalActiveChecker.getAliveTime() > timeoutMilli {
			warning("tsshd keep alive timeout")
			exitChan <- 2
			return
		}
		time.Sleep(intervalTime)
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
			exitChan <- 3
		}()
	}()
}
