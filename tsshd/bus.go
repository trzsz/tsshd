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
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var serving atomic.Bool

var busMutex sync.Mutex

var busStream atomic.Pointer[net.Conn]

var lastAliveTime atomic.Pointer[time.Time]

func sendBusCommand(command string) error {
	busMutex.Lock()
	defer busMutex.Unlock()
	stream := busStream.Load()
	if stream == nil {
		return fmt.Errorf("bus stream is nil")
	}
	return sendCommand(*stream, command)
}

func sendBusMessage(command string, msg any) error {
	busMutex.Lock()
	defer busMutex.Unlock()
	stream := busStream.Load()
	if stream == nil {
		return fmt.Errorf("bus stream is nil")
	}
	if err := sendCommand(*stream, command); err != nil {
		return err
	}
	return sendMessage(*stream, msg)
}

func trySendErrorMessage(format string, a ...any) {
	_, _ = doWithTimeout(func() (int, error) {
		_ = sendBusMessage("error", errorMessage{Msg: fmt.Sprintf(format, a...)})
		return 0, nil
	}, 1*time.Second)
}

func handleBusEvent(stream net.Conn) {
	var msg busMessage
	if err := recvMessage(stream, &msg); err != nil {
		sendError(stream, fmt.Errorf("recv bus message failed: %v", err))
		return
	}

	busMutex.Lock()

	// only one bus
	if !busStream.CompareAndSwap(nil, &stream) {
		busMutex.Unlock()
		sendError(stream, fmt.Errorf("bus has been initialized"))
		return
	}

	if err := sendSuccess(stream); err != nil { // ack ok
		busMutex.Unlock()
		trySendErrorMessage("bus ack ok failed: %v", err)
		return
	}

	busMutex.Unlock()

	serving.Store(true)

	if msg.Timeout <= 0 {
		msg.Timeout = 365 * 24 * time.Hour
	}
	now := time.Now()
	lastAliveTime.Store(&now)
	go keepAlive(msg.Timeout, msg.Interval)

	for {
		command, err := recvCommand(stream)
		if err != nil {
			trySendErrorMessage("recv bus command failed: %v", err)
			return
		}

		switch command {
		case "resize":
			err = handleResizeEvent(stream)
		case "close":
			exitChan <- 0
			return
		case "alive": // work as ping in new version
			now := time.Now()
			lastAliveTime.Store(&now)
			_ = sendBusCommand("alive")
		case "alive2":
			err = handleAliveEvent(stream)
		default:
			err = handleUnknownEvent(stream, command)
		}
		if err != nil {
			trySendErrorMessage("handle bus command [%s] failed: %v. You may need to upgrade tsshd.", command, err)
		}
	}
}

func handleAliveEvent(stream net.Conn) error {
	now := time.Now()
	lastAliveTime.Store(&now)

	var msg aliveMessage
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv alive message failed: %v", err)
	}

	return sendBusMessage("alive2", msg)
}

func handleUnknownEvent(stream net.Conn, command string) error {
	var msg struct{}
	if err := recvMessage(stream, &msg); err != nil {
		return fmt.Errorf("recv message for unknown command [%s] failed: %v", command, err)
	}
	return fmt.Errorf("unknown command: %s", command)
}

func keepAlive(totalTimeout time.Duration, intervalTimeout time.Duration) {
	if intervalTimeout <= 0 {
		intervalTimeout = min(totalTimeout/10, 10*time.Second)
	}
	for {
		if t := lastAliveTime.Load(); t != nil && time.Since(*t) > totalTimeout {
			trySendErrorMessage("tsshd keep alive timeout")
			exitChan <- 2
			return
		}
		time.Sleep(intervalTimeout)
	}
}
