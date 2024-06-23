/*
MIT License

Copyright (c) 2024 The Trzsz SSH Authors.

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

	"github.com/xtaci/kcp-go/v5"
)

var busMutex sync.Mutex

var busSession atomic.Pointer[kcp.UDPSession]

var lastAliveTime atomic.Pointer[time.Time]

func sendBusCommand(command string) error {
	busMutex.Lock()
	defer busMutex.Unlock()
	session := busSession.Load()
	if session == nil {
		return fmt.Errorf("bus session is nil")
	}
	return SendCommand(session, command)
}

func sendBusMessage(command string, msg any) error {
	busMutex.Lock()
	defer busMutex.Unlock()
	session := busSession.Load()
	if session == nil {
		return fmt.Errorf("bus session is nil")
	}
	if err := SendCommand(session, command); err != nil {
		return err
	}
	return SendMessage(session, msg)
}

func trySendErrorMessage(format string, a ...any) {
	_ = sendBusMessage("error", ErrorMessage{fmt.Sprintf(format, a...)})
}

func handleBusEvent(session *kcp.UDPSession) {
	var msg BusMessage
	if err := RecvMessage(session, &msg); err != nil {
		SendError(session, fmt.Errorf("recv bus message failed: %v", err))
		return
	}

	busMutex.Lock()

	// only one bus
	if !busSession.CompareAndSwap(nil, session) {
		busMutex.Unlock()
		SendError(session, fmt.Errorf("bus has been initialized"))
		return
	}

	if err := SendSuccess(session); err != nil { // ack ok
		busMutex.Unlock()
		trySendErrorMessage("bus ack ok failed: %v", err)
		return
	}

	busMutex.Unlock()

	serving.Store(true)

	if msg.Timeout > 0 {
		now := time.Now()
		lastAliveTime.Store(&now)
		go keepAlive(msg.Timeout)
	}

	for {
		command, err := RecvCommand(session)
		if err != nil {
			trySendErrorMessage("recv bus command failed: %v", err)
			return
		}

		switch command {
		case "resize":
			err = handleResizeEvent(session)
		case "close":
			exitChan <- true
			return
		case "alive":
			now := time.Now()
			lastAliveTime.Store(&now)
		default:
			err = handleUnknownEvent(session)
		}
		if err != nil {
			trySendErrorMessage("handle bus command [%s] failed: %v", command, err)
		}
	}
}

func handleUnknownEvent(session *kcp.UDPSession) error {
	var msg struct{}
	if err := RecvMessage(session, &msg); err != nil {
		return fmt.Errorf("recv unknown message failed: %v", err)
	}
	return fmt.Errorf("unknown command")
}

func keepAlive(timeout time.Duration) {
	for {
		_ = sendBusCommand("alive")
		if t := lastAliveTime.Load(); t != nil && time.Since(*t) > timeout {
			trySendErrorMessage("tsshd keep alive timeout")
			exitChan <- true
			return
		}
		time.Sleep(timeout / 10)
	}
}
